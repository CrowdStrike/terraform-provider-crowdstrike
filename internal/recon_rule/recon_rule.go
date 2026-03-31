package reconrule

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/recon"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                   = &reconRuleResource{}
	_ resource.ResourceWithConfigure      = &reconRuleResource{}
	_ resource.ResourceWithImportState    = &reconRuleResource{}
	_ resource.ResourceWithValidateConfig = &reconRuleResource{}
)

var (
	documentationSection        string         = "Falcon Intelligence Recon"
	resourceMarkdownDescription string         = "This resource allows you to manage Falcon Intelligence Recon monitoring rules in the CrowdStrike Falcon Platform.\n\nRecon rules define the monitoring criteria used to discover threats across the dark web, criminal forums, and other online sources."
	requiredScopes              []scopes.Scope = []scopes.Scope{
		{
			Name:  "Monitoring rules (Falcon Intelligence Recon)",
			Read:  true,
			Write: true,
		},
	}
)

func NewReconRuleResource() resource.Resource {
	return &reconRuleResource{}
}

type reconRuleResource struct {
	client *client.CrowdStrikeAPISpecification
}

type notificationModel struct {
	ID               types.String `tfsdk:"id"`
	Type             types.String `tfsdk:"type"`
	ContentFormat    types.String `tfsdk:"content_format"`
	Frequency        types.String `tfsdk:"frequency"`
	Recipients       types.Set    `tfsdk:"recipients"`
	TriggerMatchless types.Bool   `tfsdk:"trigger_matchless"`
	Status           types.String `tfsdk:"status"`
}

var notificationAttrTypes = map[string]attr.Type{
	"id":                types.StringType,
	"type":              types.StringType,
	"content_format":    types.StringType,
	"frequency":         types.StringType,
	"recipients":        types.SetType{ElemType: types.StringType},
	"trigger_matchless": types.BoolType,
	"status":            types.StringType,
}

type reconRuleResourceModel struct {
	ID                       types.String `tfsdk:"id"`
	Name                     types.String `tfsdk:"name"`
	Topic                    types.String `tfsdk:"topic"`
	Filter                   types.String `tfsdk:"filter"`
	Priority                 types.String `tfsdk:"priority"`
	Permissions              types.String `tfsdk:"permissions"`
	BreachMonitoringEnabled  types.Bool   `tfsdk:"breach_monitoring_enabled"`
	BreachMonitorOnly        types.Bool   `tfsdk:"breach_monitor_only"`
	SubstringMatchingEnabled types.Bool   `tfsdk:"substring_matching_enabled"`
	MatchOnTsqResultTypes    types.Set    `tfsdk:"match_on_tsq_result_types"`
	LookbackPeriod           types.Int64  `tfsdk:"lookback_period"`
	Notification             types.List   `tfsdk:"notification"`
	Status                   types.String `tfsdk:"status"`
	StatusMessage            types.String `tfsdk:"status_message"`
	CreatedTimestamp         types.String `tfsdk:"created_timestamp"`
	UpdatedTimestamp         types.String `tfsdk:"updated_timestamp"`
	LastUpdated              types.String `tfsdk:"last_updated"`
}

func (m *reconRuleResourceModel) wrap(
	ctx context.Context,
	rule models.SadomainRule,
	actions []*models.DomainActionV1,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringPointerValue(rule.ID)
	m.Name = types.StringPointerValue(rule.Name)
	m.Topic = types.StringPointerValue(rule.Topic)
	m.Filter = types.StringPointerValue(rule.Filter)
	m.Priority = types.StringPointerValue(rule.Priority)
	m.Permissions = types.StringPointerValue(rule.Permissions)
	m.BreachMonitoringEnabled = types.BoolPointerValue(rule.BreachMonitoringEnabled)
	m.BreachMonitorOnly = types.BoolPointerValue(rule.BreachMonitorOnly)
	m.SubstringMatchingEnabled = types.BoolPointerValue(rule.SubstringMatchingEnabled)
	m.LookbackPeriod = types.Int64Value(rule.LookbackPeriod)
	m.Status = types.StringPointerValue(rule.Status)
	m.StatusMessage = types.StringValue(rule.StatusMessage)

	tsqSet, d := flex.FlattenStringValueSet(ctx, rule.MatchOnTsqResultTypes)
	diags.Append(d...)
	if diags.HasError() {
		return diags
	}

	m.MatchOnTsqResultTypes = tsqSet

	if rule.CreatedTimestamp != nil {
		m.CreatedTimestamp = types.StringValue(rule.CreatedTimestamp.String())
	}
	if rule.UpdatedTimestamp != nil {
		m.UpdatedTimestamp = types.StringValue(rule.UpdatedTimestamp.String())
	}

	notifList, d := wrapNotifications(ctx, actions)
	diags.Append(d...)
	if diags.HasError() {
		return diags
	}

	m.Notification = notifList

	return diags
}

func wrapNotifications(
	ctx context.Context,
	actions []*models.DomainActionV1,
) (types.List, diag.Diagnostics) {
	var diags diag.Diagnostics

	if len(actions) == 0 {
		return types.ListValueMust(types.ObjectType{AttrTypes: notificationAttrTypes}, []attr.Value{}), nil
	}

	var notifications []notificationModel
	for _, action := range actions {
		recipientsSet, d := flex.FlattenStringValueSet(ctx, action.Recipients)
		diags.Append(d...)
		if diags.HasError() {
			return types.ListNull(types.ObjectType{AttrTypes: notificationAttrTypes}), diags
		}

		notifications = append(notifications, notificationModel{
			ID:               types.StringPointerValue(action.ID),
			Type:             types.StringPointerValue(action.Type),
			ContentFormat:    types.StringPointerValue(action.ContentFormat),
			Frequency:        types.StringPointerValue(action.Frequency),
			Recipients:       recipientsSet,
			TriggerMatchless: types.BoolPointerValue(action.TriggerMatchless),
			Status:           types.StringPointerValue(action.Status),
		})
	}

	result, d := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: notificationAttrTypes}, notifications)
	diags.Append(d...)

	return result, diags
}

func (r *reconRuleResource) Configure(
	ctx context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	providerConfig, ok := req.ProviderData.(config.ProviderConfig)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf(
				"Expected config.ProviderConfig, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)
		return
	}

	r.client = providerConfig.Client
}

func (r *reconRuleResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_recon_rule"
}

func (r *reconRuleResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			documentationSection,
			resourceMarkdownDescription,
			requiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The unique identifier of the recon rule.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Timestamp of the last Terraform update of the resource.",
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The name of the recon rule.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			// Allowed values from SadomainCreateRuleRequestV1.Topic in gofalcon.
			"topic": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The topic of the recon rule. Determines what type of threat intelligence is monitored.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf(
						"SA_BRAND_PRODUCT",
						"SA_VIP",
						"SA_THIRD_PARTY",
						"SA_IP",
						"SA_CVE",
						"SA_BIN",
						"SA_DOMAIN",
						"SA_EMAIL",
						"SA_ALIAS",
						"SA_AUTHOR",
						"SA_CUSTOM",
						"SA_TYPOSQUATTING",
					),
				},
			},
			"filter": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The FQL filter used for searching.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			// Allowed values from SadomainCreateRuleRequestV1.Priority in gofalcon.
			"priority": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The priority of the recon rule.",
				Validators: []validator.String{
					stringvalidator.OneOf("low", "medium", "high"),
				},
			},
			// Allowed values from SadomainCreateRuleRequestV1.Permissions in gofalcon.
			"permissions": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The access permissions for the recon rule.",
				Validators: []validator.String{
					stringvalidator.OneOf("public", "private"),
				},
			},
			"breach_monitoring_enabled": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether to monitor for breach data. Only available for `SA_DOMAIN` and `SA_EMAIL` rule topics.",
			},
			"breach_monitor_only": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether to monitor only for breach data. Must be used with `breach_monitoring_enabled` set to `true`.",
			},
			"substring_matching_enabled": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether to monitor for substring matches. Only available for the `SA_TYPOSQUATTING` rule topic.",
			},
			// Allowed values from SadomainCreateRuleRequestV1.MatchOnTsqResultTypes in gofalcon.
			"match_on_tsq_result_types": schema.SetAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "The result types to monitor for. Only available for the `SA_TYPOSQUATTING` rule topic.",
				ElementType:         types.StringType,
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(
						stringvalidator.OneOf("basedomains", "subdomains"),
					),
				},
			},
			"lookback_period": schema.Int64Attribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "The duration (in days) for which the rule looks back in the past at first run.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
					int64planmodifier.RequiresReplace(),
				},
			},
			"status": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The current status of the recon rule.",
			},
			"status_message": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The detailed status message of the recon rule.",
			},
			"created_timestamp": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The timestamp when the recon rule was created.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"updated_timestamp": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The timestamp when the recon rule was last updated.",
			},
		},
		// Allowed values from DomainCreateActionRequest and DomainActionV1 in gofalcon.
		Blocks: map[string]schema.Block{
			"notification": schema.ListNestedBlock{
				MarkdownDescription: "Notification actions attached to this rule. Each notification defines how and when alerts are delivered.",
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
				},
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The unique identifier of the notification.",
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseStateForUnknown(),
							},
						},
						"type": schema.StringAttribute{
							Optional:            true,
							Computed:            true,
							Default:             stringdefault.StaticString("email"),
							MarkdownDescription: "The notification type. Currently only `email` is supported.",
							Validators: []validator.String{
								stringvalidator.OneOf("email"),
							},
						},
						"content_format": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "The level of detail in the notification content. Either `standard` or `enhanced`.",
							Validators: []validator.String{
								stringvalidator.OneOf("standard", "enhanced"),
							},
						},
						"frequency": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "The time interval between notification triggers. One of `asap`, `daily`, or `weekly`.",
							Validators: []validator.String{
								stringvalidator.OneOf("asap", "daily", "weekly"),
							},
						},
						"recipients": schema.SetAttribute{
							Required:            true,
							MarkdownDescription: "The email addresses to notify.",
							ElementType:         types.StringType,
							Validators: []validator.Set{
								setvalidator.SizeAtLeast(1),
								setvalidator.ValueStringsAre(
									stringvalidator.LengthAtLeast(1),
								),
							},
						},
						"trigger_matchless": schema.BoolAttribute{
							Optional:            true,
							Computed:            true,
							Default:             booldefault.StaticBool(false),
							MarkdownDescription: "Whether to trigger the notification periodically even when there are no new matches.",
						},
						"status": schema.StringAttribute{
							Optional:            true,
							Computed:            true,
							Default:             stringdefault.StaticString("enabled"),
							MarkdownDescription: "The notification status. Either `enabled` or `muted`.",
							Validators: []validator.String{
								stringvalidator.OneOf("enabled", "muted"),
							},
						},
					},
				},
			},
		},
	}
}

func (r *reconRuleResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var cfg reconRuleResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if cfg.Topic.IsUnknown() {
		return
	}

	topic := cfg.Topic.ValueString()

	if !cfg.BreachMonitorOnly.IsUnknown() && cfg.BreachMonitorOnly.ValueBool() &&
		!cfg.BreachMonitoringEnabled.IsUnknown() && !cfg.BreachMonitoringEnabled.ValueBool() {
		resp.Diagnostics.AddAttributeError(
			path.Root("breach_monitor_only"),
			"Invalid Configuration",
			"breach_monitor_only can only be set to true when breach_monitoring_enabled is also true.",
		)
	}

	// breach_monitoring_enabled and breach_monitor_only are only valid for SA_DOMAIN and SA_EMAIL.
	if topic != "SA_DOMAIN" && topic != "SA_EMAIL" {
		if !cfg.BreachMonitoringEnabled.IsUnknown() && cfg.BreachMonitoringEnabled.ValueBool() {
			resp.Diagnostics.AddAttributeError(
				path.Root("breach_monitoring_enabled"),
				"Invalid Configuration",
				"breach_monitoring_enabled can only be set to true for SA_DOMAIN and SA_EMAIL rule topics.",
			)
		}

		if !cfg.BreachMonitorOnly.IsUnknown() && cfg.BreachMonitorOnly.ValueBool() {
			resp.Diagnostics.AddAttributeError(
				path.Root("breach_monitor_only"),
				"Invalid Configuration",
				"breach_monitor_only can only be set to true for SA_DOMAIN and SA_EMAIL rule topics.",
			)
		}
	}

	// substring_matching_enabled and match_on_tsq_result_types are only valid for SA_TYPOSQUATTING.
	if topic != "SA_TYPOSQUATTING" {
		if !cfg.SubstringMatchingEnabled.IsUnknown() && cfg.SubstringMatchingEnabled.ValueBool() {
			resp.Diagnostics.AddAttributeWarning(
				path.Root("substring_matching_enabled"),
				"Unexpected Configuration",
				"substring_matching_enabled is intended for the SA_TYPOSQUATTING rule topic. "+
					"It may have no effect on other topics.",
			)
		}

		if !cfg.MatchOnTsqResultTypes.IsUnknown() && !cfg.MatchOnTsqResultTypes.IsNull() && len(cfg.MatchOnTsqResultTypes.Elements()) > 0 {
			resp.Diagnostics.AddAttributeError(
				path.Root("match_on_tsq_result_types"),
				"Invalid Configuration",
				"match_on_tsq_result_types can only be set for the SA_TYPOSQUATTING rule topic.",
			)
		}
	}
}

func (r *reconRuleResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan reconRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Creating recon rule", map[string]any{
		"name":  plan.Name.ValueString(),
		"topic": plan.Topic.ValueString(),
	})

	name := plan.Name.ValueString()
	topic := plan.Topic.ValueString()
	filter := plan.Filter.ValueString()
	priority := plan.Priority.ValueString()
	permissions := plan.Permissions.ValueString()
	breachMonitoringEnabled := plan.BreachMonitoringEnabled.ValueBool()
	breachMonitorOnly := plan.BreachMonitorOnly.ValueBool()
	substringMatchingEnabled := plan.SubstringMatchingEnabled.ValueBool()
	originatingTemplateID := ""

	matchOnTsqResultTypes := make([]string, 0)
	if !plan.MatchOnTsqResultTypes.IsNull() && !plan.MatchOnTsqResultTypes.IsUnknown() {
		resp.Diagnostics.Append(plan.MatchOnTsqResultTypes.ElementsAs(ctx, &matchOnTsqResultTypes, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	createReq := &models.SadomainCreateRuleRequestV1{
		Name:                     &name,
		Topic:                    &topic,
		Filter:                   &filter,
		Priority:                 &priority,
		Permissions:              &permissions,
		BreachMonitoringEnabled:  &breachMonitoringEnabled,
		BreachMonitorOnly:        &breachMonitorOnly,
		SubstringMatchingEnabled: &substringMatchingEnabled,
		MatchOnTsqResultTypes:    matchOnTsqResultTypes,
		LookbackPeriod:           plan.LookbackPeriod.ValueInt64(),
		OriginatingTemplateID:    &originatingTemplateID,
	}

	params := recon.NewCreateRulesV1ParamsWithContext(ctx)
	params.SetBody([]*models.SadomainCreateRuleRequestV1{createReq})

	createResp, err := r.client.Recon.CreateRulesV1(params)
	if err != nil {
		resp.Diagnostics.Append(
			tferrors.NewDiagnosticFromAPIError(tferrors.Create, err, requiredScopes),
		)
		return
	}

	if createResp == nil || createResp.Payload == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	if len(createResp.Payload.Errors) > 0 {
		resp.Diagnostics.AddError(
			"Failed to create",
			formatReconAPIErrors(createResp.Payload.Errors),
		)
		return
	}

	if len(createResp.Payload.Resources) == 0 {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	createdRule := createResp.Payload.Resources[0]
	ruleID := *createdRule.ID

	tflog.Info(ctx, "Successfully created recon rule", map[string]any{
		"id":   ruleID,
		"name": *createdRule.Name,
	})

	// Set the ID in state early so Terraform can track the resource even if
	// subsequent operations (e.g. notification creation) fail.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), types.StringValue(ruleID))...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Extract planned notifications before wrap resets Notification.
	var planNotifications []notificationModel
	if !plan.Notification.IsNull() && !plan.Notification.IsUnknown() {
		resp.Diagnostics.Append(plan.Notification.ElementsAs(ctx, &planNotifications, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	resp.Diagnostics.Append(plan.wrap(ctx, *createdRule, nil)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create notifications if configured.
	resp.Diagnostics.Append(r.syncNotifications(ctx, &plan, ruleID, nil, planNotifications)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *reconRuleResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state reconRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleID := state.ID.ValueString()
	tflog.Info(ctx, "Reading recon rule", map[string]any{
		"id": ruleID,
	})

	rule, diags := getReconRule(ctx, r.client, ruleID)
	if tferrors.HasNotFoundError(diags) {
		tflog.Warn(ctx, "Recon rule not found, removing from state", map[string]any{
			"id": ruleID,
		})
		resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	actions, d := getActionsForRule(ctx, r.client, ruleID)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, *rule, actions)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *reconRuleResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan reconRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state reconRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleID := plan.ID.ValueString()
	tflog.Info(ctx, "Updating recon rule", map[string]any{
		"id":   ruleID,
		"name": plan.Name.ValueString(),
	})

	name := plan.Name.ValueString()
	filter := plan.Filter.ValueString()
	priority := plan.Priority.ValueString()
	permissions := plan.Permissions.ValueString()
	breachMonitoringEnabled := plan.BreachMonitoringEnabled.ValueBool()
	breachMonitorOnly := plan.BreachMonitorOnly.ValueBool()
	substringMatchingEnabled := plan.SubstringMatchingEnabled.ValueBool()

	matchOnTsqResultTypes := make([]string, 0)
	if !plan.MatchOnTsqResultTypes.IsNull() && !plan.MatchOnTsqResultTypes.IsUnknown() {
		resp.Diagnostics.Append(plan.MatchOnTsqResultTypes.ElementsAs(ctx, &matchOnTsqResultTypes, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	updateReq := &models.DomainUpdateRuleRequestV1{
		ID:                       &ruleID,
		Name:                     &name,
		Filter:                   &filter,
		Priority:                 &priority,
		Permissions:              &permissions,
		BreachMonitoringEnabled:  &breachMonitoringEnabled,
		BreachMonitorOnly:        &breachMonitorOnly,
		SubstringMatchingEnabled: &substringMatchingEnabled,
		MatchOnTsqResultTypes:    matchOnTsqResultTypes,
	}

	params := recon.NewUpdateRulesV1ParamsWithContext(ctx)
	params.SetBody([]*models.DomainUpdateRuleRequestV1{updateReq})

	updateResp, err := r.client.Recon.UpdateRulesV1(params)
	if err != nil {
		resp.Diagnostics.Append(
			tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, requiredScopes),
		)
		return
	}

	if updateResp == nil || updateResp.Payload == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return
	}

	if len(updateResp.Payload.Errors) > 0 {
		resp.Diagnostics.AddError(
			"Failed to update",
			formatReconAPIErrors(updateResp.Payload.Errors),
		)
		return
	}

	if len(updateResp.Payload.Resources) == 0 {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return
	}

	updatedRule := updateResp.Payload.Resources[0]

	tflog.Info(ctx, "Successfully updated recon rule", map[string]any{
		"id":   *updatedRule.ID,
		"name": *updatedRule.Name,
	})

	// Extract planned and existing state notifications before wrap resets Notification.
	var planNotifications []notificationModel
	if !plan.Notification.IsNull() && !plan.Notification.IsUnknown() {
		resp.Diagnostics.Append(plan.Notification.ElementsAs(ctx, &planNotifications, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	var stateNotifications []notificationModel
	if !state.Notification.IsNull() && !state.Notification.IsUnknown() {
		resp.Diagnostics.Append(state.Notification.ElementsAs(ctx, &stateNotifications, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	resp.Diagnostics.Append(plan.wrap(ctx, *updatedRule, nil)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.syncNotifications(ctx, &plan, ruleID, stateNotifications, planNotifications)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *reconRuleResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state reconRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleID := state.ID.ValueString()
	tflog.Info(ctx, "Deleting recon rule", map[string]any{
		"id": ruleID,
	})

	// Delete all notifications first.
	var stateNotifications []notificationModel
	if !state.Notification.IsNull() && !state.Notification.IsUnknown() {
		resp.Diagnostics.Append(state.Notification.ElementsAs(ctx, &stateNotifications, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	for _, n := range stateNotifications {
		if n.ID.IsNull() || n.ID.IsUnknown() {
			continue
		}
		resp.Diagnostics.Append(r.deleteAction(ctx, n.ID.ValueString())...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	params := recon.NewDeleteRulesV1ParamsWithContext(ctx)
	params.SetIds([]string{ruleID})

	_, err := r.client.Recon.DeleteRulesV1(params)
	if err != nil {
		resp.Diagnostics.Append(
			tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, requiredScopes),
		)
		return
	}

	tflog.Info(ctx, "Successfully deleted recon rule", map[string]any{
		"id": ruleID,
	})
}

func (r *reconRuleResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// syncNotifications creates, updates, and deletes notifications to match the plan.
// stateNotifications is nil on initial create.
func (r *reconRuleResource) syncNotifications(
	ctx context.Context,
	plan *reconRuleResourceModel,
	ruleID string,
	stateNotifications []notificationModel,
	planNotifications []notificationModel,
) diag.Diagnostics {
	var diags diag.Diagnostics

	// Build map of existing notifications by ID.
	existingByID := make(map[string]notificationModel)
	for _, n := range stateNotifications {
		if !n.ID.IsNull() && !n.ID.IsUnknown() {
			existingByID[n.ID.ValueString()] = n
		}
	}

	// Track which existing IDs are still in the plan.
	plannedIDs := make(map[string]bool)

	var resultNotifications []notificationModel

	for _, planned := range planNotifications {
		if !planned.ID.IsNull() && !planned.ID.IsUnknown() {
			// Update existing notification.
			actionID := planned.ID.ValueString()
			plannedIDs[actionID] = true

			action, d := r.updateAction(ctx, planned)
			diags.Append(d...)
			if diags.HasError() {
				return diags
			}
			resultNotifications = append(resultNotifications, action)
		} else {
			// Create new notification.
			action, d := r.createAction(ctx, ruleID, planned)
			diags.Append(d...)
			if diags.HasError() {
				return diags
			}
			resultNotifications = append(resultNotifications, action)
		}
	}

	// Delete notifications that were in state but not in plan.
	for id := range existingByID {
		if !plannedIDs[id] {
			diags.Append(r.deleteAction(ctx, id)...)
			if diags.HasError() {
				return diags
			}
		}
	}

	// Set the notifications on the plan.
	if len(resultNotifications) == 0 {
		plan.Notification = types.ListValueMust(types.ObjectType{AttrTypes: notificationAttrTypes}, []attr.Value{})
	} else {
		notifList, d := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: notificationAttrTypes}, resultNotifications)
		diags.Append(d...)
		if diags.HasError() {
			return diags
		}
		plan.Notification = notifList
	}

	return diags
}

func (r *reconRuleResource) createAction(
	ctx context.Context,
	ruleID string,
	n notificationModel,
) (notificationModel, diag.Diagnostics) {
	var diags diag.Diagnostics

	contentFormat := n.ContentFormat.ValueString()
	frequency := n.Frequency.ValueString()
	triggerMatchless := n.TriggerMatchless.ValueBool()
	actionType := n.Type.ValueString()

	var recipients []string
	diags.Append(n.Recipients.ElementsAs(ctx, &recipients, false)...)
	if diags.HasError() {
		return notificationModel{}, diags
	}

	createReq := &models.DomainRegisterActionsRequest{
		RuleID: &ruleID,
		Actions: []*models.DomainCreateActionRequest{
			{
				ContentFormat:    &contentFormat,
				Frequency:        &frequency,
				Recipients:       recipients,
				TriggerMatchless: &triggerMatchless,
				Type:             &actionType,
			},
		},
	}

	params := recon.NewCreateActionsV1ParamsWithContext(ctx)
	params.SetBody(createReq)

	resp, err := r.client.Recon.CreateActionsV1(params)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Create, err, requiredScopes))
		return notificationModel{}, diags
	}

	if resp == nil || resp.Payload == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return notificationModel{}, diags
	}

	if len(resp.Payload.Errors) > 0 {
		diags.AddError("Failed to create notification", formatReconAPIErrors(resp.Payload.Errors))
		return notificationModel{}, diags
	}

	if len(resp.Payload.Resources) == 0 {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return notificationModel{}, diags
	}

	action := resp.Payload.Resources[0]
	tflog.Info(ctx, "Created notification", map[string]any{
		"id":      *action.ID,
		"rule_id": ruleID,
	})

	recipientsSet, d := flex.FlattenStringValueSet(ctx, action.Recipients)
	diags.Append(d...)

	return notificationModel{
		ID:               types.StringPointerValue(action.ID),
		Type:             types.StringPointerValue(action.Type),
		ContentFormat:    types.StringPointerValue(action.ContentFormat),
		Frequency:        types.StringPointerValue(action.Frequency),
		Recipients:       recipientsSet,
		TriggerMatchless: types.BoolPointerValue(action.TriggerMatchless),
		Status:           types.StringPointerValue(action.Status),
	}, diags
}

func (r *reconRuleResource) updateAction(
	ctx context.Context,
	n notificationModel,
) (notificationModel, diag.Diagnostics) {
	var diags diag.Diagnostics

	actionID := n.ID.ValueString()
	contentFormat := n.ContentFormat.ValueString()
	frequency := n.Frequency.ValueString()
	triggerMatchless := n.TriggerMatchless.ValueBool()
	status := n.Status.ValueString()

	var recipients []string
	diags.Append(n.Recipients.ElementsAs(ctx, &recipients, false)...)
	if diags.HasError() {
		return notificationModel{}, diags
	}

	updateReq := &models.DomainUpdateActionRequest{
		ID:               &actionID,
		ContentFormat:    &contentFormat,
		Frequency:        &frequency,
		Recipients:       recipients,
		TriggerMatchless: &triggerMatchless,
		Status:           &status,
	}

	params := recon.NewUpdateActionV1ParamsWithContext(ctx)
	params.SetBody(updateReq)

	resp, err := r.client.Recon.UpdateActionV1(params)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, requiredScopes))
		return notificationModel{}, diags
	}

	if resp == nil || resp.Payload == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return notificationModel{}, diags
	}

	if len(resp.Payload.Errors) > 0 {
		diags.AddError("Failed to update notification", formatReconAPIErrors(resp.Payload.Errors))
		return notificationModel{}, diags
	}

	if len(resp.Payload.Resources) == 0 {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return notificationModel{}, diags
	}

	action := resp.Payload.Resources[0]
	tflog.Info(ctx, "Updated notification", map[string]any{
		"id": *action.ID,
	})

	recipientsSet, d := flex.FlattenStringValueSet(ctx, action.Recipients)
	diags.Append(d...)

	return notificationModel{
		ID:               types.StringPointerValue(action.ID),
		Type:             types.StringPointerValue(action.Type),
		ContentFormat:    types.StringPointerValue(action.ContentFormat),
		Frequency:        types.StringPointerValue(action.Frequency),
		Recipients:       recipientsSet,
		TriggerMatchless: types.BoolPointerValue(action.TriggerMatchless),
		Status:           types.StringPointerValue(action.Status),
	}, diags
}

func (r *reconRuleResource) deleteAction(
	ctx context.Context,
	actionID string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	params := recon.NewDeleteActionV1ParamsWithContext(ctx)
	params.SetID(actionID)

	_, err := r.client.Recon.DeleteActionV1(params)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, requiredScopes))
		return diags
	}

	tflog.Info(ctx, "Deleted notification", map[string]any{
		"id": actionID,
	})

	return diags
}

// getActionsForRule queries all actions for a given rule ID.
func getActionsForRule(
	ctx context.Context,
	apiClient *client.CrowdStrikeAPISpecification,
	ruleID string,
) ([]*models.DomainActionV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	filter := fmt.Sprintf("rule_id:'%s'", ruleID)
	queryParams := recon.NewQueryActionsV1ParamsWithContext(ctx)
	queryParams.SetFilter(&filter)

	queryResp, err := apiClient.Recon.QueryActionsV1(queryParams)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, requiredScopes))
		return nil, diags
	}

	if queryResp == nil || queryResp.Payload == nil || len(queryResp.Payload.Resources) == 0 {
		return nil, diags
	}

	getParams := recon.NewGetActionsV1ParamsWithContext(ctx)
	getParams.SetIds(queryResp.Payload.Resources)

	getResp, err := apiClient.Recon.GetActionsV1(getParams)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, requiredScopes))
		return nil, diags
	}

	if getResp == nil || getResp.Payload == nil {
		return nil, diags
	}

	return getResp.Payload.Resources, diags
}

// getReconRule retrieves a single recon rule by ID.
func getReconRule(
	ctx context.Context,
	apiClient *client.CrowdStrikeAPISpecification,
	ruleID string,
) (*models.SadomainRule, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := recon.NewGetRulesV1ParamsWithContext(ctx)
	params.SetIds([]string{ruleID})

	resp, err := apiClient.Recon.GetRulesV1(params)
	if err != nil {
		diags.Append(
			tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, requiredScopes),
		)
		return nil, diags
	}

	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		diags.Append(
			tferrors.NewNotFoundError(
				fmt.Sprintf("Recon rule with ID %s not found.", ruleID),
			),
		)
		return nil, diags
	}

	return resp.Payload.Resources[0], diags
}

// formatReconAPIErrors formats DomainReconAPIError slice into a readable string.
func formatReconAPIErrors(errors []*models.DomainReconAPIError) string {
	var msgs []string
	for _, apiErr := range errors {
		if apiErr == nil {
			continue
		}

		var code int32
		if apiErr.Code != nil {
			code = *apiErr.Code
		}

		message := "unknown error"
		if apiErr.Message != nil {
			message = *apiErr.Message
		}

		msg := fmt.Sprintf("[%d] %s", code, message)
		for _, detail := range apiErr.Details {
			if detail.Field != nil && detail.Message != nil {
				msg += fmt.Sprintf(" (%s: %s)", *detail.Field, *detail.Message)
			}
		}
		msgs = append(msgs, msg)
	}
	return strings.Join(msgs, "; ")
}
