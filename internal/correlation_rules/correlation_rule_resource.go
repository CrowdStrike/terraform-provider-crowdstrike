package correlationrules

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/correlation_rules"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/strfmt"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/int32validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

var (
	_ resource.Resource                   = &correlationRuleResource{}
	_ resource.ResourceWithConfigure      = &correlationRuleResource{}
	_ resource.ResourceWithImportState    = &correlationRuleResource{}
	_ resource.ResourceWithValidateConfig = &correlationRuleResource{}
)

var apiScopes = []scopes.Scope{
	{
		Name:  "Correlation Rules",
		Read:  true,
		Write: true,
	},
}

// NewCorrelationRuleResource creates a new instance of the correlation rule resource.
func NewCorrelationRuleResource() resource.Resource {
	return &correlationRuleResource{}
}

type correlationRuleResource struct {
	client   *client.CrowdStrikeAPISpecification
	clientID string
}

// CorrelationRuleResourceModel defines the Terraform resource model.
type CorrelationRuleResourceModel struct {
	ID                    types.String `tfsdk:"id"`
	CustomerID            types.String `tfsdk:"customer_id"`
	Name                  types.String `tfsdk:"name"`
	Description           types.String `tfsdk:"description"`
	Severity              types.Int32  `tfsdk:"severity"`
	Status                types.String `tfsdk:"status"`
	Comment               types.String `tfsdk:"comment"`
	Tactic                types.String `tfsdk:"tactic"`
	Technique             types.String `tfsdk:"technique"`
	TemplateID            types.String `tfsdk:"template_id"`
	TriggerOnCreate       types.Bool   `tfsdk:"trigger_on_create"`
	Search                types.Object `tfsdk:"search"`
	Operation             types.Object `tfsdk:"operation"`
	MitreAttack           types.List   `tfsdk:"mitre_attack"`
	Notification          types.List   `tfsdk:"notification"`
	GuardrailNotification types.List   `tfsdk:"guardrail_notification"`
}

// SearchModel defines the search block.
type SearchModel struct {
	Filter         types.String `tfsdk:"filter"`
	Lookback       types.String `tfsdk:"lookback"`
	Outcome        types.String `tfsdk:"outcome"`
	TriggerMode    types.String `tfsdk:"trigger_mode"`
	ExecutionMode  types.String `tfsdk:"execution_mode"`
	UseIngestTime  types.Bool   `tfsdk:"use_ingest_time"`
	CaseTemplateID types.String `tfsdk:"case_template_id"`
}

// AttributeTypes returns the attribute types for SearchModel.
func (m SearchModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"filter":           types.StringType,
		"lookback":         types.StringType,
		"outcome":          types.StringType,
		"trigger_mode":     types.StringType,
		"execution_mode":   types.StringType,
		"use_ingest_time":  types.BoolType,
		"case_template_id": types.StringType,
	}
}

// OperationModel defines the operation block.
type OperationModel struct {
	Schedule types.Object      `tfsdk:"schedule"`
	StartOn  timetypes.RFC3339 `tfsdk:"start_on"`
	StopOn   timetypes.RFC3339 `tfsdk:"stop_on"`
}

// AttributeTypes returns the attribute types for OperationModel.
func (m OperationModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"schedule": types.ObjectType{AttrTypes: ScheduleModel{}.AttributeTypes()},
		"start_on": timetypes.RFC3339Type{},
		"stop_on":  timetypes.RFC3339Type{},
	}
}

// ScheduleModel defines the schedule block within operation.
type ScheduleModel struct {
	Definition types.String `tfsdk:"definition"`
}

// AttributeTypes returns the attribute types for ScheduleModel.
func (m ScheduleModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"definition": types.StringType,
	}
}

// MitreAttackModel defines the mitre_attack block.
type MitreAttackModel struct {
	TacticID    types.String `tfsdk:"tactic_id"`
	TechniqueID types.String `tfsdk:"technique_id"`
}

// AttributeTypes returns the attribute types for MitreAttackModel.
func (m MitreAttackModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"tactic_id":    types.StringType,
		"technique_id": types.StringType,
	}
}

// NotificationModel defines the notification block.
type NotificationModel struct {
	Type    types.String `tfsdk:"type"`
	Config  types.Object `tfsdk:"config"`
	Options types.Map    `tfsdk:"options"`
}

// AttributeTypes returns the attribute types for NotificationModel.
func (m NotificationModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"type":    types.StringType,
		"config":  types.ObjectType{AttrTypes: NotificationConfigModel{}.AttributeTypes()},
		"options": types.MapType{ElemType: types.StringType},
	}
}

// NotificationConfigModel defines the config block within notification.
type NotificationConfigModel struct {
	Cid        types.String `tfsdk:"cid"`
	ConfigID   types.String `tfsdk:"config_id"`
	PluginID   types.String `tfsdk:"plugin_id"`
	Recipients types.List   `tfsdk:"recipients"`
	Severity   types.String `tfsdk:"severity"`
}

// AttributeTypes returns the attribute types for NotificationConfigModel.
func (m NotificationConfigModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"cid":        types.StringType,
		"config_id":  types.StringType,
		"plugin_id":  types.StringType,
		"recipients": types.ListType{ElemType: types.StringType},
		"severity":   types.StringType,
	}
}

func (r *correlationRuleResource) Configure(
	_ context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}
	cfg, ok := req.ProviderData.(config.ProviderConfig)
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

	r.client = cfg.Client
	r.clientID = cfg.ClientId
}

func (r *correlationRuleResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_correlation_rule"
}

func (r *correlationRuleResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"NGSIEM",
			"Manages CrowdStrike NGSIEM Correlation Rules. Correlation rules allow you to define conditions for generating alerts based on event patterns.",
			apiScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Unique identifier of the correlation rule. Computed.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"customer_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The CID of the environment (tenant ID).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the correlation rule.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"description": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
				MarkdownDescription: "Description of the correlation rule. Optional. **Note:** Due to an API limitation, removing this value once set requires the resource to be destroyed and recreated.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplaceIf(
						func(_ context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
							// The PATCH model uses omitempty, so an empty string is
							// never sent to the API.  Force replace when clearing a
							// previously set value.
							if req.StateValue.ValueString() != "" && req.PlanValue.ValueString() == "" {
								resp.RequiresReplace = true
							}
						},
						"Requires replacement when clearing description due to an API limitation.",
						"Requires replacement when clearing `description` due to an API limitation.",
					),
				},
			},
			"severity": schema.Int32Attribute{
				Required:            true,
				MarkdownDescription: "The severity level of generated alerts. Valid values are `10` (Informational), `30` (Low), `50` (Medium), `70` (High), `90` (Critical).",
				Validators: []validator.Int32{
					int32validator.OneOf(10, 30, 50, 70, 90),
				},
			},
			"status": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Whether the rule is `active` or `inactive`.",
				Validators: []validator.String{
					stringvalidator.OneOf("active", "inactive"),
				},
			},
			"comment": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
				MarkdownDescription: "A comment. **Note:** Due to an API limitation, removing this value once set requires the resource to be destroyed and recreated.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplaceIf(
						func(_ context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
							// The PATCH model uses omitempty, so an empty string is
							// never sent to the API.  Force replace when clearing a
							// previously set value.
							if req.StateValue.ValueString() != "" && req.PlanValue.ValueString() == "" {
								resp.RequiresReplace = true
							}
						},
						"Requires replacement when clearing comment due to an API limitation.",
						"Requires replacement when clearing `comment` due to an API limitation.",
					),
				},
			},
			"tactic": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The MITRE ATT&CK tactic ID. Derived from the first mitre_attack entry.",
				PlanModifiers: []planmodifier.String{
					useStateUnlessMitreChanged{},
				},
			},
			"technique": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The MITRE ATT&CK technique ID. Derived from the first mitre_attack entry.",
				PlanModifiers: []planmodifier.String{
					useStateUnlessMitreChanged{},
				},
			},
			"template_id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The ID of the template this rule was created from, if any. Read-only; only populated on import and read.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"trigger_on_create": schema.BoolAttribute{
				Optional:            true,
				WriteOnly:           true,
				MarkdownDescription: "Whether to trigger the rule immediately upon creation. Write-only; not stored in state.",
			},
		},
		Blocks: map[string]schema.Block{
			"search": schema.SingleNestedBlock{
				MarkdownDescription: "The search configuration that defines the rule's detection logic.",
				Attributes: map[string]schema.Attribute{
					"filter": schema.StringAttribute{
						Required:            true,
						MarkdownDescription: "The query to base the rule on. For info about writing search queries, see [CrowdStrike Query Language](https://falcon.crowdstrike.com/documentation/page/d3c84a1b/crowdstrike-query-language-quick-reference).",
						Validators: []validator.String{
							fwvalidators.StringNotWhitespace(),
						},
					},
					"lookback": schema.StringAttribute{
						Required:            true,
						MarkdownDescription: "The search window in hours and minutes (e.g., `1h0m`, `5h30m`, `24h0m`). Should be at least as long as the schedule frequency.",
						Validators: []validator.String{
							fwvalidators.StringNotWhitespace(),
						},
					},
					"outcome": schema.StringAttribute{
						Required:            true,
						MarkdownDescription: "Whether to create a detection or incident if a match is found. Valid values: `detection`, `incident`.",
						Validators: []validator.String{
							stringvalidator.OneOf("detection", "incident"),
						},
					},
					"trigger_mode": schema.StringAttribute{
						Required:            true,
						MarkdownDescription: "Must be `verbose` (One outcome generated for each result matching the query. Total outcomes are limited per rule trigger.) or `summary` (One outcome generated for all results matching the query. Total results included in the outcome are limited per rule trigger.).",
						Validators: []validator.String{
							stringvalidator.OneOf("verbose", "summary"),
						},
					},
					// Currently it seems like only scheduled is valid.
					"execution_mode": schema.StringAttribute{
						Optional:            true,
						Computed:            true,
						Default:             stringdefault.StaticString("scheduled"),
						MarkdownDescription: "The execution mode for the rule. Currently only `scheduled` is supported. Defaults to `scheduled`. **Note:** Changes to this field require the resource to be destroyed and recreated.",
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
					},
					"use_ingest_time": schema.BoolAttribute{
						Optional:            true,
						Computed:            true,
						Default:             booldefault.StaticBool(false),
						MarkdownDescription: "If true, use the timestamp of the moment the event was ingested by crowdstrike cloud. Otherwise use the moment the event was generated on the system. **Note:** Due to an API limitation, changing this value from `true` to `false` requires the resource to be destroyed and recreated.",
						PlanModifiers: []planmodifier.Bool{
							boolplanmodifier.RequiresReplaceIf(
								func(_ context.Context, req planmodifier.BoolRequest, resp *boolplanmodifier.RequiresReplaceIfFuncResponse) {
									// The API does not support unsetting use_ingest_time via PATCH.
									// Force replace when changing from true to false.
									if req.StateValue.ValueBool() && !req.PlanValue.ValueBool() {
										resp.RequiresReplace = true
									}
								},
								"Requires replacement when changing use_ingest_time from true to false due to an API limitation.",
								"Requires replacement when changing `use_ingest_time` from `true` to `false` due to an API limitation.",
							),
						},
					},
					"case_template_id": schema.StringAttribute{
						Optional:            true,
						Computed:            true,
						Default:             stringdefault.StaticString(""),
						MarkdownDescription: "The ID of the case template used to generate a case when the rule triggers. If not set, no case template is used. **Note:** Due to an API limitation, removing this value once set requires the resource to be destroyed and recreated.",
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplaceIf(
								func(_ context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
									// The API omits empty strings (omitempty), so clearing case_template_id
									// via PATCH is not possible. Force replace when removing a set value.
									if req.StateValue.ValueString() != "" && req.PlanValue.ValueString() == "" {
										resp.RequiresReplace = true
									}
								},
								"Requires replacement when clearing case_template_id due to an API limitation.",
								"Requires replacement when clearing `case_template_id` due to an API limitation.",
							),
						},
					},
				},
			},
			"operation": schema.SingleNestedBlock{
				MarkdownDescription: "The operation configuration that defines scheduling and timing for the rule.",
				Blocks: map[string]schema.Block{
					"schedule": schema.SingleNestedBlock{
						MarkdownDescription: "The schedule configuration for when the rule should run.",
						Attributes: map[string]schema.Attribute{
							"definition": schema.StringAttribute{
								Required:            true,
								MarkdownDescription: "How often to run the query using `@every` format (e.g., `@every 1h0m`, `@every 5h30m`). Minimum interval is 5 minutes (`@every 0h5m`).",
								Validators: []validator.String{
									fwvalidators.StringNotWhitespace(),
								},
							},
						},
					},
				},
				Attributes: map[string]schema.Attribute{
					"start_on": schema.StringAttribute{
						CustomType:          timetypes.RFC3339Type{},
						Optional:            true,
						Computed:            true,
						MarkdownDescription: "The UTC time to start running the query (e.g., `2024-11-19T19:00:00Z`). Defaults to 15 minutes from creation time if not specified.",
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.UseStateForUnknown(),
						},
					},
					"stop_on": schema.StringAttribute{
						CustomType:          timetypes.RFC3339Type{},
						Optional:            true,
						MarkdownDescription: "The UTC time to stop running the query (e.g., `2024-12-31T23:59:59Z`). If not specified, no stop time is used. **Note:** Due to an API limitation, removing this value once set requires the resource to be destroyed and recreated.",
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplaceIf(
								func(_ context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
									// The API does not support clearing stop_on via PATCH.
									// Force replace when removing a previously set value.
									if !req.StateValue.IsNull() && req.PlanValue.IsNull() {
										resp.RequiresReplace = true
									}
								},
								"Requires replacement when removing stop_on due to an API limitation.",
								"Requires replacement when removing `stop_on` due to an API limitation.",
							),
						},
					},
				},
			},
			"mitre_attack": schema.ListNestedBlock{
				MarkdownDescription: "MITRE ATT&CK mappings for the rule.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"tactic_id": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "The MITRE ATT&CK tactic ID (e.g., `TA0001`).",
							Validators: []validator.String{
								fwvalidators.StringNotWhitespace(),
							},
						},
						"technique_id": schema.StringAttribute{
							Optional:            true,
							Computed:            true,
							Default:             stringdefault.StaticString(""),
							MarkdownDescription: "The MITRE ATT&CK technique ID (e.g., `T1078`).",
						},
					},
				},
			},
			"notification":           notificationBlock("Notification configurations for the rule. Notifications are sent when the rule triggers."),
			"guardrail_notification": notificationBlock("Guardrail notification configurations for the rule. Guardrail notifications are sent when guardrail conditions are met."),
		},
	}
}

// notificationBlock returns the schema for a notification or guardrail_notification block.
func notificationBlock(description string) schema.ListNestedBlock {
	return schema.ListNestedBlock{
		MarkdownDescription: description,
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				"type": schema.StringAttribute{
					Required:            true,
					MarkdownDescription: "The notification type (e.g., `email`, `slack`, `webhook`).",
					Validators: []validator.String{
						fwvalidators.StringNotWhitespace(),
					},
				},
				"options": schema.MapAttribute{
					Optional:            true,
					ElementType:         types.StringType,
					MarkdownDescription: "Additional options for the notification. The available options depend on the notification type.",
				},
			},
			Blocks: map[string]schema.Block{
				"config": schema.SingleNestedBlock{
					MarkdownDescription: "The notification configuration.",
					Attributes: map[string]schema.Attribute{
						"cid": schema.StringAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "The CID for the notification configuration. Defaults to the rule's customer_id if not specified.",
						},
						"config_id": schema.StringAttribute{
							Optional:            true,
							MarkdownDescription: "The configuration ID for the notification. **Note:** Due to an API limitation, removing this value once set requires the resource to be destroyed and recreated.",
							PlanModifiers: []planmodifier.String{
								normalizeEmptyToNull{},
								requiresReplaceIfCleared(),
							},
						},
						"plugin_id": schema.StringAttribute{
							Optional:            true,
							MarkdownDescription: "The plugin ID for the notification. **Note:** Due to an API limitation, removing this value once set requires the resource to be destroyed and recreated.",
							PlanModifiers: []planmodifier.String{
								normalizeEmptyToNull{},
								requiresReplaceIfCleared(),
							},
						},
						"recipients": schema.ListAttribute{
							Required:            true,
							ElementType:         types.StringType,
							MarkdownDescription: "The list of recipients for the notification.",
						},
						"severity": schema.StringAttribute{
							Optional:            true,
							MarkdownDescription: "The severity level for the notification. **Note:** Due to an API limitation, removing this value once set requires the resource to be destroyed and recreated.",
							PlanModifiers: []planmodifier.String{
								normalizeEmptyToNull{},
								requiresReplaceIfCleared(),
							},
						},
					},
				},
			},
		},
	}
}

func (r *correlationRuleResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan CorrelationRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createReq, diags := r.buildCreateRequest(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	res, err := r.client.CorrelationRules.EntitiesRulesPostV1(&correlation_rules.EntitiesRulesPostV1Params{
		Context: ctx,
		Body:    createReq,
	})
	if err != nil {
		d := tferrors.NewDiagnosticFromAPIError(tferrors.Create, err, apiScopes)
		resp.Diagnostics.Append(d)
		return
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	if d := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Create, res.Payload.Errors); d != nil {
		resp.Diagnostics.Append(d)
		return
	}

	rule := res.Payload.Resources[0]

	// Set ID in state immediately so Terraform can track the resource even if
	// subsequent operations (like waitForStatus) fail.
	if rule.ID != nil {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), *rule.ID)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	// Poll until status transitions from "creating" to expected status
	if rule.ID != nil {
		expectedStatus := plan.Status.ValueString()
		rule, err = r.waitForStatus(ctx, *rule.ID, expectedStatus)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error waiting for correlation rule status",
				fmt.Sprintf("Failed to wait for status %q: %s", expectedStatus, err),
			)
			return
		}
	}

	resp.Diagnostics.Append(plan.wrap(ctx, rule, rule.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *correlationRuleResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state CorrelationRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleID := state.ID.ValueString()

	res, err := r.client.CorrelationRules.EntitiesRulesGetV1(&correlation_rules.EntitiesRulesGetV1Params{
		Context: ctx,
		Ids:     []string{ruleID},
	})
	if err != nil {
		d := tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, apiScopes)
		if d != nil && d.Summary() == tferrors.NotFoundErrorSummary {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.Append(d)
		return
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	rule := res.Payload.Resources[0]
	resp.Diagnostics.Append(state.wrap(ctx, rule, nil)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *correlationRuleResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan CorrelationRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state CorrelationRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	patchReq, diags := r.buildPatchRequest(ctx, plan, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	res, err := r.client.CorrelationRules.EntitiesRulesPatchV1(&correlation_rules.EntitiesRulesPatchV1Params{
		Context: ctx,
		Body:    []*models.CorrelationrulesapiRulePatchRequestV1{patchReq},
	})
	if err != nil {
		d := tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopes)
		resp.Diagnostics.Append(d)
		return
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return
	}

	if d := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Update, res.Payload.Errors); d != nil {
		resp.Diagnostics.Append(d)
		return
	}

	// .status can become "creating" or "updating", which are undocumented intermediates.
	// Poll for status to become the value we want.
	// This usually happens within a few seconds
	expectedStatus := plan.Status.ValueString()
	rule, err := r.waitForStatus(ctx, plan.ID.ValueString(), expectedStatus)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error waiting for correlation rule status",
			fmt.Sprintf("Failed to wait for status %q: %s", expectedStatus, err),
		)
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, rule, nil)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *correlationRuleResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state CorrelationRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.CorrelationRules.EntitiesRulesDeleteV1(&correlation_rules.EntitiesRulesDeleteV1Params{
		Context: ctx,
		Ids:     []string{state.ID.ValueString()},
	})
	if err != nil {
		d := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, apiScopes)
		if d != nil && d.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(d)
		return
	}
}

func (r *correlationRuleResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *correlationRuleResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var data CorrelationRuleResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.Operation.IsNull() || data.Operation.IsUnknown() {
		return
	}

	var opModel OperationModel
	resp.Diagnostics.Append(data.Operation.As(ctx, &opModel, basetypes.ObjectAsOptions{})...)
	if resp.Diagnostics.HasError() {
		return
	}

	if opModel.StartOn.IsNull() || opModel.StartOn.IsUnknown() {
		return
	}

	startOnTime, d := opModel.StartOn.ValueRFC3339Time()
	if d.HasError() {
		resp.Diagnostics.Append(d...)
		return
	}

	minStartTime := time.Now().Add(15 * time.Minute)
	if startOnTime.Before(minStartTime) {
		resp.Diagnostics.AddAttributeError(
			path.Root("operation").AtName("start_on"),
			"Invalid start_on time",
			fmt.Sprintf("start_on must be at least 15 minutes in the future. Provided: %s, minimum allowed: %s",
				startOnTime.Format(time.RFC3339),
				minStartTime.Format(time.RFC3339),
			),
		)
	}
}

// waitForStatus polls the API until the rule reaches the expected status or times out.
func (r *correlationRuleResource) waitForStatus(
	ctx context.Context,
	ruleID string,
	expectedStatus string,
) (*models.CorrelationrulesapiRuleV1, error) {
	var rule *models.CorrelationrulesapiRuleV1

	err := retry.RetryContext(ctx, 2*time.Minute, func() *retry.RetryError {
		res, err := r.client.CorrelationRules.EntitiesRulesGetV1(&correlation_rules.EntitiesRulesGetV1Params{
			Context: ctx,
			Ids:     []string{ruleID},
		})
		if err != nil {
			return retry.NonRetryableError(err)
		}

		if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
			return retry.NonRetryableError(fmt.Errorf("empty response when polling for status"))
		}

		rule = res.Payload.Resources[0]

		if rule.Status == nil {
			return retry.RetryableError(fmt.Errorf("status is nil, waiting"))
		}

		if *rule.Status == "creating" {
			return retry.RetryableError(fmt.Errorf("status is still 'creating', waiting"))
		}

		if *rule.Status == "updating" {
			return retry.RetryableError(fmt.Errorf("status is still 'updating', waiting"))
		}

		if *rule.Status != expectedStatus {
			return retry.NonRetryableError(fmt.Errorf("unexpected status: got %s, expected %s", *rule.Status, expectedStatus))
		}

		return nil
	})

	return rule, err
}

// buildCreateRequest constructs the API create request from the Terraform plan.
func (r *correlationRuleResource) buildCreateRequest(
	ctx context.Context,
	plan CorrelationRuleResourceModel,
) (*models.CorrelationrulesapiRuleCreateRequestV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Extract search block
	var searchModel SearchModel
	diags.Append(plan.Search.As(ctx, &searchModel, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil, diags
	}

	search := &models.CorrelationrulesapiRuleSearchV1{
		Filter:         utils.Addr(searchModel.Filter.ValueString()),
		Lookback:       utils.Addr(searchModel.Lookback.ValueString()),
		Outcome:        utils.Addr(searchModel.Outcome.ValueString()),
		TriggerMode:    utils.Addr(searchModel.TriggerMode.ValueString()),
		ExecutionMode:  utils.Addr(searchModel.ExecutionMode.ValueString()),
		UseIngestTime:  utils.Addr(searchModel.UseIngestTime.ValueBool()),
		CaseTemplateID: searchModel.CaseTemplateID.ValueString(),
	}

	// Extract operation block
	operation, d := r.buildCreateOperation(ctx, plan.Operation)
	diags.Append(d...)
	if diags.HasError() {
		return nil, diags
	}

	// Extract mitre_attack list
	mitreAttack, d := r.buildMitreAttack(ctx, plan.MitreAttack)
	diags.Append(d...)
	if diags.HasError() {
		return nil, diags
	}

	// Extract notifications list
	notifications, d := r.buildCreateNotifications(ctx, plan.Notification, plan.CustomerID.ValueString())
	diags.Append(d...)
	if diags.HasError() {
		return nil, diags
	}

	// Extract guardrail notifications list
	guardrailNotifications, d := r.buildCreateNotifications(ctx, plan.GuardrailNotification, plan.CustomerID.ValueString())
	diags.Append(d...)
	if diags.HasError() {
		return nil, diags
	}

	createReq := &models.CorrelationrulesapiRuleCreateRequestV1{
		CustomerID:             utils.Addr(plan.CustomerID.ValueString()),
		Name:                   utils.Addr(plan.Name.ValueString()),
		Description:            plan.Description.ValueString(),
		Severity:               utils.Addr(plan.Severity.ValueInt32()),
		Status:                 utils.Addr(plan.Status.ValueString()),
		TemplateID:             utils.Addr(""),
		Comment:                plan.Comment.ValueString(),
		TriggerOnCreate:        plan.TriggerOnCreate.ValueBool(),
		Search:                 search,
		Operation:              operation,
		MitreAttack:            mitreAttack,
		Notifications:          notifications,
		GuardrailNotifications: guardrailNotifications,
	}

	return createReq, diags
}

// buildCreateOperation builds the operation for create request.
func (r *correlationRuleResource) buildCreateOperation(
	ctx context.Context,
	operationObj types.Object,
) (*models.CorrelationrulesapiCreateRuleOperationV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	operation := &models.CorrelationrulesapiCreateRuleOperationV1{}

	if operationObj.IsNull() || operationObj.IsUnknown() {
		return operation, diags
	}

	var opModel OperationModel
	diags.Append(operationObj.As(ctx, &opModel, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil, diags
	}

	// Handle schedule
	if !opModel.Schedule.IsNull() && !opModel.Schedule.IsUnknown() {
		var schedModel ScheduleModel
		diags.Append(opModel.Schedule.As(ctx, &schedModel, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return nil, diags
		}
		operation.Schedule = &models.CorrelationrulesapiRuleScheduleV1{
			Definition: utils.Addr(schedModel.Definition.ValueString()),
		}
	}

	// Handle start_on
	if !opModel.StartOn.IsNull() && !opModel.StartOn.IsUnknown() {
		startOn, err := strfmt.ParseDateTime(opModel.StartOn.ValueString())
		if err != nil {
			diags.AddError("Invalid start_on format", fmt.Sprintf("Failed to parse start_on: %s", err))
			return nil, diags
		}
		operation.StartOn = &startOn
	}

	// Handle stop_on
	if !opModel.StopOn.IsNull() && !opModel.StopOn.IsUnknown() {
		stopOn, err := strfmt.ParseDateTime(opModel.StopOn.ValueString())
		if err != nil {
			diags.AddError("Invalid stop_on format", fmt.Sprintf("Failed to parse stop_on: %s", err))
			return nil, diags
		}
		operation.StopOn = &stopOn
	}

	return operation, diags
}

// buildPatchRequest constructs the API patch request from the Terraform plan.
// Only includes fields that have changed between state and plan (partial update).
func (r *correlationRuleResource) buildPatchRequest(
	ctx context.Context,
	plan CorrelationRuleResourceModel,
	state CorrelationRuleResourceModel,
) (*models.CorrelationrulesapiRulePatchRequestV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	// ID is always required
	patchReq := &models.CorrelationrulesapiRulePatchRequestV1{
		ID: utils.Addr(plan.ID.ValueString()),
	}

	// Only include fields that have changed
	if !plan.Name.Equal(state.Name) {
		patchReq.Name = plan.Name.ValueString()
	}

	if !plan.Description.Equal(state.Description) {
		patchReq.Description = plan.Description.ValueString()
	}

	if !plan.Severity.Equal(state.Severity) {
		patchReq.Severity = plan.Severity.ValueInt32()
	}

	if !plan.Status.Equal(state.Status) {
		patchReq.Status = plan.Status.ValueString()
	}

	if !plan.Comment.Equal(state.Comment) {
		patchReq.Comment = plan.Comment.ValueString()
	}

	// Only include search if it changed
	if !plan.Search.Equal(state.Search) {
		if !plan.Search.IsNull() && !plan.Search.IsUnknown() {
			var searchModel SearchModel
			diags.Append(plan.Search.As(ctx, &searchModel, basetypes.ObjectAsOptions{})...)
			if diags.HasError() {
				return nil, diags
			}
			patchReq.Search = &models.CorrelationrulesapiPatchRuleSearchV1{
				Filter:         searchModel.Filter.ValueString(),
				Lookback:       searchModel.Lookback.ValueString(),
				Outcome:        searchModel.Outcome.ValueString(),
				TriggerMode:    utils.Addr(searchModel.TriggerMode.ValueString()), // must be a pointer that is not nil for some reason
				UseIngestTime:  searchModel.UseIngestTime.ValueBool(),
				CaseTemplateID: searchModel.CaseTemplateID.ValueString(),
			}
		}
	}

	operation, d := r.buildPatchOperation(ctx, plan.Operation, state.Operation)
	diags.Append(d...)
	if diags.HasError() {
		return nil, diags
	}
	patchReq.Operation = operation

	if !plan.MitreAttack.Equal(state.MitreAttack) {
		mitreAttack, d := r.buildMitreAttack(ctx, plan.MitreAttack)
		diags.Append(d...)
		if diags.HasError() {
			return nil, diags
		}
		// Send an empty slice (not nil) so the API clears existing entries.
		if mitreAttack == nil {
			mitreAttack = []*models.CorrelationrulesapiMitreAttackMappingV1{}
		}
		patchReq.MitreAttack = mitreAttack
	}

	if !plan.Notification.Equal(state.Notification) {
		notifications, d := r.buildPatchNotifications(ctx, plan.Notification, plan.CustomerID.ValueString())
		diags.Append(d...)
		if diags.HasError() {
			return nil, diags
		}
		patchReq.Notifications = notifications
	}

	if !plan.GuardrailNotification.Equal(state.GuardrailNotification) {
		guardrailNotifications, d := r.buildPatchNotifications(ctx, plan.GuardrailNotification, plan.CustomerID.ValueString())
		diags.Append(d...)
		if diags.HasError() {
			return nil, diags
		}
		patchReq.GuardrailNotifications = guardrailNotifications
	}

	return patchReq, diags
}

// buildPatchOperation builds the operation for patch request.
// Only includes fields that have changed between state and plan.
func (r *correlationRuleResource) buildPatchOperation(
	ctx context.Context,
	planOperationObj types.Object,
	stateOperationObj types.Object,
) (*models.CorrelationrulesapiPatchRuleOperationV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	if planOperationObj.IsNull() || planOperationObj.IsUnknown() {
		return nil, diags
	}

	var planOp OperationModel
	diags.Append(planOperationObj.As(ctx, &planOp, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil, diags
	}

	var stateOp OperationModel
	if !stateOperationObj.IsNull() && !stateOperationObj.IsUnknown() {
		diags.Append(stateOperationObj.As(ctx, &stateOp, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return nil, diags
		}
	}

	operation := &models.CorrelationrulesapiPatchRuleOperationV1{}
	changed := false

	if !planOp.Schedule.Equal(stateOp.Schedule) {
		if !planOp.Schedule.IsNull() && !planOp.Schedule.IsUnknown() {
			var schedModel ScheduleModel
			diags.Append(planOp.Schedule.As(ctx, &schedModel, basetypes.ObjectAsOptions{})...)
			if diags.HasError() {
				return nil, diags
			}
			operation.Schedule = &models.CorrelationrulesapiRuleScheduleV1Patch{
				Definition: utils.Addr(schedModel.Definition.ValueString()),
			}
			changed = true
		}
	}

	if !planOp.StartOn.Equal(stateOp.StartOn) {
		if !planOp.StartOn.IsNull() && !planOp.StartOn.IsUnknown() {
			startOn, err := strfmt.ParseDateTime(planOp.StartOn.ValueString())
			if err != nil {
				diags.AddError("Invalid start_on format", fmt.Sprintf("Failed to parse start_on: %s", err))
				return nil, diags
			}
			operation.StartOn = &startOn
			changed = true
		}
	}

	if !planOp.StopOn.Equal(stateOp.StopOn) {
		if !planOp.StopOn.IsNull() && !planOp.StopOn.IsUnknown() {
			stopOnStr := planOp.StopOn.ValueString()
			operation.StopOn = &stopOnStr
			changed = true
		}
	}

	if !changed {
		return nil, diags
	}

	return operation, diags
}

// buildMitreAttack builds the MITRE ATT&CK list.
func (r *correlationRuleResource) buildMitreAttack(
	ctx context.Context,
	mitreAttackList types.List,
) ([]*models.CorrelationrulesapiMitreAttackMappingV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	if mitreAttackList.IsNull() || mitreAttackList.IsUnknown() {
		return nil, diags
	}

	if len(mitreAttackList.Elements()) == 0 {
		return []*models.CorrelationrulesapiMitreAttackMappingV1{}, diags
	}

	var mitreModels []MitreAttackModel
	diags.Append(mitreAttackList.ElementsAs(ctx, &mitreModels, false)...)
	if diags.HasError() {
		return nil, diags
	}

	mitreAttack := make([]*models.CorrelationrulesapiMitreAttackMappingV1, 0, len(mitreModels))
	for _, m := range mitreModels {
		mitreAttack = append(mitreAttack, &models.CorrelationrulesapiMitreAttackMappingV1{
			TacticID:    utils.Addr(m.TacticID.ValueString()),
			TechniqueID: m.TechniqueID.ValueString(),
		})
	}

	return mitreAttack, diags
}

// buildCreateNotifications builds the notifications list for create request.
// customerID is used as the default value for notification config cid if not explicitly set.
func (r *correlationRuleResource) buildCreateNotifications(
	ctx context.Context,
	notificationList types.List,
	customerID string,
) ([]*models.CorrelationrulesapiCreateRuleNotifications, diag.Diagnostics) {
	var diags diag.Diagnostics

	if notificationList.IsNull() || notificationList.IsUnknown() || len(notificationList.Elements()) == 0 {
		return nil, diags
	}

	var notifModels []NotificationModel
	diags.Append(notificationList.ElementsAs(ctx, &notifModels, false)...)
	if diags.HasError() {
		return nil, diags
	}

	notifications := make([]*models.CorrelationrulesapiCreateRuleNotifications, 0, len(notifModels))
	for _, n := range notifModels {
		if n.Config.IsNull() || n.Config.IsUnknown() {
			diags.AddError(
				"Missing notification config",
				"Each notification block requires a config sub-block.",
			)
			return nil, diags
		}

		// Extract config block
		var configModel NotificationConfigModel
		diags.Append(n.Config.As(ctx, &configModel, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return nil, diags
		}

		// Extract recipients list
		var recipients []string
		diags.Append(configModel.Recipients.ElementsAs(ctx, &recipients, false)...)
		if diags.HasError() {
			return nil, diags
		}

		// Use explicit cid if set, otherwise default to rule's customer_id
		cid := customerID
		if !configModel.Cid.IsNull() && configModel.Cid.ValueString() != "" {
			cid = configModel.Cid.ValueString()
		}

		config := &models.CorrelationrulesapiCreateRuleNotificationConfig{
			Cid:        utils.Addr(cid),
			Recipients: recipients,
		}
		// Only set optional fields if they have values
		if !configModel.ConfigID.IsNull() && configModel.ConfigID.ValueString() != "" {
			config.ConfigID = utils.Addr(configModel.ConfigID.ValueString())
		}
		if !configModel.PluginID.IsNull() && configModel.PluginID.ValueString() != "" {
			config.PluginID = utils.Addr(configModel.PluginID.ValueString())
		}
		if !configModel.Severity.IsNull() && configModel.Severity.ValueString() != "" {
			config.Severity = utils.Addr(configModel.Severity.ValueString())
		}

		notif := &models.CorrelationrulesapiCreateRuleNotifications{
			Type:   utils.Addr(n.Type.ValueString()),
			Config: config,
		}

		// Extract options map if present
		if !n.Options.IsNull() && !n.Options.IsUnknown() {
			options := make(map[string]string)
			diags.Append(n.Options.ElementsAs(ctx, &options, false)...)
			if diags.HasError() {
				return nil, diags
			}
			notif.Options = options
		}

		notifications = append(notifications, notif)
	}

	return notifications, diags
}

// buildPatchNotifications builds the notifications list for patch request.
// customerID is used as the default value for notification config cid if not explicitly set.
func (r *correlationRuleResource) buildPatchNotifications(
	ctx context.Context,
	notificationList types.List,
	customerID string,
) ([]*models.CorrelationrulesapiPatchRuleNotificationsV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	if notificationList.IsNull() || notificationList.IsUnknown() {
		return nil, diags
	}

	// An explicitly empty list signals the API to clear all notifications.
	if len(notificationList.Elements()) == 0 {
		return []*models.CorrelationrulesapiPatchRuleNotificationsV1{}, diags
	}

	var notifModels []NotificationModel
	diags.Append(notificationList.ElementsAs(ctx, &notifModels, false)...)
	if diags.HasError() {
		return nil, diags
	}

	notifications := make([]*models.CorrelationrulesapiPatchRuleNotificationsV1, 0, len(notifModels))
	for _, n := range notifModels {
		if n.Config.IsNull() || n.Config.IsUnknown() {
			diags.AddError(
				"Missing notification config",
				"Each notification block requires a config sub-block.",
			)
			return nil, diags
		}

		// Extract config block
		var configModel NotificationConfigModel
		diags.Append(n.Config.As(ctx, &configModel, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return nil, diags
		}

		// Extract recipients list
		var recipients []string
		diags.Append(configModel.Recipients.ElementsAs(ctx, &recipients, false)...)
		if diags.HasError() {
			return nil, diags
		}

		// Use explicit cid if set, otherwise default to rule's customer_id
		cid := customerID
		if !configModel.Cid.IsNull() && configModel.Cid.ValueString() != "" {
			cid = configModel.Cid.ValueString()
		}

		config := &models.CorrelationrulesapiPatchRuleNotificationConfigV1{
			Cid:        cid,
			Recipients: recipients,
		}
		// Only set optional fields if they have values, to avoid overwriting existing
		// values with empty strings.
		if !configModel.ConfigID.IsNull() && configModel.ConfigID.ValueString() != "" {
			config.ConfigID = configModel.ConfigID.ValueString()
		}
		if !configModel.PluginID.IsNull() && configModel.PluginID.ValueString() != "" {
			config.PluginID = configModel.PluginID.ValueString()
		}
		if !configModel.Severity.IsNull() && configModel.Severity.ValueString() != "" {
			config.Severity = configModel.Severity.ValueString()
		}

		notif := &models.CorrelationrulesapiPatchRuleNotificationsV1{
			Type:   n.Type.ValueString(),
			Config: config,
		}

		// Extract options map if present
		if !n.Options.IsNull() && !n.Options.IsUnknown() {
			options := make(map[string]string)
			diags.Append(n.Options.ElementsAs(ctx, &options, false)...)
			if diags.HasError() {
				return nil, diags
			}
			notif.Options = options
		}

		notifications = append(notifications, notif)
	}

	return notifications, diags
}

// wrap transforms API response values to their Terraform model values.
func (model *CorrelationRuleResourceModel) wrap(
	ctx context.Context,
	rule *models.CorrelationrulesapiRuleV1,
	id *string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	// Special case: ID returned by patch or read seems to be the version id.
	// But we can't query the entity by the version id, only the "original" id.
	if id != nil {
		model.ID = types.StringValue(*id)
	}
	if rule.CustomerID != nil {
		model.CustomerID = types.StringValue(*rule.CustomerID)
	}
	if rule.Name != nil {
		model.Name = types.StringValue(*rule.Name)
	}
	model.Description = types.StringValue(rule.Description)
	if rule.Severity != nil {
		model.Severity = types.Int32Value(*rule.Severity)
	}
	if rule.Status != nil {
		model.Status = types.StringValue(*rule.Status)
	}
	model.Comment = types.StringValue(rule.Comment)
	if rule.Tactic != nil {
		model.Tactic = types.StringValue(*rule.Tactic)
	}
	if rule.Technique != nil {
		model.Technique = types.StringValue(*rule.Technique)
	}
	if rule.TemplateID != nil {
		model.TemplateID = types.StringValue(*rule.TemplateID)
	}

	if rule.Search != nil {
		searchModel := SearchModel{
			Filter:         types.StringPointerValue(rule.Search.Filter),
			Lookback:       types.StringPointerValue(rule.Search.Lookback),
			Outcome:        types.StringPointerValue(rule.Search.Outcome),
			TriggerMode:    types.StringPointerValue(rule.Search.TriggerMode),
			ExecutionMode:  types.StringPointerValue(rule.Search.ExecutionMode),
			UseIngestTime:  types.BoolValue(rule.Search.UseIngestTime != nil && *rule.Search.UseIngestTime),
			CaseTemplateID: types.StringValue(rule.Search.CaseTemplateID),
		}
		searchObj, d := types.ObjectValueFrom(ctx, searchModel.AttributeTypes(), searchModel)
		diags.Append(d...)
		if diags.HasError() {
			return diags
		}
		model.Search = searchObj
	}

	if rule.Operation != nil {
		opModel := OperationModel{}

		if rule.Operation.Schedule != nil && rule.Operation.Schedule.Definition != nil {
			schedModel := ScheduleModel{
				Definition: types.StringPointerValue(rule.Operation.Schedule.Definition),
			}
			schedObj, d := types.ObjectValueFrom(ctx, schedModel.AttributeTypes(), schedModel)
			diags.Append(d...)
			if diags.HasError() {
				return diags
			}
			opModel.Schedule = schedObj
		} else {
			opModel.Schedule = types.ObjectNull(ScheduleModel{}.AttributeTypes())
		}

		if !rule.Operation.StartOn.IsZero() {
			startOn, d := flex.RFC3339ValueToFramework(time.Time(rule.Operation.StartOn).Format(time.RFC3339))
			diags.Append(d...)
			opModel.StartOn = startOn
		} else {
			opModel.StartOn = timetypes.NewRFC3339Null()
		}

		if !rule.Operation.StopOn.IsZero() {
			stopOn, d := flex.RFC3339ValueToFramework(time.Time(rule.Operation.StopOn).Format(time.RFC3339))
			diags.Append(d...)
			opModel.StopOn = stopOn
		} else {
			opModel.StopOn = timetypes.NewRFC3339Null()
		}

		opObj, d := types.ObjectValueFrom(ctx, opModel.AttributeTypes(), opModel)
		diags.Append(d...)
		if diags.HasError() {
			return diags
		}
		model.Operation = opObj
	}

	// Map mitre_attack
	if len(rule.MitreAttack) > 0 {
		mitreModels := make([]MitreAttackModel, 0, len(rule.MitreAttack))
		for _, m := range rule.MitreAttack {
			if m == nil {
				continue
			}
			mitreModel := MitreAttackModel{
				TacticID:    types.StringPointerValue(m.TacticID),
				TechniqueID: types.StringValue(m.TechniqueID),
			}
			mitreModels = append(mitreModels, mitreModel)
		}
		mitreList, d := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: MitreAttackModel{}.AttributeTypes()}, mitreModels)
		diags.Append(d...)
		if diags.HasError() {
			return diags
		}
		model.MitreAttack = mitreList
	} else {
		model.MitreAttack = types.ListNull(types.ObjectType{AttrTypes: MitreAttackModel{}.AttributeTypes()})
	}

	// Map notifications
	notifList, d := mapNotificationsFromAPI(ctx, rule.Notifications)
	diags.Append(d...)
	if diags.HasError() {
		return diags
	}
	model.Notification = notifList

	// Map guardrail notifications
	guardrailNotifList, d := mapNotificationsFromAPI(ctx, rule.GuardrailNotifications)
	diags.Append(d...)
	if diags.HasError() {
		return diags
	}
	model.GuardrailNotification = guardrailNotifList

	return diags
}

// mapNotificationsFromAPI converts API notification response to Terraform list.
func mapNotificationsFromAPI(
	ctx context.Context,
	apiNotifications []*models.CorrelationrulesapiRuleNotificationsV1,
) (types.List, diag.Diagnostics) {
	var diags diag.Diagnostics

	if len(apiNotifications) == 0 {
		return types.ListNull(types.ObjectType{AttrTypes: NotificationModel{}.AttributeTypes()}), diags
	}

	notifModels := make([]NotificationModel, 0, len(apiNotifications))
	for _, n := range apiNotifications {
		if n == nil || n.Config == nil {
			continue
		}

		// Build recipients list
		recipients, d := types.ListValueFrom(ctx, types.StringType, n.Config.Recipients)
		diags.Append(d...)
		if diags.HasError() {
			return types.ListNull(types.ObjectType{AttrTypes: NotificationModel{}.AttributeTypes()}), diags
		}

		configModel := NotificationConfigModel{
			Cid:        types.StringPointerValue(n.Config.Cid),
			Recipients: recipients,
		}
		// Handle optional fields - keep null if not set
		if n.Config.ConfigID != nil && *n.Config.ConfigID != "" {
			configModel.ConfigID = types.StringPointerValue(n.Config.ConfigID)
		} else {
			configModel.ConfigID = types.StringNull()
		}
		if n.Config.PluginID != nil && *n.Config.PluginID != "" {
			configModel.PluginID = types.StringPointerValue(n.Config.PluginID)
		} else {
			configModel.PluginID = types.StringNull()
		}
		if n.Config.Severity != nil && *n.Config.Severity != "" {
			configModel.Severity = types.StringPointerValue(n.Config.Severity)
		} else {
			configModel.Severity = types.StringNull()
		}
		configObj, d := types.ObjectValueFrom(ctx, configModel.AttributeTypes(), configModel)
		diags.Append(d...)
		if diags.HasError() {
			return types.ListNull(types.ObjectType{AttrTypes: NotificationModel{}.AttributeTypes()}), diags
		}

		// Build options map
		var optionsMap types.Map
		if len(n.Options) > 0 {
			optionsMap, d = types.MapValueFrom(ctx, types.StringType, n.Options)
			diags.Append(d...)
			if diags.HasError() {
				return types.ListNull(types.ObjectType{AttrTypes: NotificationModel{}.AttributeTypes()}), diags
			}
		} else {
			optionsMap = types.MapNull(types.StringType)
		}

		notifModel := NotificationModel{
			Type:    types.StringPointerValue(n.Type),
			Config:  configObj,
			Options: optionsMap,
		}
		notifModels = append(notifModels, notifModel)
	}

	notifList, d := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: NotificationModel{}.AttributeTypes()}, notifModels)
	diags.Append(d...)
	return notifList, diags
}
