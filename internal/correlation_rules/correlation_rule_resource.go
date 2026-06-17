package correlationrules

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/correlation_rules"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwtypes "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/types"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
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
	_ resource.ResourceWithModifyPlan     = &correlationRuleResource{}
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
	ID            types.String `tfsdk:"id"`
	CustomerID    types.String `tfsdk:"cid"`
	Name          types.String `tfsdk:"name"`
	Description   types.String `tfsdk:"description"`
	Severity      types.String `tfsdk:"severity"`
	Status        types.String `tfsdk:"status"`
	Comment       types.String `tfsdk:"comment"`
	Search        types.Object `tfsdk:"search"`
	Schedule      types.Object `tfsdk:"schedule"`
	MitreAttack   types.List   `tfsdk:"mitre_attack"`
	Notifications types.Set    `tfsdk:"notifications"`
}

// SearchModel defines the search block.
type SearchModel struct {
	Filter         types.String         `tfsdk:"filter"`
	Lookback       timetypes.GoDuration `tfsdk:"lookback"`
	CreateCase     types.Bool           `tfsdk:"create_case"`
	TriggerMode    types.String         `tfsdk:"trigger_mode"`
	ExecutionMode  types.String         `tfsdk:"execution_mode"`
	UseIngestTime  types.Bool           `tfsdk:"use_ingest_time"`
	CaseTemplateID types.String         `tfsdk:"case_template_id"`
}

// AttributeTypes returns the attribute types for SearchModel.
func (m SearchModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"filter":           types.StringType,
		"lookback":         timetypes.GoDurationType{},
		"create_case":      types.BoolType,
		"trigger_mode":     types.StringType,
		"execution_mode":   types.StringType,
		"use_ingest_time":  types.BoolType,
		"case_template_id": types.StringType,
	}
}

// outcomeDetection and outcomeCase are the wire values for search.outcome.
// A detection is always created; outcomeCase additionally creates a case.
const (
	outcomeDetection = "detection"
	outcomeCase      = "case"
)

// outcomeFromCreateCase maps the create_case bool to the wire outcome string.
func outcomeFromCreateCase(createCase bool) string {
	if createCase {
		return outcomeCase
	}
	return outcomeDetection
}

// ScheduleModel defines the schedule block.
type ScheduleModel struct {
	Interval timetypes.GoDuration `tfsdk:"interval"`
	StartOn  fwtypes.RFC3339      `tfsdk:"start_on"`
	StopOn   fwtypes.RFC3339      `tfsdk:"stop_on"`
}

// AttributeTypes returns the attribute types for ScheduleModel.
func (m ScheduleModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"interval": timetypes.GoDurationType{},
		"start_on": fwtypes.RFC3339Type{},
		"stop_on":  fwtypes.RFC3339Type{},
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

// NotificationModel defines a single notification entry. Regular and guardrail
// notifications share this shape; the `is_guardrail` flag determines which API
// array the entry is routed to.
type NotificationModel struct {
	Type        types.String `tfsdk:"type"`
	IsGuardrail types.Bool   `tfsdk:"is_guardrail"`
	Recipients  types.List   `tfsdk:"recipients"`
	PluginID    types.String `tfsdk:"plugin_id"`
	ConfigID    types.String `tfsdk:"config_id"`
	Severity    types.String `tfsdk:"severity"`
}

// AttributeTypes returns the attribute types for NotificationModel.
func (m NotificationModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"type":         types.StringType,
		"is_guardrail": types.BoolType,
		"recipients":   types.ListType{ElemType: types.StringType},
		"plugin_id":    types.StringType,
		"config_id":    types.StringType,
		"severity":     types.StringType,
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
			"Next-Gen SIEM",
			"Manages CrowdStrike NGSIEM Correlation Rules. Correlation rules allow you to define conditions for generating alerts based on event patterns. For tenant limits and other product-level constraints, see the correlation rules documentation in the Falcon console.",
			apiScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The rule id. This is the stable rule identifier, not a version id.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"cid": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The CID of the environment (tenant ID). Must be 32 lowercase hex characters with no `-NN` checksum suffix (the canonical form the API returns).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					CIDValidator(),
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
				MarkdownDescription: "Description of the correlation rule.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"severity": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The severity level of generated alerts. Valid values: `informational`, `low`, `medium`, `high`, `critical`.",
				Validators: []validator.String{
					stringvalidator.OneOf(severityNames()...),
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
				MarkdownDescription: "A comment describing the rule or its most recent change.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"search": schema.SingleNestedAttribute{
				Required:            true,
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
						CustomType:          timetypes.GoDurationType{},
						Required:            true,
						MarkdownDescription: "The search window as a Go duration string (e.g., `1h0m`, `5h30m`, `24h`, `90m`). Should be at least as long as the schedule frequency. Maximum is `168h`.",
						Validators: []validator.String{
							LookbackValidator(),
						},
					},
					"create_case": schema.BoolAttribute{
						Optional:            true,
						Computed:            true,
						Default:             booldefault.StaticBool(false),
						MarkdownDescription: "Whether the rule also creates a case when it matches. A detection is always created; set this to `true` to additionally create a case (optionally from `case_template_id`). Defaults to `false`.",
					},
					"trigger_mode": schema.StringAttribute{
						Required:            true,
						MarkdownDescription: "Must be `verbose` (One outcome generated for each result matching the query. Total outcomes are limited per rule trigger.) or `summary` (One outcome generated for all results matching the query. Total results included in the outcome are limited per rule trigger.).",
						Validators: []validator.String{
							stringvalidator.OneOf("verbose", "summary"),
						},
					},
					"execution_mode": schema.StringAttribute{
						Optional:            true,
						Computed:            true,
						Default:             stringdefault.StaticString("scheduled"),
						MarkdownDescription: "The execution mode for the rule. Currently only `scheduled` is supported. Defaults to `scheduled`. **Note:** Changes to this field require the resource to be destroyed and recreated.",
						Validators: []validator.String{
							stringvalidator.OneOf("scheduled"),
						},
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
					},
					"use_ingest_time": schema.BoolAttribute{
						Optional:            true,
						Computed:            true,
						Default:             booldefault.StaticBool(false),
						MarkdownDescription: "If true, use the timestamp of the moment the event was ingested by crowdstrike cloud. Otherwise use the moment the event was generated on the system.",
					},
					"case_template_id": schema.StringAttribute{
						Optional:            true,
						MarkdownDescription: "The ID of the case template used to generate a case when the rule triggers. If not set, no case template is used.",
						Validators: []validator.String{
							fwvalidators.StringNotWhitespace(),
						},
					},
				},
			},
			"schedule": schema.SingleNestedAttribute{
				Required:            true,
				MarkdownDescription: "The schedule that controls when the rule runs.",
				Attributes: map[string]schema.Attribute{
					"interval": schema.StringAttribute{
						CustomType:          timetypes.GoDurationType{},
						Required:            true,
						MarkdownDescription: "How often to run the query, as a Go duration string (e.g., `1h0m`, `5h30m`, `30m`). Minimum is `5m` (the API caps at 288 executions per day).",
						Validators: []validator.String{
							ScheduleIntervalValidator(),
						},
					},
					"start_on": schema.StringAttribute{
						CustomType:          fwtypes.RFC3339Type{},
						Required:            true,
						MarkdownDescription: "The UTC time to start running the query (e.g., `2024-11-19T19:00:00Z`). Must be at least 15 minutes in the future at create time.",
					},
					"stop_on": schema.StringAttribute{
						CustomType:          fwtypes.RFC3339Type{},
						Optional:            true,
						MarkdownDescription: "The UTC time to stop running the query (e.g., `2024-12-31T23:59:59Z`). If not specified, no stop time is used. **Note:** Due to an API limitation, removing this value once set requires the resource to be destroyed and recreated.",
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplaceIf(
								func(_ context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
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
			"mitre_attack": schema.ListNestedAttribute{
				Optional:            true,
				MarkdownDescription: "MITRE ATT&CK mappings for the rule. Maximum of 10 entries.",
				Validators: []validator.List{
					listvalidator.SizeAtMost(10),
				},
				NestedObject: schema.NestedAttributeObject{
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
							MarkdownDescription: "The MITRE ATT&CK technique ID (e.g., `T1078`).",
							Validators: []validator.String{
								fwvalidators.StringNotWhitespace(),
							},
						},
					},
				},
			},
			"notifications": schema.SetNestedAttribute{
				Required:            true,
				MarkdownDescription: "Notifications sent when the rule requires attention. Each entry describes a delivery channel and is routed to the rule's regular (errors/warnings) array, the guardrail (auto-deactivation) array, or both via `is_guardrail`. At least one entry MUST set `is_guardrail = true`. Regular entries always send on failure and never on success — these options are not configurable.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
				},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"type": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "The notification channel type. Valid values: `email`, `slack`, `pagerduty`, `webhook`, `ms_teams`.",
							Validators: []validator.String{
								stringvalidator.OneOf("email", "slack", "pagerduty", "webhook", "ms_teams"),
							},
						},
						"is_guardrail": schema.BoolAttribute{
							Optional:            true,
							Computed:            true,
							Default:             booldefault.StaticBool(false),
							MarkdownDescription: "If true, the entry is sent to the rule's guardrail notification list, which fires when the platform auto-deactivates the rule for exceeding outcome thresholds (50 outcomes when the rule runs more than once per 24 hours; 100 outcomes otherwise). At least one notification on every rule must set this to `true`. Defaults to `false`.",
						},
						"recipients": schema.ListAttribute{
							Optional:            true,
							ElementType:         types.StringType,
							MarkdownDescription: "Email addresses to notify. Required (at least one) when `type = \"email\"`; not used by other channel types, which route through `plugin_id`/`config_id` instead.",
							Validators: []validator.List{
								listvalidator.ValueStringsAre(fwvalidators.StringIsEmailAddress()),
							},
						},
						"plugin_id": schema.StringAttribute{
							Optional:            true,
							MarkdownDescription: "The Fusion SOAR plugin identifier for the delivery channel, written to the API `config.plugin_id`. Used by channels backed by a plugin connector (e.g. `slack` sends the connector kind such as `slack.incoming_webhook`). Must be unset when `type = \"email\"`.",
							Validators: []validator.String{
								fwvalidators.StringNotWhitespace(),
							},
						},
						"config_id": schema.StringAttribute{
							Optional:            true,
							MarkdownDescription: "The Fusion SOAR configuration identifier for the delivery channel, written to the API `config.config_id`. Holds the concrete integration instance id for non-email channels (e.g. the `slack`/`webhook`/`ms_teams` integration). Must be unset when `type = \"email\"`.",
							Validators: []validator.String{
								fwvalidators.StringNotWhitespace(),
							},
						},
						"severity": schema.StringAttribute{
							Optional:            true,
							MarkdownDescription: "Optional per-notification severity label. Valid values: `critical`, `high`, `medium`, `low`, `informational`.",
							Validators: []validator.String{
								stringvalidator.OneOf("critical", "high", "medium", "low", "informational"),
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

	if res == nil || res.Payload == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	if d := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Create, res.Payload.Errors); d != nil {
		resp.Diagnostics.Append(d)
		return
	}

	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
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
			resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.Append(d)
		return
	}

	if res == nil || res.Payload == nil {
		resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
		resp.State.RemoveResource(ctx)
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
		resp.State.RemoveResource(ctx)
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

	expectedStatus := plan.Status.ValueString()

	// The API rejects a single PATCH that both sets status to "inactive" and
	// includes an operation (schedule/start_on/stop_on) payload. Send the
	// status change first (without operation), wait for it to settle, then
	// apply the schedule change in a second PATCH.
	if patchReq.Status == "inactive" && patchReq.Operation != nil {
		operation := patchReq.Operation
		patchReq.Operation = nil

		resp.Diagnostics.Append(r.sendPatch(ctx, patchReq)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if _, err := r.waitForStatus(ctx, plan.ID.ValueString(), expectedStatus); err != nil {
			resp.Diagnostics.AddError(
				"Error waiting for correlation rule status",
				fmt.Sprintf("Failed to wait for status %q: %s", expectedStatus, err),
			)
			return
		}

		schedulePatch := &rulePatchRequest{
			CorrelationrulesapiRulePatchRequestV1: models.CorrelationrulesapiRulePatchRequestV1{
				ID:        utils.Addr(plan.ID.ValueString()),
				Operation: operation,
			},
		}
		resp.Diagnostics.Append(r.sendPatch(ctx, schedulePatch)...)
		if resp.Diagnostics.HasError() {
			return
		}
	} else {
		resp.Diagnostics.Append(r.sendPatch(ctx, patchReq)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	// .status can become "creating" or "updating", which are undocumented intermediates.
	// Poll for status to become the value we want.
	// This usually happens within a few seconds
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

func (r *correlationRuleResource) sendPatch(
	ctx context.Context,
	patchReq *rulePatchRequest,
) diag.Diagnostics {
	var diags diag.Diagnostics

	res, err := r.client.CorrelationRules.EntitiesRulesPatchV1(
		&correlation_rules.EntitiesRulesPatchV1Params{Context: ctx},
		func(op *runtime.ClientOperation) {
			op.Params = &patchRuleParams{Body: []*rulePatchRequest{patchReq}}
		},
	)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopes))
		return diags
	}

	if res == nil || res.Payload == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return diags
	}

	if d := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Update, res.Payload.Errors); d != nil {
		diags.Append(d)
		return diags
	}

	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return diags
	}

	return diags
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

	r.validateNotifications(ctx, data.Notifications, &resp.Diagnostics)
}

func (r *correlationRuleResource) ModifyPlan(
	ctx context.Context,
	req resource.ModifyPlanRequest,
	resp *resource.ModifyPlanResponse,
) {
	if req.Plan.Raw.IsNull() {
		return
	}

	var plan CorrelationRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	planStartOn, planSchedModel, planOK := r.scheduleStartOn(ctx, plan.Schedule, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if !planOK {
		return
	}

	enforce := true
	if !req.State.Raw.IsNull() {
		var state CorrelationRuleResourceModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}

		_, stateSchedModel, stateOK := r.scheduleStartOn(ctx, state.Schedule, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}

		if stateOK && planSchedModel.StartOn.Equal(stateSchedModel.StartOn) {
			enforce = false
		}
	}

	if !enforce {
		return
	}

	minStartTime := time.Now().Add(15 * time.Minute)
	if planStartOn.Before(minStartTime) {
		resp.Diagnostics.AddAttributeError(
			path.Root("schedule").AtName("start_on"),
			"Invalid start_on time",
			fmt.Sprintf("start_on must be at least 15 minutes in the future. Provided: %s, minimum allowed: %s",
				planStartOn.Format(time.RFC3339),
				minStartTime.Format(time.RFC3339),
			),
		)
	}
}

func (r *correlationRuleResource) scheduleStartOn(
	ctx context.Context,
	sched types.Object,
	diags *diag.Diagnostics,
) (time.Time, ScheduleModel, bool) {
	var schedModel ScheduleModel

	if sched.IsNull() || sched.IsUnknown() {
		return time.Time{}, schedModel, false
	}

	diags.Append(sched.As(ctx, &schedModel, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return time.Time{}, schedModel, false
	}

	if schedModel.StartOn.IsNull() || schedModel.StartOn.IsUnknown() {
		return time.Time{}, schedModel, false
	}

	startOnTime, d := schedModel.StartOn.ValueRFC3339Time()
	if d.HasError() {
		diags.Append(d...)
		return time.Time{}, schedModel, false
	}

	return startOnTime, schedModel, true
}

func (r *correlationRuleResource) validateNotifications(
	ctx context.Context,
	notifs types.Set,
	diags *diag.Diagnostics,
) {
	if notifs.IsNull() || notifs.IsUnknown() {
		return
	}

	var models []NotificationModel
	diags.Append(notifs.ElementsAs(ctx, &models, false)...)
	if diags.HasError() {
		return
	}

	root := path.Root("notifications")
	hasGuardrail := false
	allKnownGuardrail := true
	for i, n := range models {
		elem := root.AtSetValue(notifs.Elements()[i])

		if n.IsGuardrail.IsUnknown() {
			allKnownGuardrail = false
		} else if n.IsGuardrail.ValueBool() {
			hasGuardrail = true
		}

		if n.Type.IsUnknown() {
			continue
		}
		ntype := n.Type.ValueString()
		isEmail := ntype == "email"

		pluginSet := !n.PluginID.IsNull() && !n.PluginID.IsUnknown()
		configSet := !n.ConfigID.IsNull() && !n.ConfigID.IsUnknown()
		recipientsSet := !n.Recipients.IsNull() && !n.Recipients.IsUnknown()

		if isEmail {
			if pluginSet {
				diags.AddAttributeError(
					elem.AtName("plugin_id"),
					"Invalid notification",
					"plugin_id must not be set when type is email.",
				)
			}
			if configSet {
				diags.AddAttributeError(
					elem.AtName("config_id"),
					"Invalid notification",
					"config_id must not be set when type is email.",
				)
			}
			if recipientsSet && len(n.Recipients.Elements()) == 0 {
				diags.AddAttributeError(
					elem.AtName("recipients"),
					"Invalid notification",
					"recipients must contain at least one email address when type is email.",
				)
			}
			if !recipientsSet {
				diags.AddAttributeError(
					elem.AtName("recipients"),
					"Invalid notification",
					"recipients is required when type is email.",
				)
			}
		} else {
			if !pluginSet && !configSet {
				diags.AddAttributeError(
					elem.AtName("config_id"),
					"Invalid notification",
					fmt.Sprintf("at least one of plugin_id or config_id is required when type is %q.", ntype),
				)
			}
			if recipientsSet {
				diags.AddAttributeError(
					elem.AtName("recipients"),
					"Invalid notification",
					fmt.Sprintf("recipients must not be set when type is %q; use plugin_id/config_id instead.", ntype),
				)
			}
		}
	}

	if !hasGuardrail && allKnownGuardrail {
		diags.AddAttributeError(
			root,
			"Missing guardrail notification",
			"At least one notification entry must set is_guardrail = true so the platform can alert when the rule is auto-deactivated for exceeding outcome thresholds.",
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
		Outcome:        utils.Addr(outcomeFromCreateCase(searchModel.CreateCase.ValueBool())),
		TriggerMode:    utils.Addr(searchModel.TriggerMode.ValueString()),
		ExecutionMode:  utils.Addr(searchModel.ExecutionMode.ValueString()),
		UseIngestTime:  searchModel.UseIngestTime.ValueBool(),
		CaseTemplateID: searchModel.CaseTemplateID.ValueString(),
	}

	// Extract schedule block
	schedule, d := r.buildCreateSchedule(ctx, plan.Schedule)
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

	// Extract notifications set, partitioning into regular and guardrail slices.
	notifications, guardrailNotifications, d := r.buildCreateNotifications(ctx, plan.Notifications, plan.CustomerID.ValueString())
	diags.Append(d...)
	if diags.HasError() {
		return nil, diags
	}

	createReq := &models.CorrelationrulesapiRuleCreateRequestV1{
		CustomerID:             utils.Addr(plan.CustomerID.ValueString()),
		Name:                   utils.Addr(plan.Name.ValueString()),
		Description:            plan.Description.ValueString(),
		Severity:               utils.Addr(severityNameToAPI[plan.Severity.ValueString()]),
		Status:                 utils.Addr(plan.Status.ValueString()),
		TemplateID:             utils.Addr(""),
		Comment:                plan.Comment.ValueString(),
		Search:                 search,
		Operation:              schedule,
		MitreAttack:            mitreAttack,
		Notifications:          notifications,
		GuardrailNotifications: guardrailNotifications,
	}

	return createReq, diags
}

// buildCreateSchedule builds the operation payload for the create request from
// the schedule block. The provider stores the schedule cadence as a bare
// duration (`1h0m`); the API expects `@every 1h0m`, so we prepend the prefix
// here and strip it on read.
func (r *correlationRuleResource) buildCreateSchedule(
	ctx context.Context,
	scheduleObj types.Object,
) (*models.CorrelationrulesapiCreateRuleOperationV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	operation := &models.CorrelationrulesapiCreateRuleOperationV1{}

	if scheduleObj.IsNull() || scheduleObj.IsUnknown() {
		return operation, diags
	}

	var schedModel ScheduleModel
	diags.Append(scheduleObj.As(ctx, &schedModel, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil, diags
	}

	if !schedModel.Interval.IsNull() && !schedModel.Interval.IsUnknown() {
		operation.Schedule = &models.CorrelationrulesapiRuleScheduleV1{
			Definition: utils.Addr("@every " + schedModel.Interval.ValueString()),
		}
	}

	if !schedModel.StartOn.IsNull() && !schedModel.StartOn.IsUnknown() {
		startOn, err := strfmt.ParseDateTime(schedModel.StartOn.ValueString())
		if err != nil {
			diags.AddError("Invalid start_on format", fmt.Sprintf("Failed to parse start_on: %s", err))
			return nil, diags
		}
		operation.StartOn = &startOn
	}

	if !schedModel.StopOn.IsNull() && !schedModel.StopOn.IsUnknown() {
		stopOn, err := strfmt.ParseDateTime(schedModel.StopOn.ValueString())
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
) (*rulePatchRequest, diag.Diagnostics) {
	var diags diag.Diagnostics

	patchReq := &rulePatchRequest{
		CorrelationrulesapiRulePatchRequestV1: models.CorrelationrulesapiRulePatchRequestV1{
			ID: utils.Addr(plan.ID.ValueString()),
		},
	}

	// Only include fields that have changed
	if !plan.Name.Equal(state.Name) {
		patchReq.Name = plan.Name.ValueString()
	}

	if !plan.Description.Equal(state.Description) {
		patchReq.Description = flex.FrameworkToStringPointer(plan.Description)
	}

	if !plan.Severity.Equal(state.Severity) {
		patchReq.Severity = severityNameToAPI[plan.Severity.ValueString()]
	}

	if !plan.Status.Equal(state.Status) {
		patchReq.Status = plan.Status.ValueString()
	}

	if !plan.Comment.Equal(state.Comment) {
		patchReq.Comment = flex.FrameworkToStringPointer(plan.Comment)
	}

	// Only include search if it changed
	if !plan.Search.Equal(state.Search) {
		if !plan.Search.IsNull() && !plan.Search.IsUnknown() {
			var planSearch SearchModel
			diags.Append(plan.Search.As(ctx, &planSearch, basetypes.ObjectAsOptions{})...)
			if diags.HasError() {
				return nil, diags
			}
			patchReq.Search = &patchRuleSearch{
				CorrelationrulesapiPatchRuleSearchV1: models.CorrelationrulesapiPatchRuleSearchV1{
					Filter:      planSearch.Filter.ValueString(),
					Lookback:    planSearch.Lookback.ValueString(),
					Outcome:     outcomeFromCreateCase(planSearch.CreateCase.ValueBool()),
					TriggerMode: planSearch.TriggerMode.ValueString(),
				},
				CaseTemplateID: flex.FrameworkToStringPointer(planSearch.CaseTemplateID),
				UseIngestTime:  utils.Addr(planSearch.UseIngestTime.ValueBool()),
			}
		}
	}

	operation, d := r.buildPatchSchedule(ctx, plan.Schedule, state.Schedule)
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

	if !plan.Notifications.Equal(state.Notifications) {
		notifications, guardrailNotifications, d := r.buildPatchNotifications(ctx, plan.Notifications, plan.CustomerID.ValueString())
		diags.Append(d...)
		if diags.HasError() {
			return nil, diags
		}
		patchReq.Notifications = notifications
		patchReq.GuardrailNotifications = guardrailNotifications
	}

	return patchReq, diags
}

// buildPatchSchedule builds the operation payload for the patch request from
// the schedule block. Only includes fields that have changed between state and
// plan. Prepends `@every ` to the cadence on the wire.
func (r *correlationRuleResource) buildPatchSchedule(
	ctx context.Context,
	planScheduleObj types.Object,
	stateScheduleObj types.Object,
) (*models.CorrelationrulesapiPatchRuleOperationV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	if planScheduleObj.IsNull() || planScheduleObj.IsUnknown() {
		return nil, diags
	}

	var planSched ScheduleModel
	diags.Append(planScheduleObj.As(ctx, &planSched, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil, diags
	}

	var stateSched ScheduleModel
	if !stateScheduleObj.IsNull() && !stateScheduleObj.IsUnknown() {
		diags.Append(stateScheduleObj.As(ctx, &stateSched, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return nil, diags
		}
	}

	operation := &models.CorrelationrulesapiPatchRuleOperationV1{}
	changed := false

	if !planSched.Interval.Equal(stateSched.Interval) {
		if !planSched.Interval.IsNull() && !planSched.Interval.IsUnknown() {
			operation.Schedule = &models.CorrelationrulesapiRuleScheduleV1Patch{
				Definition: utils.Addr("@every " + planSched.Interval.ValueString()),
			}
			changed = true
		}
	}

	if !planSched.StartOn.Equal(stateSched.StartOn) {
		if !planSched.StartOn.IsNull() && !planSched.StartOn.IsUnknown() {
			startOn, err := strfmt.ParseDateTime(planSched.StartOn.ValueString())
			if err != nil {
				diags.AddError("Invalid start_on format", fmt.Sprintf("Failed to parse start_on: %s", err))
				return nil, diags
			}
			operation.StartOn = &startOn
			changed = true
		}
	}

	if !planSched.StopOn.Equal(stateSched.StopOn) {
		if !planSched.StopOn.IsNull() && !planSched.StopOn.IsUnknown() {
			stopOnStr := planSched.StopOn.ValueString()
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

// regularNotificationOptions returns the fixed options map applied to every
// non-guardrail notification. The UI does not expose these as configurable, so
// the provider hardcodes them: notifications are only sent on failure.
func regularNotificationOptions() map[string]string {
	return map[string]string{
		"send_on_success": "never",
		"send_on_failure": "always",
	}
}

// buildCreateNotifications partitions the notifications set into regular and
// guardrail slices for the create API. `customerID` seeds the per-entry
// `config.cid` field (the API mirrors this back as the rule's own CID).
func (r *correlationRuleResource) buildCreateNotifications(
	ctx context.Context,
	notificationSet types.Set,
	customerID string,
) (regular, guardrail []*models.CorrelationrulesapiCreateRuleNotifications, diags diag.Diagnostics) {
	if notificationSet.IsNull() || notificationSet.IsUnknown() || len(notificationSet.Elements()) == 0 {
		return nil, nil, diags
	}

	var notifModels []NotificationModel
	diags.Append(notificationSet.ElementsAs(ctx, &notifModels, false)...)
	if diags.HasError() {
		return nil, nil, diags
	}

	for _, n := range notifModels {
		var recipients []string
		if !n.Recipients.IsNull() && !n.Recipients.IsUnknown() {
			diags.Append(n.Recipients.ElementsAs(ctx, &recipients, false)...)
			if diags.HasError() {
				return nil, nil, diags
			}
		}

		config := &models.CorrelationrulesapiCreateRuleNotificationConfig{
			Cid:        utils.Addr(customerID),
			Recipients: recipients,
		}

		if !n.PluginID.IsNull() && !n.PluginID.IsUnknown() {
			config.PluginID = utils.Addr(n.PluginID.ValueString())
		}
		if !n.ConfigID.IsNull() && !n.ConfigID.IsUnknown() {
			config.ConfigID = utils.Addr(n.ConfigID.ValueString())
		}
		if !n.Severity.IsNull() && !n.Severity.IsUnknown() {
			config.Severity = utils.Addr(n.Severity.ValueString())
		}

		notif := &models.CorrelationrulesapiCreateRuleNotifications{
			Type:   utils.Addr(n.Type.ValueString()),
			Config: config,
		}

		if n.IsGuardrail.ValueBool() {
			guardrail = append(guardrail, notif)
		} else {
			notif.Options = regularNotificationOptions()
			regular = append(regular, notif)
		}
	}

	return regular, guardrail, diags
}

// buildPatchNotifications partitions the notifications set into regular and
// guardrail slices for the patch API. The returned slices are always non-nil
// (empty slice when no entries belong to a side) so the API interprets them as
// "replace with this exact set".
func (r *correlationRuleResource) buildPatchNotifications(
	ctx context.Context,
	notificationSet types.Set,
	customerID string,
) (regular, guardrail []*patchRuleNotification, diags diag.Diagnostics) {
	regular = []*patchRuleNotification{}
	guardrail = []*patchRuleNotification{}

	if notificationSet.IsNull() || notificationSet.IsUnknown() {
		return regular, guardrail, diags
	}

	var notifModels []NotificationModel
	diags.Append(notificationSet.ElementsAs(ctx, &notifModels, false)...)
	if diags.HasError() {
		return nil, nil, diags
	}

	for _, n := range notifModels {
		var recipients []string
		if !n.Recipients.IsNull() && !n.Recipients.IsUnknown() {
			diags.Append(n.Recipients.ElementsAs(ctx, &recipients, false)...)
			if diags.HasError() {
				return nil, nil, diags
			}
		}

		config := &patchRuleNotificationConfig{
			CorrelationrulesapiPatchRuleNotificationConfigV1: models.CorrelationrulesapiPatchRuleNotificationConfigV1{
				Cid:        customerID,
				Recipients: recipients,
			},
		}

		// Always set pointers so PATCH can clear previously-set values when a
		// channel switches type or drops an id (see patch_overrides.go).
		pluginID := ""
		if !n.PluginID.IsNull() && !n.PluginID.IsUnknown() {
			pluginID = n.PluginID.ValueString()
		}
		configID := ""
		if !n.ConfigID.IsNull() && !n.ConfigID.IsUnknown() {
			configID = n.ConfigID.ValueString()
		}
		config.PluginID = utils.Addr(pluginID)
		config.ConfigID = utils.Addr(configID)
		config.Severity = utils.Addr(n.Severity.ValueString())

		notif := &patchRuleNotification{
			CorrelationrulesapiPatchRuleNotificationsV1: models.CorrelationrulesapiPatchRuleNotificationsV1{
				Type: n.Type.ValueString(),
			},
			Config: config,
		}

		if n.IsGuardrail.ValueBool() {
			guardrail = append(guardrail, notif)
		} else {
			notif.Options = regularNotificationOptions()
			regular = append(regular, notif)
		}
	}

	return regular, guardrail, diags
}

// wrap transforms API response values to their Terraform model values.
func (model *CorrelationRuleResourceModel) wrap(
	ctx context.Context,
	rule *models.CorrelationrulesapiRuleV1,
	id *string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	// The `id` field returned by the API is a version id that changes on every
	// PATCH. The stable identifier is `rule_id`. GET/PATCH/DELETE on
	// `/correlation-rules/entities/rules/v1` only accept `rule_id`, so we must
	// never overwrite state's `id` with the drifting version id from Read or
	// Update responses. Create passes the response's initial `id` (which equals
	// `rule_id` at that moment); Read and Update pass nil so state is preserved.
	if id != nil {
		model.ID = types.StringValue(*id)
	}
	if rule.CustomerID != nil {
		model.CustomerID = types.StringValue(*rule.CustomerID)
	}
	if rule.Name != nil {
		model.Name = types.StringValue(*rule.Name)
	}
	model.Description = flex.StringValueToFramework(rule.Description)
	if rule.Severity != nil {
		if name, ok := severityAPIToName[*rule.Severity]; ok {
			model.Severity = types.StringValue(name)
		}
	}
	if rule.Status != nil {
		model.Status = types.StringValue(*rule.Status)
	}
	model.Comment = flex.StringValueToFramework(rule.Comment)

	if rule.Search != nil {
		lookback, d := timetypes.NewGoDurationValueFromPointerString(rule.Search.Lookback)
		diags.Append(d...)
		if diags.HasError() {
			return diags
		}
		searchModel := SearchModel{
			Filter:         types.StringPointerValue(rule.Search.Filter),
			Lookback:       lookback,
			CreateCase:     types.BoolValue(rule.Search.Outcome != nil && *rule.Search.Outcome == outcomeCase),
			TriggerMode:    types.StringPointerValue(rule.Search.TriggerMode),
			ExecutionMode:  types.StringPointerValue(rule.Search.ExecutionMode),
			UseIngestTime:  types.BoolValue(rule.Search.UseIngestTime),
			CaseTemplateID: flex.StringValueToFramework(rule.Search.CaseTemplateID),
		}
		searchObj, d := types.ObjectValueFrom(ctx, searchModel.AttributeTypes(), searchModel)
		diags.Append(d...)
		if diags.HasError() {
			return diags
		}
		model.Search = searchObj
	}

	if rule.Operation != nil {
		schedModel := ScheduleModel{}

		if rule.Operation.Schedule != nil && rule.Operation.Schedule.Definition != nil {
			interval := *rule.Operation.Schedule.Definition
			interval = strings.TrimPrefix(interval, "@every ")
			intervalVal, d := timetypes.NewGoDurationValueFromString(interval)
			diags.Append(d...)
			if diags.HasError() {
				return diags
			}
			schedModel.Interval = intervalVal
		}

		if !rule.Operation.StartOn.IsZero() {
			schedModel.StartOn = fwtypes.NewRFC3339TimeValue(time.Time(rule.Operation.StartOn))
		} else {
			schedModel.StartOn = fwtypes.NewRFC3339Null()
		}

		if !rule.Operation.StopOn.IsZero() {
			schedModel.StopOn = fwtypes.NewRFC3339TimeValue(time.Time(rule.Operation.StopOn))
		} else {
			schedModel.StopOn = fwtypes.NewRFC3339Null()
		}

		schedObj, d := types.ObjectValueFrom(ctx, schedModel.AttributeTypes(), schedModel)
		diags.Append(d...)
		if diags.HasError() {
			return diags
		}
		model.Schedule = schedObj
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
				TechniqueID: flex.StringValueToFramework(m.TechniqueID),
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

	// Map notifications (merge regular + guardrail into single set)
	if len(rule.Notifications) == 0 && len(rule.GuardrailNotifications) == 0 {
		elemType := types.ObjectType{AttrTypes: NotificationModel{}.AttributeTypes()}
		if model.Notifications.IsNull() || model.Notifications.IsUnknown() {
			model.Notifications = types.SetNull(elemType)
		} else {
			model.Notifications = types.SetValueMust(elemType, []attr.Value{})
		}
	} else {
		notifSet, d := mapNotificationsFromAPI(ctx, rule.Notifications, rule.GuardrailNotifications)
		diags.Append(d...)
		if diags.HasError() {
			return diags
		}
		model.Notifications = notifSet
	}

	return diags
}

func mapNotificationsFromAPI(
	ctx context.Context,
	regular []*models.CorrelationrulesapiRuleNotificationsV1,
	guardrail []*models.CorrelationrulesapiRuleNotificationsV1,
) (types.Set, diag.Diagnostics) {
	var diags diag.Diagnostics
	elemType := types.ObjectType{AttrTypes: NotificationModel{}.AttributeTypes()}

	notifModels := make([]NotificationModel, 0, len(regular)+len(guardrail))

	for _, n := range regular {
		m, d := flattenNotification(ctx, n, false)
		diags.Append(d...)
		if diags.HasError() {
			return types.SetNull(elemType), diags
		}
		if m != nil {
			notifModels = append(notifModels, *m)
		}
	}
	for _, n := range guardrail {
		m, d := flattenNotification(ctx, n, true)
		diags.Append(d...)
		if diags.HasError() {
			return types.SetNull(elemType), diags
		}
		if m != nil {
			notifModels = append(notifModels, *m)
		}
	}

	notifSet, d := types.SetValueFrom(ctx, elemType, notifModels)
	diags.Append(d...)
	return notifSet, diags
}

func flattenNotification(
	ctx context.Context,
	n *models.CorrelationrulesapiRuleNotificationsV1,
	isGuardrail bool,
) (*NotificationModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	if n == nil || n.Config == nil {
		return nil, diags
	}

	m := NotificationModel{
		Type:        types.StringPointerValue(n.Type),
		IsGuardrail: types.BoolValue(isGuardrail),
	}

	// Non-email channels come back with recipients=null; keep the attribute
	// null in that case so config (which omits recipients) round-trips cleanly.
	if len(n.Config.Recipients) == 0 {
		m.Recipients = types.ListNull(types.StringType)
	} else {
		recipients, d := types.ListValueFrom(ctx, types.StringType, n.Config.Recipients)
		diags.Append(d...)
		if diags.HasError() {
			return nil, diags
		}
		m.Recipients = recipients
	}

	m.PluginID = flex.StringPointerToFramework(n.Config.PluginID)
	m.ConfigID = flex.StringPointerToFramework(n.Config.ConfigID)
	m.Severity = flex.StringPointerToFramework(n.Config.Severity)

	return &m, diags
}
