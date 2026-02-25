package cloudsecurity

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &cloudSecurityKacCustomRuleResource{}
	_ resource.ResourceWithConfigure   = &cloudSecurityKacCustomRuleResource{}
	_ resource.ResourceWithImportState = &cloudSecurityKacCustomRuleResource{}
)

const (
	KacRuleDefaultPlatform  = "Kubernetes"
	KacRuleDefaultProvider  = "Kubernetes"
	KacRuleDefaultDomain    = "Runtime"
	KacRuleDefaultSubdomain = "IOM"
	KacRuleDefaultSeverity  = "critical"
)

var (
	kacRuledocumentationSection        string         = "Falcon Cloud Security"
	kacRuleresourceMarkdownDescription string         = "This resource manages custom cloud security KAC rules."
	kacRuleRequiredScopes              []scopes.Scope = cloudSecurityRuleScopes
)

func NewCloudSecurityKacCustomRuleResource() resource.Resource {
	return &cloudSecurityKacCustomRuleResource{}
}

type cloudSecurityKacCustomRuleResource struct {
	client *client.CrowdStrikeAPISpecification
}

type cloudSecurityKacCustomRuleResourceModel struct {
	ID              types.String `tfsdk:"id"`
	Description     types.String `tfsdk:"description"`
	Logic           types.String `tfsdk:"logic"`
	Name            types.String `tfsdk:"name"`
	Severity        types.String `tfsdk:"severity"`
	RemediationInfo types.List   `tfsdk:"remediation_info"`
	AttackTypes     types.Set    `tfsdk:"attack_types"`
	AlertInfo       types.List   `tfsdk:"alert_info"`
}

func (r *cloudSecurityKacCustomRuleResource) Configure(
	ctx context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	config, ok := req.ProviderData.(config.ProviderConfig)

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

	r.client = config.Client
}

func (r *cloudSecurityKacCustomRuleResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_security_kac_custom_rule"
}

func (r *cloudSecurityKacCustomRuleResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(kacRuledocumentationSection, kacRuleresourceMarkdownDescription, kacRuleRequiredScopes),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier of the policy rule.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
						"must be a valid Id in the format of 7c86a274-c04b-4292-9f03-dafae42bde97",
					),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					stringplanmodifier.RequiresReplace(),
				},
			},
			"description": schema.StringAttribute{
				Required:    true,
				Description: "Description of the policy rule.",
			},
			"logic": schema.StringAttribute{
				Required:    true,
				Description: "Rego logic for the rule.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the policy rule.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"severity": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(KacRuleDefaultSeverity),
				MarkdownDescription: "Severity of the rule. Valid values are `critical`, `high`, `medium`, `informational`.",
				Validators: []validator.String{
					stringvalidator.OneOf("critical", "high", "medium", "informational"),
				},
			},
			"remediation_info": schema.ListAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Information about how to remediate issues detected by this rule.",
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
					listvalidator.ValueStringsAre(
						stringvalidator.LengthAtLeast(1),
					),
				},
			},
			"attack_types": schema.SetAttribute{
				Optional:            true,
				MarkdownDescription: "Specific attack types associated with the rule.",
				ElementType:         types.StringType,
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(
						stringvalidator.LengthAtLeast(1),
					),
				},
			},
			"alert_info": schema.ListAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "A list of the alert logic and detection criteria for rule violations.",
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
					listvalidator.ValueStringsAre(
						stringvalidator.LengthAtLeast(1),
					),
				},
			},
		},
	}
}

func (r *cloudSecurityKacCustomRuleResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan cloudSecurityKacCustomRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rule, diags := r.createCloudPolicyRule(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if rule != nil && rule.UUID != nil {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), types.StringPointerValue(rule.UUID))...)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, rule)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *cloudSecurityKacCustomRuleResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state cloudSecurityKacCustomRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rule, diags := r.getCloudPolicyRule(ctx, state.ID.ValueString())

	if diags.HasError() {
		if tferrors.HasNotFoundError(diags) {
			resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, rule)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *cloudSecurityKacCustomRuleResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan cloudSecurityKacCustomRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rule, diags := r.updateCloudPolicyRule(ctx, &plan)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, rule)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *cloudSecurityKacCustomRuleResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state cloudSecurityKacCustomRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.deleteCloudPolicyRule(ctx, state.ID.ValueString())...)
}

func (r *cloudSecurityKacCustomRuleResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (m *cloudSecurityKacCustomRuleResourceModel) wrap(
	ctx context.Context,
	rule *models.ApimodelsRule,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringPointerValue(rule.UUID)
	m.Name = types.StringPointerValue(rule.Name)
	m.Description = types.StringPointerValue(rule.Description)
	m.Logic = types.StringValue(rule.Logic)

	if rule.Severity != nil {
		m.Severity = types.StringValue(int32ToSeverity[int32(*rule.Severity)])
	} else {
		m.Severity = types.StringNull()
	}

	m.AlertInfo, diags = flex.FlattenStringValueList(ctx, convertAlertRemediationInfoToTerraformState(rule.AlertInfo))
	if diags.HasError() {
		return diags
	}

	m.RemediationInfo, diags = flex.FlattenStringValueList(ctx, convertAlertRemediationInfoToTerraformState(rule.Remediation))
	if diags.HasError() {
		return diags
	}

	m.AttackTypes = types.SetNull(types.StringType)
	if len(rule.AttackTypes) > 0 {
		filteredAttackTypes := make([]types.String, 0, len(rule.AttackTypes))
		for _, attackType := range rule.AttackTypes {
			if attackType != "" {
				filteredAttackTypes = append(filteredAttackTypes, types.StringValue(attackType))
			}
		}
		if len(filteredAttackTypes) > 0 {
			attackTypes, diags := types.SetValueFrom(ctx, types.StringType, filteredAttackTypes)
			if diags.HasError() {
				return diags
			}
			m.AttackTypes = attackTypes
		}
	}

	return diags
}

func (r *cloudSecurityKacCustomRuleResource) createCloudPolicyRule(ctx context.Context, plan *cloudSecurityKacCustomRuleResourceModel) (*models.ApimodelsRule, diag.Diagnostics) {
	var diags diag.Diagnostics
	body := &models.CommonCreateRuleRequest{
		Description: plan.Description.ValueStringPointer(),
		Name:        plan.Name.ValueStringPointer(),
		Platform:    utils.Addr(KacRuleDefaultPlatform),
		Provider:    utils.Addr(KacRuleDefaultProvider),
		Logic:       plan.Logic.ValueStringPointer(),
		Domain:      utils.Addr(KacRuleDefaultDomain),
		Subdomain:   utils.Addr(KacRuleDefaultSubdomain),
		Severity:    severityToInt64[plan.Severity.ValueString()],
	}

	if !plan.AlertInfo.IsNull() {
		body.AlertInfo, diags = convertAlertInfoToAPIFormat(ctx, plan.AlertInfo)
		if diags.HasError() {
			return nil, diags
		}
	}

	if !plan.RemediationInfo.IsNull() {
		body.RemediationInfo, diags = convertRemediationInfoToAPIFormat(ctx, plan.RemediationInfo)
		if diags.HasError() {
			return nil, diags
		}
	}

	if len(plan.AttackTypes.Elements()) > 0 {
		var attackTypes []string
		diags = plan.AttackTypes.ElementsAs(ctx, &attackTypes, false)
		if diags.HasError() {
			return nil, diags
		}
		body.AttackTypes = strings.Join(attackTypes, ",")
	}

	return createCloudPolicyRule(r.client, cloud_policies.CreateRuleMixin0Params{
		Context: ctx,
		Body:    body,
	}, kacRuleRequiredScopes)
}

func (r *cloudSecurityKacCustomRuleResource) getCloudPolicyRule(ctx context.Context, id string) (*models.ApimodelsRule, diag.Diagnostics) {
	return getCloudPolicyRule(r.client, cloud_policies.GetRuleParams{
		Context: ctx,
		Ids:     []string{id},
	}, kacRuleRequiredScopes)
}

func (r *cloudSecurityKacCustomRuleResource) updateCloudPolicyRule(ctx context.Context, plan *cloudSecurityKacCustomRuleResourceModel) (*models.ApimodelsRule, diag.Diagnostics) {
	body := &models.CommonUpdateRuleRequest{
		Description: plan.Description.ValueString(),
		Name:        plan.Name.ValueString(),
		UUID:        plan.ID.ValueStringPointer(),
		Severity:    severityToInt64[plan.Severity.ValueString()],
		RuleLogicList: []*models.ApimodelsRuleLogic{{
			Platform: utils.Addr(KacRuleDefaultPlatform),
			Logic:    plan.Logic.ValueString(),
		}},
	}

	if !plan.AlertInfo.IsNull() {
		alertInfo, diags := convertAlertInfoToAPIFormat(ctx, plan.AlertInfo)
		if diags.HasError() {
			return nil, diags
		}
		body.AlertInfo = &alertInfo
	}

	if !plan.RemediationInfo.IsNull() {
		remediationInfo, diags := convertRemediationInfoToAPIFormat(ctx, plan.RemediationInfo)
		if diags.HasError() {
			return nil, diags
		}
		body.RuleLogicList[0].RemediationInfo = &remediationInfo
	}

	if len(plan.AttackTypes.Elements()) > 0 {
		var attackTypes []string
		diags := plan.AttackTypes.ElementsAs(ctx, &attackTypes, false)
		if diags.HasError() {
			return nil, diags
		}
		body.AttackTypes = attackTypes
	}

	return updateCloudPolicyRule(r.client, cloud_policies.UpdateRuleParams{
		Context: ctx,
		Body:    body,
	}, kacRuleRequiredScopes)
}

func (r *cloudSecurityKacCustomRuleResource) deleteCloudPolicyRule(ctx context.Context, id string) diag.Diagnostics {
	return deleteCloudPolicyRule(r.client, cloud_policies.DeleteRuleMixin0Params{
		Context: ctx,
		Ids:     []string{id},
	}, kacRuleRequiredScopes)
}
