package cloudsecurity

import (
	"context"
	"fmt"
	"regexp"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwtypes "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/types"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &cloudSecurityIacCustomRuleResource{}
	_ resource.ResourceWithConfigure   = &cloudSecurityIacCustomRuleResource{}
	_ resource.ResourceWithImportState = &cloudSecurityIacCustomRuleResource{}
)

const (
	IacRuleDefaultDomain    = "CSPM"
	IacRuleDefaultSubdomain = "IAC"
	IacRuleDefaultSeverity  = "critical"
)

var (
	IacRuledocumentationSection        string = "Falcon Cloud Security"
	IacRuleresourceMarkdownDescription string = "This resource manages custom cloud security IAC rules. " +
		"These rules enable scanning of Infrastructure as Code (IaC) configurations for security issues and policy violations using custom Rego policies. "
	IacRuleRequiredScopes []scopes.Scope = cloudSecurityIacRuleScopes
)

func NewCloudSecurityIacCustomRuleResource() resource.Resource {
	return &cloudSecurityIacCustomRuleResource{}
}

type cloudSecurityIacCustomRuleResource struct {
	client *client.CrowdStrikeAPISpecification
}

type cloudSecurityIacCustomRuleResourceModel struct {
	ID              types.String                                `tfsdk:"id"`
	Description     types.String                                `tfsdk:"description"`
	Logic           fwtypes.TrailingWhitespaceInsensitiveString `tfsdk:"logic"`
	Name            types.String                                `tfsdk:"name"`
	Severity        types.String                                `tfsdk:"severity"`
	CloudProvider   types.String                                `tfsdk:"cloud_provider"`
	IacFramework    types.String                                `tfsdk:"iac_framework"`
	ResourceType    types.String                                `tfsdk:"resource_type"`
	RemediationInfo types.List                                  `tfsdk:"remediation_info"`
	Category        fwtypes.CaseInsensitiveString               `tfsdk:"category"`
	AlertInfo       types.List                                  `tfsdk:"alert_info"`
	Labels          types.List                                  `tfsdk:"labels"`
}

func (r *cloudSecurityIacCustomRuleResource) Configure(
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

func (r *cloudSecurityIacCustomRuleResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_security_iac_custom_rule"
}

func (r *cloudSecurityIacCustomRuleResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(IacRuledocumentationSection, IacRuleresourceMarkdownDescription, IacRuleRequiredScopes),
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
				CustomType:  fwtypes.TrailingWhitespaceInsensitiveStringType{},
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
			"cloud_provider": schema.StringAttribute{
				Required:    true,
				Description: "Cloud provider for the policy rule. Valid values are `AWS`, `Azure`, `GCP`, `General`.",
				Validators: []validator.String{
					stringvalidator.OneOf(
						"AWS",
						"Azure",
						"GCP",
						"General",
					),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"iac_framework": schema.StringAttribute{
				Computed:    true,
				Default:     stringdefault.StaticString("Terraform"),
				Description: "Infrastructure-as-code framework for the custom rule. Currently only Terraform is supported.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"resource_type": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("Custom"),
				MarkdownDescription: "Service-level category. Examples: `ACM`, `S3`, `IAM` for AWS; `AKS`, `Key Vault` for Azure; `BigQuery`, `GKE` for GCP. Defaults to `Custom`.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"severity": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(IacRuleDefaultSeverity),
				MarkdownDescription: "Severity of the rule. Valid values are `critical`, `high`, `medium`, `informational`.",
				Validators: []validator.String{
					stringvalidator.OneOf("critical", "high", "medium", "informational"),
				},
			},
			"remediation_info": schema.ListAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Information about how to remediate issues detected by this rule. Do not include numbering within this list. The Falcon console will automatically add numbering.",
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
					listvalidator.ValueStringsAre(
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
			"category": schema.StringAttribute{
				CustomType:          fwtypes.CaseInsensitiveStringType{},
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Grouping category for the rule (e.g., `Encryption`, `Networking`, `Backup`). The API may normalize the casing.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"labels": schema.ListAttribute{
				Optional:            true,
				Computed:            true,
				ElementType:         fwtypes.CaseInsensitiveStringType{},
				MarkdownDescription: "Array of string labels for filtering and organizing rules. Changing this requires replacing the resource. The API may normalize the casing.",
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.LengthAtLeast(1),
					),
				},
				PlanModifiers: []planmodifier.List{
					listplanmodifier.RequiresReplace(),
					listplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *cloudSecurityIacCustomRuleResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan cloudSecurityIacCustomRuleResourceModel
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

func (r *cloudSecurityIacCustomRuleResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state cloudSecurityIacCustomRuleResourceModel
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

func (r *cloudSecurityIacCustomRuleResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan cloudSecurityIacCustomRuleResourceModel
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

func (r *cloudSecurityIacCustomRuleResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state cloudSecurityIacCustomRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.deleteCloudPolicyRule(ctx, state.ID.ValueString())...)
}

func (r *cloudSecurityIacCustomRuleResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (m *cloudSecurityIacCustomRuleResourceModel) wrap(
	ctx context.Context,
	rule *models.ApimodelsRule,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringPointerValue(rule.UUID)
	m.Name = types.StringPointerValue(rule.Name)
	m.Description = types.StringPointerValue(rule.Description)
	m.Logic = fwtypes.TrailingWhitespaceInsensitiveString{
		StringValue: types.StringValue(rule.Logic),
	}
	m.Category = fwtypes.CaseInsensitiveString{
		StringValue: flex.StringValueToFramework(rule.Category),
	}

	m.RemediationInfo, diags = flex.FlattenStringValueList(ctx, convertAlertRemediationInfoToTerraformState(rule.Remediation))
	if diags.HasError() {
		return diags
	}

	if rule.Severity != nil {
		m.Severity = types.StringValue(int32ToSeverity[int32(*rule.Severity)])
	} else {
		m.Severity = types.StringNull()
	}

	m.AlertInfo, diags = flex.FlattenStringValueList(ctx, convertAlertRemediationInfoToTerraformState(rule.AlertInfo))
	if diags.HasError() {
		return diags
	}

	m.CloudProvider = flex.StringPointerToFramework(rule.Provider)

	if len(rule.RuleLogicList) > 0 {
		m.IacFramework = flex.StringPointerToFramework(rule.RuleLogicList[0].Platform)
	}

	if len(rule.ResourceTypes) > 0 {
		m.ResourceType = flex.StringPointerToFramework(rule.ResourceTypes[0].ResourceType)
	}

	m.Labels = types.ListNull(fwtypes.CaseInsensitiveStringType{})

	if rule.CustomConfiguration == nil {
		return diags
	}

	customConfig, ok := rule.CustomConfiguration.(map[string]interface{})
	if !ok {
		return diags
	}

	labelsInterface, exists := customConfig["labels"]
	if !exists {
		return diags
	}

	labelsArray, ok := labelsInterface.([]interface{})
	if !ok {
		return diags
	}

	labelValues := make([]attr.Value, 0, len(labelsArray))
	for _, label := range labelsArray {
		if labelStr, ok := label.(string); ok {
			labelValues = append(labelValues, fwtypes.CaseInsensitiveString{
				StringValue: types.StringValue(labelStr),
			})
		}
	}

	if len(labelValues) > 0 {
		m.Labels, diags = types.ListValue(fwtypes.CaseInsensitiveStringType{}, labelValues)
		if diags.HasError() {
			return diags
		}
	}

	return diags
}

func (r *cloudSecurityIacCustomRuleResource) createCloudPolicyRule(ctx context.Context, plan *cloudSecurityIacCustomRuleResourceModel) (*models.ApimodelsRule, diag.Diagnostics) {
	var diags diag.Diagnostics
	body := &models.CommonCreateRuleRequest{
		Description:  plan.Description.ValueStringPointer(),
		Name:         plan.Name.ValueStringPointer(),
		Platform:     plan.IacFramework.ValueStringPointer(),
		Provider:     plan.CloudProvider.ValueStringPointer(),
		Logic:        plan.Logic.ValueStringPointer(),
		Domain:       utils.Addr(IacRuleDefaultDomain),
		Subdomain:    utils.Addr(IacRuleDefaultSubdomain),
		Severity:     severityToInt64[plan.Severity.ValueString()],
		ResourceType: plan.ResourceType.ValueStringPointer(),
	}

	if !plan.Category.IsNull() {
		body.Category = plan.Category.ValueString()
	}

	if !plan.RemediationInfo.IsNull() {
		body.RemediationInfo, diags = convertRemediationInfoToAPIFormat(ctx, plan.RemediationInfo)
		if diags.HasError() {
			return nil, diags
		}
	}

	if !plan.AlertInfo.IsNull() {
		body.AlertInfo, diags = convertAlertInfoToAPIFormat(ctx, plan.AlertInfo)
		if diags.HasError() {
			return nil, diags
		}
	}

	if !plan.Labels.IsNull() && len(plan.Labels.Elements()) > 0 {
		labelElements := plan.Labels.Elements()
		labels := make([]string, 0, len(labelElements))
		for _, elem := range labelElements {
			if labelVal, ok := elem.(fwtypes.CaseInsensitiveString); ok {
				labels = append(labels, labelVal.ValueString())
			}
		}
		if len(labels) > 0 {
			body.Labels = labels
		}
	}

	return createCloudPolicyRule(r.client, cloud_policies.CreateRuleMixin0Params{
		Context: ctx,
		Body:    body,
	}, IacRuleRequiredScopes)
}

func (r *cloudSecurityIacCustomRuleResource) getCloudPolicyRule(ctx context.Context, id string) (*models.ApimodelsRule, diag.Diagnostics) {
	return getCloudPolicyRule(r.client, cloud_policies.GetRuleParams{
		Context: ctx,
		Ids:     []string{id},
	}, IacRuleRequiredScopes)
}

func (r *cloudSecurityIacCustomRuleResource) updateCloudPolicyRule(ctx context.Context, plan *cloudSecurityIacCustomRuleResourceModel) (*models.ApimodelsRule, diag.Diagnostics) {
	var diags diag.Diagnostics
	var remediationInfo string

	body := &models.CommonUpdateRuleRequest{
		Description: plan.Description.ValueString(),
		Name:        plan.Name.ValueString(),
		UUID:        plan.ID.ValueStringPointer(),
		Severity:    severityToInt64[plan.Severity.ValueString()],
	}

	if !plan.Category.IsNull() {
		body.Category = plan.Category.ValueString()
	}

	if !plan.RemediationInfo.IsNull() {
		remediationInfo, diags = convertRemediationInfoToAPIFormat(ctx, plan.RemediationInfo)
		if diags.HasError() {
			return nil, diags
		}
	}

	body.RuleLogicList = []*models.ApimodelsRuleLogic{{
		Platform:        plan.IacFramework.ValueStringPointer(),
		RemediationInfo: &remediationInfo,
		Logic:           plan.Logic.ValueString(),
	}}

	if !plan.AlertInfo.IsNull() {
		alertInfo, convertDiags := convertAlertInfoToAPIFormat(ctx, plan.AlertInfo)
		diags.Append(convertDiags...)
		if diags.HasError() {
			return nil, diags
		}
		body.AlertInfo = &alertInfo
	}

	return updateCloudPolicyRule(r.client, cloud_policies.UpdateRuleParams{
		Context: ctx,
		Body:    body,
	}, IacRuleRequiredScopes)
}

func (r *cloudSecurityIacCustomRuleResource) deleteCloudPolicyRule(ctx context.Context, id string) diag.Diagnostics {
	return deleteCloudPolicyRule(r.client, cloud_policies.DeleteRuleMixin0Params{
		Context: ctx,
		Ids:     []string{id},
	}, IacRuleRequiredScopes)
}
