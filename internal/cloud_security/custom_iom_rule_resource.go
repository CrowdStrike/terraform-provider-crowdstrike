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
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
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
	_ resource.Resource                = &cloudSecurityIomCustomRuleResource{}
	_ resource.ResourceWithConfigure   = &cloudSecurityIomCustomRuleResource{}
	_ resource.ResourceWithImportState = &cloudSecurityIomCustomRuleResource{}
	_ resource.ResourceWithModifyPlan  = &cloudSecurityIomCustomRuleResource{}
)

const (
	IomRuleDefaultDomain    = "CSPM"
	IomRuleDefaultSubdomain = "IOM"
	IomRuleDefaultSeverity  = "critical"
)

var (
	iomRuleDocumentationSection        string = "Falcon Cloud Security"
	iomRuleResourceMarkdownDescription string = "This resource manages custom cloud security IOM rules. " +
		"These rules can be created either by inheriting properties from a parent rule with minimal customization, or by fully customizing all attributes for maximum flexibility. " +
		"To create a rule based on a parent rule, utilize the `crowdstrike_cloud_security_rules` data source to gather parent rule information to use in the new custom rule. " +
		"The `crowdstrike_cloud_compliance_framework_controls` data source can be used to query Falcon for compliance benchmark controls to associate with custom rules created with this resource. "
	iomRuleRequiredScopes []scopes.Scope = cloudSecurityRuleScopes
)

func NewCloudSecurityIomCustomRuleResource() resource.Resource {
	return &cloudSecurityIomCustomRuleResource{}
}

type cloudSecurityIomCustomRuleResource struct {
	client *client.CrowdStrikeAPISpecification
}

type cloudSecurityIomCustomRuleResourceModel struct {
	ID              types.String `tfsdk:"id"`
	AlertInfo       types.List   `tfsdk:"alert_info"`
	Controls        types.Set    `tfsdk:"controls"`
	Description     types.String `tfsdk:"description"`
	Logic           types.String `tfsdk:"logic"`
	Name            types.String `tfsdk:"name"`
	AttackTypes     types.Set    `tfsdk:"attack_types"`
	ParentRuleId    types.String `tfsdk:"parent_rule_id"`
	CloudPlatform   types.String `tfsdk:"cloud_platform"`
	CloudProvider   types.String `tfsdk:"cloud_provider"`
	RemediationInfo types.List   `tfsdk:"remediation_info"`
	ResourceType    types.String `tfsdk:"resource_type"`
	Severity        types.String `tfsdk:"severity"`
}

func (r *cloudSecurityIomCustomRuleResource) Configure(
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

func (r *cloudSecurityIomCustomRuleResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_security_iom_custom_rule"
}

func (r *cloudSecurityIomCustomRuleResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(iomRuleDocumentationSection, iomRuleResourceMarkdownDescription, iomRuleRequiredScopes),
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
			"alert_info": schema.ListAttribute{
				Optional:            true,
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "A list of the alert logic and detection criteria for rule violations. Do not include numbering within this list. The Falcon console will automatically add numbering. When `alert_info` is not defined and `parent_rule_id` is defined, this field will inherit the parent rule's `alert_info`.",
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
					listvalidator.ValueStringsAre(
						validators.StringNotWhitespace(),
					),
				},
			},
			"controls": schema.SetNestedAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Security framework and compliance rule information. Utilize the `crowdstrike_cloud_compliance_framework_controls` data source to obtain this information. When `controls` is not defined and `parent_rule_id` is defined, this field will inherit the parent rule's `controls`.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"authority": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "The compliance framework",
							Validators: []validator.String{
								validators.StringNotWhitespace(),
							},
						},
						"code": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "The compliance framework rule code",
							Validators: []validator.String{
								validators.StringNotWhitespace(),
							},
						},
					},
				},
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
				},
			},
			"description": schema.StringAttribute{
				Required:    true,
				Description: "Description of the policy rule.",
			},
			"attack_types": schema.SetAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Specific attack types associated with the rule. If `parent_rule_id` is defined, `attack_types` will be inherited from the parent rule and cannot be specified using this field.",
				ElementType:         types.StringType,
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(
						validators.StringNotWhitespace(),
					),
				},
			},
			"logic": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Rego logic for the rule. Either `logic` or `parent_rule_id` must be defined. When `parent_rule_id` is set, the rule inherits the Rego logic from the parent rule. Note: The API does not return Rego logic for rules created from a parent rule, so this field will not appear in state when using `parent_rule_id`.",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the policy rule.",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"parent_rule_id": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Id of the parent rule to inherit properties from. The `crowdstrike_cloud_security_rules` data source can be used to query Falcon for parent rule information to use in this field. Required if `logic` is not specified.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
						"must be a valid Id in the format of 7c86a274-c04b-4292-9f03-dafae42bde97",
					),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"cloud_platform": schema.StringAttribute{
				Computed:    true,
				Description: "Cloud platform for the policy rule.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"cloud_provider": schema.StringAttribute{
				Required:    true,
				Description: "Cloud provider for the policy rule.",
				Validators: []validator.String{
					stringvalidator.OneOf(
						"AWS",
						"Azure",
						"GCP",
					),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"remediation_info": schema.ListAttribute{
				Optional:            true,
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Information about how to remediate issues detected by this rule. Do not include numbering within this list. The Falcon console will automatically add numbering. When `remediation_info` is not defined and `parent_rule_id` is defined, this field will inherit the parent rule's `remediation_info`.",
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
					listvalidator.ValueStringsAre(
						validators.StringNotWhitespace(),
					),
				},
			},
			"resource_type": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The full resource type. Examples: `AWS::IAM::CredentialReport`, `Microsoft.Compute/virtualMachines`, `container.googleapis.com/Cluster`",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"severity": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(IomRuleDefaultSeverity),
				MarkdownDescription: "Severity of the rule. Valid values are `critical`, `high`, `medium`, `informational`.",
				Validators: []validator.String{
					stringvalidator.OneOf("critical", "high", "medium", "informational"),
				},
			},
		},
	}
}

func (r *cloudSecurityIomCustomRuleResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan cloudSecurityIomCustomRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.CloudPlatform = plan.CloudProvider

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

func (r *cloudSecurityIomCustomRuleResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state cloudSecurityIomCustomRuleResourceModel
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

func (r *cloudSecurityIomCustomRuleResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan cloudSecurityIomCustomRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.CloudPlatform = plan.CloudProvider

	rule, diags := r.updateCloudPolicyRule(ctx, &plan)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, rule)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *cloudSecurityIomCustomRuleResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state cloudSecurityIomCustomRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.deleteCloudPolicyRule(ctx, state.ID.ValueString())...)
}

func (r *cloudSecurityIomCustomRuleResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r cloudSecurityIomCustomRuleResource) ConfigValidators(ctx context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		resourcevalidator.ExactlyOneOf(
			path.MatchRoot("logic"),
			path.MatchRoot("parent_rule_id"),
		),
		resourcevalidator.Conflicting(
			path.MatchRoot("parent_rule_id"),
			path.MatchRoot("attack_types"),
		),
	}
}

func (r *cloudSecurityIomCustomRuleResource) ModifyPlan(
	ctx context.Context,
	req resource.ModifyPlanRequest,
	resp *resource.ModifyPlanResponse,
) {
	if req.Plan.Raw.IsNull() {
		return
	}

	// this prevents these checks from running on resource creation
	if req.State.Raw.IsNull() {
		return
	}

	var plan, config cloudSecurityIomCustomRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if utils.IsKnown(config.ParentRuleId) {
		if utils.IsNull(config.AlertInfo) || utils.IsNull(config.Controls) || utils.IsNull(config.RemediationInfo) {
			var parent cloudSecurityIomCustomRuleResourceModel
			rule, diags := r.getCloudPolicyRule(ctx, plan.ParentRuleId.ValueString())
			resp.Diagnostics.Append(diags...)
			if resp.Diagnostics.HasError() {
				return
			}

			resp.Diagnostics.Append(parent.wrap(ctx, rule)...)
			if resp.Diagnostics.HasError() {
				return
			}

			if utils.IsNull(config.AlertInfo) {
				plan.AlertInfo = parent.AlertInfo
			}

			if utils.IsNull(config.RemediationInfo) {
				plan.RemediationInfo = parent.RemediationInfo
			}

			if utils.IsNull(config.Controls) {
				plan.Controls = parent.Controls
			}
		}
	} else {
		// Set values to unknown when parent rule is not yet known, allowing Update and Create to handle inherited values.
		if utils.IsNull(config.AlertInfo) && utils.IsKnown(plan.AlertInfo) {
			plan.AlertInfo = types.ListUnknown(plan.AlertInfo.ElementType(ctx))
		}

		if utils.IsNull(config.RemediationInfo) && utils.IsKnown(plan.RemediationInfo) {
			plan.RemediationInfo = types.ListUnknown(plan.RemediationInfo.ElementType(ctx))
		}

		if utils.IsNull(config.Controls) && utils.IsKnown(plan.Controls) {
			plan.Controls = types.SetUnknown(plan.Controls.ElementType(ctx))
		}
	}

	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
}

func (m *cloudSecurityIomCustomRuleResourceModel) wrap(
	ctx context.Context,
	rule *models.ApimodelsRule,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringPointerValue(rule.UUID)
	m.Name = types.StringPointerValue(rule.Name)
	m.Description = types.StringPointerValue(rule.Description)
	m.CloudProvider = types.StringPointerValue(rule.Provider)

	m.RemediationInfo, diags = flex.FlattenStringValueList(ctx, convertAlertRemediationInfoToTerraformState(rule.Remediation))
	if diags.HasError() {
		return diags
	}

	m.AlertInfo, diags = flex.FlattenStringValueList(ctx, convertAlertRemediationInfoToTerraformState(rule.AlertInfo))
	if diags.HasError() {
		return diags
	}

	if rule.Severity != nil {
		m.Severity = types.StringValue(int32ToSeverity[int32(*rule.Severity)])
	} else {
		m.Severity = types.StringNull()
	}

	if rule.ParentRuleShortUUID != "" {
		m.ParentRuleId = types.StringValue(rule.ParentRuleShortUUID)
	} else {
		m.Logic = types.StringValue(rule.Logic)
	}

	filteredAttackTypes := make([]string, 0, len(rule.AttackTypes))
	for _, attackType := range rule.AttackTypes {
		trimmed := strings.TrimSpace(attackType)
		if trimmed != "" {
			filteredAttackTypes = append(filteredAttackTypes, trimmed)
		}
	}

	m.AttackTypes, diags = flex.FlattenStringValueSet(ctx, filteredAttackTypes)
	if diags.HasError() {
		return diags
	}

	var controlsDiags diag.Diagnostics
	m.Controls, controlsDiags = flex.FlattenObjectValueSetFrom(
		ctx,
		types.ObjectType{AttrTypes: policyControl{}.AttributeTypes()},
		rule.Controls,
		func(control *models.ApimodelsControl) (policyControl, diag.Diagnostics) {
			return policyControl{
				Authority: types.StringPointerValue(control.Authority),
				Code:      types.StringPointerValue(control.Code),
			}, nil
		},
	)
	diags.Append(controlsDiags...)
	if diags.HasError() {
		return diags
	}

	if len(rule.RuleLogicList) > 0 {
		m.CloudPlatform = types.StringPointerValue(rule.RuleLogicList[0].Platform)
	}

	if len(rule.ResourceTypes) > 0 {
		m.ResourceType = types.StringPointerValue(rule.ResourceTypes[0].ResourceType)
	}
	return diags
}

func (r *cloudSecurityIomCustomRuleResource) createCloudPolicyRule(ctx context.Context, plan *cloudSecurityIomCustomRuleResourceModel) (*models.ApimodelsRule, diag.Diagnostics) {
	var diags diag.Diagnostics
	var newRule *models.ApimodelsRule
	isDuplicateRule := !plan.ParentRuleId.IsNull()

	body := &models.CommonCreateRuleRequest{
		Description:  plan.Description.ValueStringPointer(),
		Name:         plan.Name.ValueStringPointer(),
		Platform:     plan.CloudPlatform.ValueStringPointer(),
		Provider:     plan.CloudProvider.ValueStringPointer(),
		ResourceType: plan.ResourceType.ValueStringPointer(),
		Domain:       utils.Addr(IomRuleDefaultDomain),
		Subdomain:    utils.Addr(IomRuleDefaultSubdomain),
	}

	if isDuplicateRule {
		var parent cloudSecurityIomCustomRuleResourceModel
		body.ParentRuleID = plan.ParentRuleId.ValueStringPointer()

		emptyRemediationInfo := plan.RemediationInfo.IsUnknown() || plan.RemediationInfo.IsNull()
		emptyAlertInfo := plan.AlertInfo.IsUnknown() || plan.AlertInfo.IsNull()
		emptyControls := plan.Controls.IsUnknown() || plan.Controls.IsNull()

		if emptyRemediationInfo || emptyAlertInfo || emptyControls {
			rule, diags := r.getCloudPolicyRule(ctx, plan.ParentRuleId.ValueString())
			if diags.HasError() {
				return nil, diags
			}

			diags = parent.wrap(ctx, rule)
			if diags.HasError() {
				return nil, diags
			}

			if emptyAlertInfo {
				plan.AlertInfo = parent.AlertInfo
			}

			if emptyRemediationInfo {
				plan.RemediationInfo = parent.RemediationInfo
			}

			if emptyControls {
				plan.Controls = parent.Controls
			}
		}
	} else {
		body.Logic = plan.Logic.ValueStringPointer()

		if utils.IsKnown(plan.AttackTypes) {
			attackTypes := make([]string, 0, len(plan.AttackTypes.Elements()))
			diags.Append(plan.AttackTypes.ElementsAs(ctx, &attackTypes, false)...)
			if diags.HasError() {
				return nil, diags
			}
			body.AttackTypes = strings.Join(attackTypes, ",")
		}
	}

	body.AlertInfo, diags = convertAlertInfoToAPIFormat(ctx, plan.AlertInfo, isDuplicateRule)
	if diags.HasError() {
		return nil, diags
	}

	body.RemediationInfo, diags = convertRemediationInfoToAPIFormat(ctx, plan.RemediationInfo, isDuplicateRule)
	if diags.HasError() {
		return nil, diags
	}

	body.Controls, diags = flex.ExpandSetWithConverter(
		ctx,
		plan.Controls,
		func(control policyControl) (*models.DbmodelsControlReference, diag.Diagnostics) {
			return &models.DbmodelsControlReference{
				Authority: control.Authority.ValueStringPointer(),
				Code:      control.Code.ValueStringPointer(),
			}, nil
		},
	)
	if diags.HasError() {
		return nil, diags
	}

	body.Severity = severityToInt64[plan.Severity.ValueString()]

	newRule, diags = createCloudPolicyRule(r.client, cloud_policies.CreateRuleMixin0Params{
		Context: ctx,
		Body:    body,
	}, iomRuleRequiredScopes)
	if diags.HasError() {
		return nil, diags
	}

	// Duplicate rules can only set remediation_info and alert_info
	// to empty during an update, not on initial creation
	if isDuplicateRule {
		configRemdiationInfo := plan.RemediationInfo
		configAlertInfo := plan.AlertInfo
		diags = plan.wrap(ctx, newRule)
		if diags.HasError() {
			return nil, diags
		}

		if !plan.RemediationInfo.Equal(configRemdiationInfo) || !plan.AlertInfo.Equal(configAlertInfo) {
			plan.RemediationInfo = configRemdiationInfo
			plan.AlertInfo = configAlertInfo
			rule, diags := r.updateCloudPolicyRule(ctx, plan)
			if diags.HasError() {
				return nil, diags
			}
			newRule = rule
		}
	}

	return newRule, diags
}

func (r *cloudSecurityIomCustomRuleResource) getCloudPolicyRule(ctx context.Context, id string) (*models.ApimodelsRule, diag.Diagnostics) {
	return getCloudPolicyRule(r.client, cloud_policies.GetRuleParams{
		Context: ctx,
		Ids:     []string{id},
	}, iomRuleRequiredScopes)
}

func (r *cloudSecurityIomCustomRuleResource) updateCloudPolicyRule(ctx context.Context, plan *cloudSecurityIomCustomRuleResourceModel) (*models.ApimodelsRule, diag.Diagnostics) {
	var diags diag.Diagnostics
	var remediationInfo, alertInfo string
	isDuplicaterule := !plan.ParentRuleId.IsNull()

	body := &models.CommonUpdateRuleRequest{
		Description: plan.Description.ValueString(),
		Name:        plan.Name.ValueString(),
		UUID:        plan.ID.ValueStringPointer(),
		Severity:    severityToInt64[plan.Severity.ValueString()],
	}

	if isDuplicaterule {
		var parentRule cloudSecurityIomCustomRuleResourceModel
		var ruleResp *models.ApimodelsRule
		emptyRemediationInfo := plan.RemediationInfo.IsUnknown() || plan.RemediationInfo.IsNull()
		emptyAlertInfo := plan.AlertInfo.IsUnknown() || plan.AlertInfo.IsNull()
		emptyControls := plan.Controls.IsUnknown() || plan.Controls.IsNull()

		if emptyRemediationInfo || emptyAlertInfo || emptyControls {
			ruleResp, diags = r.getCloudPolicyRule(ctx, plan.ParentRuleId.ValueString())
			if diags.HasError() {
				return nil, diags
			}

			parentRule.wrap(ctx, ruleResp)
		}

		if emptyRemediationInfo {
			plan.RemediationInfo = parentRule.RemediationInfo
		}

		if emptyAlertInfo {
			plan.AlertInfo = parentRule.AlertInfo
		}

		if emptyControls {
			plan.Controls = parentRule.Controls
		}
	}

	alertInfo, diags = convertAlertInfoToAPIFormat(ctx, plan.AlertInfo, isDuplicaterule)
	if diags.HasError() {
		return nil, diags
	}

	remediationInfo, diags = convertRemediationInfoToAPIFormat(ctx, plan.RemediationInfo, isDuplicaterule)
	if diags.HasError() {
		return nil, diags
	}

	body.AlertInfo = &alertInfo

	ruleLogic := &models.ApimodelsRuleLogic{
		Platform:        plan.CloudPlatform.ValueStringPointer(),
		RemediationInfo: &remediationInfo,
	}

	if !isDuplicaterule {
		ruleLogic.Logic = plan.Logic.ValueString()
	}

	body.RuleLogicList = []*models.ApimodelsRuleLogic{ruleLogic}

	if len(plan.AttackTypes.Elements()) > 0 {
		var attackTypes []string
		diags = plan.AttackTypes.ElementsAs(ctx, &attackTypes, false)
		if diags.HasError() {
			return nil, diags
		}
		body.AttackTypes = attackTypes
	}

	body.Controls, diags = flex.ExpandSetWithConverter(
		ctx,
		plan.Controls,
		func(control policyControl) (*models.ApimodelsControlReference, diag.Diagnostics) {
			return &models.ApimodelsControlReference{
				Authority: control.Authority.ValueStringPointer(),
				Code:      control.Code.ValueStringPointer(),
			}, nil
		},
	)
	if diags.HasError() {
		return nil, diags
	}

	return updateCloudPolicyRule(r.client, cloud_policies.UpdateRuleParams{
		Context: ctx,
		Body:    body,
	}, iomRuleRequiredScopes)
}

func (r *cloudSecurityIomCustomRuleResource) deleteCloudPolicyRule(ctx context.Context, id string) diag.Diagnostics {
	return deleteCloudPolicyRule(r.client, cloud_policies.DeleteRuleMixin0Params{
		Context: ctx,
		Ids:     []string{id},
	}, iomRuleRequiredScopes)
}
