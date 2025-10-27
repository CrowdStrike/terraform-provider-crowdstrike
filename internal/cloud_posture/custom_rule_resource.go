package cloudposture

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

var (
	_ resource.Resource                   = &cloudPostureCustomRuleResource{}
	_ resource.ResourceWithConfigure      = &cloudPostureCustomRuleResource{}
	_ resource.ResourceWithImportState    = &cloudPostureCustomRuleResource{}
	_ resource.ResourceWithModifyPlan     = &cloudPostureCustomRuleResource{}
	_ resource.ResourceWithValidateConfig = &cloudPostureCustomRuleResource{}
)

var (
	documentationSection        string = "Cloud Posture"
	resourceMarkdownDescription string = "This resource manages custom cloud posture rules. " +
		"These rules can be created either by inheriting properties from a parent rule with minimal customization, or by fully customizing all attributes for maximum flexibility. " +
		"To create a rule based on a parent rule, utilize the `crowdstrike_cloud_posture_rules` data source to gather parent rule information to use in the new custom rule. " +
		"The `crowdstrike_cloud_compliance_framework_controls` data source can be used to query Falcon for compliance benchmark controls to associate with custom rules created with this resource. "
	requiredScopes   []scopes.Scope = cloudPostureRuleScopes
	includeNumbering bool           = true
	excludeNumbering bool           = false
)

func NewCloudPostureCustomRuleResource() resource.Resource {
	return &cloudPostureCustomRuleResource{}
}

type cloudPostureCustomRuleResource struct {
	client *client.CrowdStrikeAPISpecification
}

type cloudPostureCustomRuleResourceModel struct {
	ID              types.String `tfsdk:"id"`
	AlertInfo       types.List   `tfsdk:"alert_info"`
	Controls        types.Set    `tfsdk:"controls"`
	Description     types.String `tfsdk:"description"`
	Domain          types.String `tfsdk:"domain"`
	Logic           types.String `tfsdk:"logic"`
	Name            types.String `tfsdk:"name"`
	AttackTypes     types.Set    `tfsdk:"attack_types"`
	ParentRuleId    types.String `tfsdk:"parent_rule_id"`
	CloudPlatform   types.String `tfsdk:"cloud_platform"`
	CloudProvider   types.String `tfsdk:"cloud_provider"`
	RemediationInfo types.List   `tfsdk:"remediation_info"`
	ResourceType    types.String `tfsdk:"resource_type"`
	Severity        types.String `tfsdk:"severity"`
	Subdomain       types.String `tfsdk:"subdomain"`
}

func (r *cloudPostureCustomRuleResource) Configure(
	ctx context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*client.CrowdStrikeAPISpecification)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf(
				"Expected *client.CrowdStrikeAPISpecification, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)

		return
	}

	r.client = client
}

func (r *cloudPostureCustomRuleResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_posture_custom_rule"
}

func (r *cloudPostureCustomRuleResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(documentationSection, resourceMarkdownDescription, requiredScopes),
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
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				MarkdownDescription: "A list of the alert logic and detection criteria for rule violations. " +
					"When `alert_info` is not defined and `parent_rule_id` is defined, this field will inherit the parent rule's `alert_info`. " +
					"Do not include numbering within this list. The Falcon console will automatically add numbering. " +
					"`alert_info` must contain at least one element when defined with `parent_rule_id`.",
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.LengthAtLeast(1),
					),
				},
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
			},
			"controls": schema.SetNestedAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: "Security framework and compliance rule information. " +
					"Utilize the `crowdstrike_cloud_compliance_framework_controls` data source to obtain this information. " +
					"When `controls` is not defined and `parent_rule_id` is defined, this field will inherit the parent rule's `controls`.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"authority": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "The compliance framework",
						},
						"code": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "The compliance framework rule code",
						},
					},
				},
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.UseStateForUnknown(),
				},
			},
			"description": schema.StringAttribute{
				Required:    true,
				Description: "Description of the policy rule.",
			},
			"domain": schema.StringAttribute{
				Computed:    true,
				Default:     stringdefault.StaticString("CSPM"),
				Description: "CrowdStrike domain for the custom rule. Default is CSPM",
			},
			"attack_types": schema.SetAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: "Specific attack types associated with the rule. " +
					"If `parent_rule_id` is defined, `attack_types` will be inherited from the parent rule and cannot be specified using this field. ",
				ElementType: types.StringType,
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(
						stringvalidator.LengthAtLeast(1),
					),
				},
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.UseStateForUnknown(),
				},
			},
			"logic": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Rego logic for the rule. " +
					"If this is not defined, then parent_rule_id must be defined. " +
					"When `parent_rule_id` is defined, the rego `logic` from the parent rule is not visible, but it is used for triggering this rule.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the policy rule.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"parent_rule_id": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Id of the parent rule to inherit properties from. " +
					"The `crowdstrike_cloud_posture_rules` data source can be used to query Falcon for parent rule information to use in this field. " +
					"Required if `logic` is not specified.",
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
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				MarkdownDescription: "Information about how to remediate issues detected by this rule. " +
					"Do not include numbering within this list. The Falcon console will automatically add numbering. " +
					"When `remediation_info` is not defined and `parent_rule_id` is defined, this field will inherit the parent rule's `remediation_info`. " +
					"`remediation_info` must contain at least one element when defined with `parent_rule_id`.",
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.LengthAtLeast(1),
					),
				},
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
			},
			"resource_type": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "The full resource type. Examples: " +
					"`AWS::IAM::CredentialReport`, " +
					"`Microsoft.Compute/virtualMachines`, " +
					"`container.googleapis.com/Cluster`",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"severity": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("critical"),
				MarkdownDescription: "Severity of the rule. Valid values are `critical`, `high`, `medium`, `informational`.",
				Validators: []validator.String{
					stringvalidator.OneOf("critical", "high", "medium", "informational"),
				},
			},
			"subdomain": schema.StringAttribute{
				Computed:    true,
				Description: "Subdomain for the policy rule. Valid values are 'IOM' (Indicators of Misconfiguration) or 'IAC' (Infrastructure as Code). IOM is only supported at this time.",
				Default:     stringdefault.StaticString("IOM"),
			},
		},
	}
}

func (r *cloudPostureCustomRuleResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan cloudPostureCustomRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Match Cloud Platform and Cloud Provider until IAC and KAC are implemented
	if !utils.IsKnown(plan.CloudPlatform) {
		plan.CloudPlatform = plan.CloudProvider
	}

	rule, diags := r.createCloudPolicyRule(ctx, &plan)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	// Update state before continuing because we already created the Policy, but
	// other operations may fail resulting in created, but not tracked resources.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, rule)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *cloudPostureCustomRuleResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state cloudPostureCustomRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rule, diags := r.getCloudPolicyRule(ctx, state.ID.ValueString())
	if diags.HasError() {
		for _, diag := range diags {
			if strings.Contains(diag.Detail(), "resource doesn't exist") {
				resp.State.RemoveResource(ctx)
				resp.Diagnostics.AddWarning(
					"Resource Not Found",
					fmt.Sprintf("The resource with ID %s no longer exists in Falcon and will be removed from the Terraform state.", state.ID.ValueString()),
				)
				return
			}
		}
		resp.Diagnostics.Append(diags...)
		return
	}

	if rule == nil {
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, rule)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *cloudPostureCustomRuleResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan cloudPostureCustomRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Match Cloud Platform and Cloud Provider until IAC and KAC are implemented
	if !utils.IsKnown(plan.CloudPlatform) {
		plan.CloudPlatform = plan.CloudProvider
	}

	rule, diags := r.updateCloudPolicyRule(ctx, &plan)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, rule)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *cloudPostureCustomRuleResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state cloudPostureCustomRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.deleteCloudPolicyRule(ctx, state.ID.ValueString())...)
}

func (r *cloudPostureCustomRuleResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r cloudPostureCustomRuleResource) ConfigValidators(ctx context.Context) []resource.ConfigValidator {
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

func (r *cloudPostureCustomRuleResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config cloudPostureCustomRuleResourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Validate duplicate rule attributes due to varying behavior for empty lists/sets between rule types.
	if !config.ParentRuleId.IsNull() && !config.ParentRuleId.IsUnknown() {
		if !config.AlertInfo.IsNull() && !config.AlertInfo.IsUnknown() {
			if len(config.AlertInfo.Elements()) == 0 {
				resp.Diagnostics.AddAttributeError(
					path.Root("alert_info"),
					"Invalid Configuration",
					"When parent_rule_id is set, alert_info cannot be an empty list. It must either be omitted (in which case it will be inherited from the parent rule) or contain at least one element.",
				)
			}
		}
		if !config.RemediationInfo.IsNull() && !config.RemediationInfo.IsUnknown() {
			if len(config.RemediationInfo.Elements()) == 0 {
				resp.Diagnostics.AddAttributeError(
					path.Root("remediation_info"),
					"Invalid Configuration",
					"When parent_rule_id is set, remediation_info cannot be an empty list. It must either be omitted (in which case it will be inherited from the parent rule) or contain at least one element.",
				)
			}
		}
	}
}

func (r *cloudPostureCustomRuleResource) ModifyPlan(
	ctx context.Context,
	req resource.ModifyPlanRequest,
	resp *resource.ModifyPlanResponse,
) {
	if req.Plan.Raw.IsNull() {
		return
	}

	if req.State.Raw.IsNull() {
		return
	}

	var plan, state, config cloudPostureCustomRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	isDuplicateRule := !config.ParentRuleId.IsUnknown() && !config.ParentRuleId.IsNull()

	// This is needed to assign duplicate rules and rego rules different sets of defaults.
	// Duplicate rules will default to the parent rule, therefore need to be set after apply, and rego rules will default to empty.
	if isDuplicateRule {
		if config.AlertInfo.IsNull() {
			plan.AlertInfo = types.ListUnknown(types.StringType)
		} else {
			plan.AlertInfo = config.AlertInfo
		}

		if config.RemediationInfo.IsNull() {
			plan.RemediationInfo = types.ListUnknown(types.StringType)
		} else {
			plan.RemediationInfo = config.RemediationInfo
		}

		if config.Controls.IsNull() {
			plan.Controls = types.SetUnknown(types.ObjectType{AttrTypes: policyControl{}.AttributeTypes()})
		} else {
			plan.Controls = config.Controls
		}

	} else {
		if !config.AlertInfo.IsUnknown() && !config.RemediationInfo.IsUnknown() && !config.AttackTypes.IsUnknown() && !config.Controls.IsUnknown() {
			if config.AlertInfo.IsNull() {
				plan.AlertInfo = types.ListValueMust(types.StringType, []attr.Value{})
			} else {
				plan.AlertInfo = config.AlertInfo
			}

			if config.RemediationInfo.IsNull() {
				plan.RemediationInfo = types.ListValueMust(types.StringType, []attr.Value{})
			} else {
				plan.RemediationInfo = config.RemediationInfo
			}

			if config.AttackTypes.IsNull() {
				plan.AttackTypes = types.SetValueMust(types.StringType, []attr.Value{})
			} else {
				plan.AttackTypes = config.AttackTypes
			}

			if config.Controls.IsNull() {
				plan.Controls = types.SetValueMust(types.ObjectType{AttrTypes: policyControl{}.AttributeTypes()}, []attr.Value{})
			} else {
				plan.Controls = config.Controls
			}
		}
	}

	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
}

func (m *cloudPostureCustomRuleResourceModel) wrap(
	ctx context.Context,
	rule *models.ApimodelsRule,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringPointerValue(rule.UUID)
	m.Name = types.StringPointerValue(rule.Name)
	m.Description = types.StringPointerValue(rule.Description)
	m.Domain = types.StringPointerValue(rule.Domain)
	m.Subdomain = types.StringPointerValue(rule.Subdomain)
	m.CloudProvider = types.StringPointerValue(rule.Provider)
	m.RemediationInfo = convertAlertRemediationInfoToTerraformState(rule.Remediation)
	m.AlertInfo = convertAlertRemediationInfoToTerraformState(rule.AlertInfo)

	if rule.Severity != nil {
		m.Severity = types.StringValue(int32ToSeverity[int32(*rule.Severity)])
	}

	if rule.ParentRuleShortUUID != "" {
		m.ParentRuleId = types.StringValue(rule.ParentRuleShortUUID)
	} else {
		m.Logic = types.StringValue(rule.Logic)
	}

	attackTypes := types.SetValueMust(types.StringType, []attr.Value{})
	if len(rule.AttackTypes) > 0 {
		filteredAttackTypes := make([]types.String, 0, len(rule.AttackTypes))
		for _, attackType := range rule.AttackTypes {
			if attackType != "" {
				filteredAttackTypes = append(filteredAttackTypes, types.StringValue(attackType))
			}
		}
		attackTypes, diags = types.SetValueFrom(ctx, types.StringType, filteredAttackTypes)
		if diags.HasError() {
			return diags
		}
	}
	m.AttackTypes = attackTypes

	controls := types.SetValueMust(types.ObjectType{AttrTypes: policyControl{}.AttributeTypes()}, []attr.Value{})
	if len(rule.Controls) > 0 {
		var policyControls []policyControl
		for _, control := range rule.Controls {
			policyControls = append(policyControls, policyControl{
				Authority: types.StringPointerValue(control.Authority),
				Code:      types.StringPointerValue(control.Code),
			})
		}

		controls, diags = types.SetValueFrom(
			ctx,
			types.ObjectType{AttrTypes: policyControl{}.AttributeTypes()},
			policyControls,
		)

		if diags.HasError() {
			return diags
		}
	}
	m.Controls = controls

	if rule.RuleLogicList != nil {
		m.CloudPlatform = types.StringPointerValue(rule.RuleLogicList[0].Platform)
	}

	if rule.ResourceTypes != nil {
		m.ResourceType = types.StringPointerValue(rule.ResourceTypes[0].ResourceType)
	}
	return diags
}

func (r *cloudPostureCustomRuleResource) createCloudPolicyRule(ctx context.Context, plan *cloudPostureCustomRuleResourceModel) (*models.ApimodelsRule, diag.Diagnostics) {
	var diags diag.Diagnostics
	isDuplicateRule := !plan.ParentRuleId.IsNull()

	body := &models.CommonCreateRuleRequest{
		Description:  plan.Description.ValueStringPointer(),
		Name:         plan.Name.ValueStringPointer(),
		Platform:     plan.CloudPlatform.ValueStringPointer(),
		Provider:     plan.CloudProvider.ValueStringPointer(),
		ResourceType: plan.ResourceType.ValueStringPointer(),
		Domain:       plan.Domain.ValueStringPointer(),
		Subdomain:    plan.Subdomain.ValueStringPointer(),
	}

	if isDuplicateRule {
		var parent cloudPostureCustomRuleResourceModel
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

		if !plan.AlertInfo.IsNull() {
			body.AlertInfo, diags = convertAlertInfoToAPIFormat(ctx, plan.AlertInfo, includeNumbering)
			if diags.HasError() {
				return nil, diags
			}
		}

		if !plan.RemediationInfo.IsNull() {
			body.RemediationInfo, diags = convertRemediationInfoToAPIFormat(ctx, plan.RemediationInfo, includeNumbering)
			if diags.HasError() {
				return nil, diags
			}
		}
	} else {
		body.Logic = plan.Logic.ValueStringPointer()
		if !plan.AlertInfo.IsNull() {
			body.AlertInfo, diags = convertAlertInfoToAPIFormat(ctx, plan.AlertInfo, excludeNumbering)
			if diags.HasError() {
				return nil, diags
			}
		}

		if !plan.RemediationInfo.IsNull() {
			body.RemediationInfo, diags = convertRemediationInfoToAPIFormat(ctx, plan.RemediationInfo, excludeNumbering)
			if diags.HasError() {
				return nil, diags
			}
		}

		if !plan.AttackTypes.IsUnknown() && !plan.AttackTypes.IsNull() {
			attackTypes := make([]string, 0, len(plan.AttackTypes.Elements()))
			diags.Append(plan.AttackTypes.ElementsAs(ctx, &attackTypes, false)...)
			if diags.HasError() {
				return nil, diags
			}
			body.AttackTypes = strings.Join(attackTypes, ",")
		}
	}

	if !plan.Controls.IsUnknown() && !plan.Controls.IsNull() {
		var controls []policyControl
		body.Controls = []*models.DbmodelsControlReference{}
		diags = plan.Controls.ElementsAs(ctx, &controls, false)
		if diags.HasError() {
			return nil, diags
		}
		for _, control := range controls {
			body.Controls = append(body.Controls, &models.DbmodelsControlReference{
				Authority: control.Authority.ValueStringPointer(),
				Code:      control.Code.ValueStringPointer(),
			})
		}
	}

	body.Severity = severityToInt64[plan.Severity.ValueString()]

	params := cloud_policies.CreateRuleParams{
		Context: ctx,
		Body:    body,
	}

	resp, err := r.client.CloudPolicies.CreateRule(&params)
	if err != nil {
		if badRequest, ok := err.(*cloud_policies.CreateRuleBadRequest); ok {
			diags.AddError(
				"Error Creating Rule",
				fmt.Sprintf("Failed to create rule (400): %+v", *badRequest.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		if ruleConflict, ok := err.(*cloud_policies.CreateRuleConflict); ok {
			diags.AddError(
				"Error Creating Rule",
				fmt.Sprintf("Failed to create rule (409): %+v", *ruleConflict.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		if internalServerError, ok := err.(*cloud_policies.CreateRuleInternalServerError); ok {
			diags.AddError(
				"Error Creating Rule",
				fmt.Sprintf("Failed to create rule (500): %+v", *internalServerError.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		diags.AddError(
			"Error Creating Rule",
			fmt.Sprintf("Failed to create rule %s: %+v", plan.Name.ValueString(), err),
		)

		return nil, diags
	}

	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		diags.AddError(
			"Error Creating Rule",
			"Failed to create rule: Payload is empty.",
		)
		return nil, diags
	}

	payload := resp.GetPayload()

	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Error Creating Rule. Body Error",
			fmt.Sprintf("Failed to create rule: %s", err.Error()),
		)
		return nil, diags
	}
	return payload.Resources[0], diags
}

func (r *cloudPostureCustomRuleResource) getCloudPolicyRule(ctx context.Context, id string) (*models.ApimodelsRule, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := cloud_policies.GetRuleParams{
		Context: ctx,
		Ids:     []string{id},
	}

	resp, err := r.client.CloudPolicies.GetRule(&params)
	if err != nil {
		if notFound, ok := err.(*cloud_policies.GetRuleNotFound); ok {
			diags.AddError(
				"Error Retrieving Rule",
				fmt.Sprintf("Failed to retrieve rule (404): %s, %+v", id, *notFound.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		if internalServerError, ok := err.(*cloud_policies.GetRuleInternalServerError); ok {
			diags.AddError(
				"Error Retrieving Rule",
				fmt.Sprintf("Failed to retrieve rule (500): %s, %+v", id, *internalServerError.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		diags.AddError(
			"Error Retrieving Rule",
			fmt.Sprintf("Failed to retrieve rule %s: %+v", id, err),
		)

		return nil, diags
	}

	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		return nil, diags
	}

	payload := resp.GetPayload()

	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Error Retrieving Rule",
			fmt.Sprintf("Failed to retrieve rule: %s", err.Error()),
		)
		return nil, diags
	}

	return payload.Resources[0], diags
}

func (r *cloudPostureCustomRuleResource) updateCloudPolicyRule(ctx context.Context, plan *cloudPostureCustomRuleResourceModel) (*models.ApimodelsRule, diag.Diagnostics) {
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
		var parentRule cloudPostureCustomRuleResourceModel
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
			remediationInfo, diags = convertRemediationInfoToAPIFormat(ctx, parentRule.RemediationInfo, includeNumbering)
		} else {
			remediationInfo, diags = convertRemediationInfoToAPIFormat(ctx, plan.RemediationInfo, includeNumbering)
		}

		if diags.HasError() {
			return nil, diags
		}

		body.RuleLogicList = []*models.ApimodelsRuleLogic{
			{
				Platform:        plan.CloudPlatform.ValueStringPointer(),
				RemediationInfo: remediationInfo,
			},
		}

		if emptyAlertInfo {
			alertInfo, diags = convertAlertInfoToAPIFormat(ctx, parentRule.AlertInfo, includeNumbering)
		} else {
			alertInfo, diags = convertAlertInfoToAPIFormat(ctx, plan.AlertInfo, includeNumbering)
		}

		if diags.HasError() {
			return nil, diags
		}

		body.AlertInfo = alertInfo

		if emptyControls {
			plan.Controls = parentRule.Controls
		}
	} else {
		if !plan.AlertInfo.IsNull() {
			if len(plan.AlertInfo.Elements()) > 0 {
				alertInfo, diags = convertAlertInfoToAPIFormat(ctx, plan.AlertInfo, excludeNumbering)
				if diags.HasError() {
					return nil, diags
				}
			}
			body.AlertInfo = alertInfo
		}

		if !plan.RemediationInfo.IsNull() {
			if len(plan.RemediationInfo.Elements()) > 0 {
				remediationInfo, diags = convertRemediationInfoToAPIFormat(ctx, plan.RemediationInfo, excludeNumbering)
				if diags.HasError() {
					return nil, diags
				}
			}
			body.RuleLogicList = []*models.ApimodelsRuleLogic{
				{
					Platform:        plan.CloudPlatform.ValueStringPointer(),
					Logic:           plan.Logic.ValueString(),
					RemediationInfo: remediationInfo,
				},
			}
		}
	}

	if len(plan.AttackTypes.Elements()) > 0 {
		var attackTypes []string
		diags = plan.AttackTypes.ElementsAs(ctx, &attackTypes, false)
		if diags.HasError() {
			return nil, diags
		}
		body.AttackTypes = attackTypes
	}

	body.Controls = []*models.ApimodelsControlReference{}
	if !plan.Controls.IsNull() {
		var controls []policyControl
		body.Controls = []*models.ApimodelsControlReference{}
		plan.Controls.ElementsAs(ctx, &controls, false)
		for _, control := range controls {
			body.Controls = append(body.Controls, &models.ApimodelsControlReference{
				Authority: control.Authority.ValueStringPointer(),
				Code:      control.Code.ValueStringPointer(),
			})
		}
	}

	params := cloud_policies.UpdateRuleParams{
		Context: ctx,
		Body:    body,
	}

	resp, err := r.client.CloudPolicies.UpdateRule(&params)
	if err != nil {
		if badRequest, ok := err.(*cloud_policies.UpdateRuleBadRequest); ok {
			diags.AddError(
				"Error Updating Rule",
				fmt.Sprintf("Failed to update rule (400): %+v", *badRequest.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		if ruleConflict, ok := err.(*cloud_policies.UpdateRuleConflict); ok {
			diags.AddError(
				"Error Updating Rule",
				fmt.Sprintf("Failed to update rule (409): %+v", *ruleConflict.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		if internalServerError, ok := err.(*cloud_policies.UpdateRuleInternalServerError); ok {
			diags.AddError(
				"Error Updating Rule",
				fmt.Sprintf("Failed to update rule (500): %+v", *internalServerError.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		diags.AddError(
			"Error Updating Rule",
			fmt.Sprintf("Failed to update rule: %s", err),
		)
		return nil, diags
	}

	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		diags.AddError(
			"Error Updating Rule",
			"Failed to update rule: Payload is empty.",
		)
		return nil, diags
	}

	payload := resp.GetPayload()

	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Error Updating Rule",
			fmt.Sprintf("Failed to update rule: %s", err.Error()),
		)
		return nil, diags
	}
	return payload.Resources[0], diags
}

func (r *cloudPostureCustomRuleResource) deleteCloudPolicyRule(ctx context.Context, id string) diag.Diagnostics {
	var diags diag.Diagnostics

	params := cloud_policies.DeleteRuleParams{
		Context: ctx,
		Ids:     []string{id},
	}

	_, err := r.client.CloudPolicies.DeleteRule(&params)
	if err != nil {
		if internalServerError, ok := err.(*cloud_policies.DeleteRuleInternalServerError); ok {
			diags.AddError(
				"Error Deleting Rule",
				fmt.Sprintf("Failed to delete rule (500) %s: %+v", id, *internalServerError.Payload.Errors[0].Message),
			)
			return diags
		}
	}

	return diags
}

func convertAlertInfoToAPIFormat(ctx context.Context, alertInfo basetypes.ListValue, includeNumbering bool) (string, diag.Diagnostics) {
	var diags diag.Diagnostics
	var alertInfoStrings []string
	var convertedAlertInfo string

	if alertInfo.IsNull() || alertInfo.IsUnknown() {
		return "", diags
	}

	// Duplicate rules require the numbering with |\n delimiters
	// for Alert Info while custom rules only require | without
	// newlines or numbering
	if includeNumbering {
		for i, elem := range alertInfo.Elements() {
			str, ok := elem.(types.String)
			if !ok {
				diags.AddError(
					"Error converting AlertInfo",
					fmt.Sprintf("Failed to convert element %d to string", i),
				)
				return "", diags
			}
			alertInfoStrings = append(alertInfoStrings, fmt.Sprintf("%d. %s", i+1, str.ValueString()))
		}

		convertedAlertInfo = strings.Join(alertInfoStrings, "|\n")
	} else {
		diags = alertInfo.ElementsAs(ctx, &alertInfoStrings, false)
		convertedAlertInfo = strings.Join(alertInfoStrings, "|")
	}
	return convertedAlertInfo, diags
}

func convertRemediationInfoToAPIFormat(ctx context.Context, info basetypes.ListValue, includeNumbering bool) (string, diag.Diagnostics) {
	var diags diag.Diagnostics
	var infoStrings []string
	var convertedInfo string

	if info.IsNull() || info.IsUnknown() {
		return "", diags
	}

	// Duplicate rules require the numbering with |\n delimiters
	// for Remediation info while custom rules only require | without
	// newlines or numbering
	if includeNumbering {
		for i, elem := range info.Elements() {
			str, ok := elem.(types.String)
			if !ok {
				diags.AddError(
					"Error converting RemediationInfo",
					fmt.Sprintf("Failed to convert element %d to string", i),
				)
				return "", diags
			}
			infoStrings = append(infoStrings, fmt.Sprintf("Step %d. %s", i+1, str.ValueString()))
		}
		convertedInfo = strings.Join(infoStrings, "|\n")
	} else {
		diags = info.ElementsAs(ctx, &infoStrings, false)
		convertedInfo = strings.Join(infoStrings, "|")
	}

	return convertedInfo, diags
}
