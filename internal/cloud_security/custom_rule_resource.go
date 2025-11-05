package cloudsecurity

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
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                = &cloudSecurityCustomRuleResource{}
	_ resource.ResourceWithConfigure   = &cloudSecurityCustomRuleResource{}
	_ resource.ResourceWithImportState = &cloudSecurityCustomRuleResource{}
	_ resource.ResourceWithModifyPlan  = &cloudSecurityCustomRuleResource{}
)

var (
	documentationSection        string = "Falcon Cloud Security"
	resourceMarkdownDescription string = "This resource manages custom cloud security rules. " +
		"These rules can be created either by inheriting properties from a parent rule with minimal customization, or by fully customizing all attributes for maximum flexibility. " +
		"To create a rule based on a parent rule, utilize the `crowdstrike_cloud_security_rules` data source to gather parent rule information to use in the new custom rule. " +
		"The `crowdstrike_cloud_compliance_framework_controls` data source can be used to query Falcon for compliance benchmark controls to associate with custom rules created with this resource. "
	requiredScopes []scopes.Scope = cloudSecurityRuleScopes
)

func NewCloudSecurityCustomRuleResource() resource.Resource {
	return &cloudSecurityCustomRuleResource{}
}

type cloudSecurityCustomRuleResource struct {
	client *client.CrowdStrikeAPISpecification
}

type cloudSecurityCustomRuleResourceModel struct {
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

func (r *cloudSecurityCustomRuleResource) Configure(
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

func (r *cloudSecurityCustomRuleResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_security_custom_rule"
}

func (r *cloudSecurityCustomRuleResource) Schema(
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
				Optional:            true,
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "A list of the alert logic and detection criteria for rule violations. Do not include numbering within this list. The Falcon console will automatically add numbering.When `alert_info` is not defined and `parent_rule_id` is defined, this field will inherit the parent rule's `alert_info`.",
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.LengthAtLeast(1),
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
						},
						"code": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "The compliance framework rule code",
						},
					},
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
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Specific attack types associated with the rule. If `parent_rule_id` is defined, `attack_types` will be inherited from the parent rule and cannot be specified using this field. ",
				ElementType:         types.StringType,
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(
						stringvalidator.LengthAtLeast(1),
					),
				},
			},
			"logic": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Rego logic for the rule. Either `logic` or `parent_rule_id` must be defined. When `parent_rule_id` is set, the rule inherits the Rego logic from the parent rule. Note: The API does not return Rego logic for rules created from a parent rule, so this field will not appear in state when using `parent_rule_id`.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the policy rule.",
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
					listvalidator.ValueStringsAre(
						stringvalidator.LengthAtLeast(1),
					),
				},
			},
			"resource_type": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The full resource type. Examples: `AWS::IAM::CredentialReport`, `Microsoft.Compute/virtualMachines`, `container.googleapis.com/Cluster`",
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
				Description: "Subdomain for the policy rule.",
				Default:     stringdefault.StaticString("IOM"),
			},
		},
	}
}

func (r *cloudSecurityCustomRuleResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan cloudSecurityCustomRuleResourceModel
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

func (r *cloudSecurityCustomRuleResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state cloudSecurityCustomRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rule, diags := r.getCloudPolicyRule(ctx, state.ID.ValueString())
	if diags.HasError() {
		if tferrors.HasNotFoundError(diags) {
			resp.State.RemoveResource(ctx)
			tflog.Warn(
				ctx,
				fmt.Sprintf(
					"custom rule with ID %s not found, removing from state",
					state.ID.ValueString(),
				),
			)
			return
		}
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, rule)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *cloudSecurityCustomRuleResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan cloudSecurityCustomRuleResourceModel
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

func (r *cloudSecurityCustomRuleResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state cloudSecurityCustomRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.deleteCloudPolicyRule(ctx, state.ID.ValueString())...)
}

func (r *cloudSecurityCustomRuleResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r cloudSecurityCustomRuleResource) ConfigValidators(ctx context.Context) []resource.ConfigValidator {
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

func (r *cloudSecurityCustomRuleResource) ModifyPlan(
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

	var plan, config cloudSecurityCustomRuleResourceModel
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
			var parent cloudSecurityCustomRuleResourceModel
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
		// If config value is null and plan value is not null and not an empty list, set to unknown to force update.
		if utils.IsNull(config.AlertInfo) && utils.IsKnown(plan.AlertInfo) && len(plan.AlertInfo.Elements()) != 0 {
			plan.AlertInfo = types.ListUnknown(plan.AlertInfo.ElementType(ctx))
		}

		if utils.IsNull(config.RemediationInfo) && utils.IsKnown(plan.RemediationInfo) && len(plan.RemediationInfo.Elements()) != 0 {
			plan.RemediationInfo = types.ListUnknown(plan.RemediationInfo.ElementType(ctx))
		}

		if utils.IsNull(config.Controls) && utils.IsKnown(plan.Controls) && len(plan.Controls.Elements()) != 0 {
			plan.Controls = types.SetUnknown(plan.Controls.ElementType(ctx))
		}
	}

	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
}

func (m *cloudSecurityCustomRuleResourceModel) wrap(
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

	if len(rule.RuleLogicList) > 0 {
		m.CloudPlatform = types.StringPointerValue(rule.RuleLogicList[0].Platform)
	}

	if len(rule.ResourceTypes) > 0 {
		m.ResourceType = types.StringPointerValue(rule.ResourceTypes[0].ResourceType)
	}
	return diags
}

func (r *cloudSecurityCustomRuleResource) createCloudPolicyRule(ctx context.Context, plan *cloudSecurityCustomRuleResourceModel) (*models.ApimodelsRule, diag.Diagnostics) {
	var diags diag.Diagnostics
	var newRule *models.ApimodelsRule
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
		var parent cloudSecurityCustomRuleResourceModel
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

	body.Controls = []*models.DbmodelsControlReference{}
	if len(plan.Controls.Elements()) > 0 {
		var controls []policyControl
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

	params := cloud_policies.CreateRuleMixin0Params{
		Context: ctx,
		Body:    body,
	}

	resp, err := r.client.CloudPolicies.CreateRuleMixin0(&params)
	if err != nil {
		if badRequest, ok := err.(*cloud_policies.CreateRuleMixin0BadRequest); ok {
			diags.AddError(
				"Error Creating Rule",
				fmt.Sprintf("Failed to create rule (400): %+v", *badRequest.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		if ruleConflict, ok := err.(*cloud_policies.CreateRuleMixin0Conflict); ok {
			diags.AddError(
				"Error Creating Rule",
				fmt.Sprintf("Failed to create rule (409): %+v", *ruleConflict.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		if internalServerError, ok := err.(*cloud_policies.CreateRuleMixin0InternalServerError); ok {
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
			"Failed to create rule: API returned an empty response",
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

	newRule = payload.Resources[0]

	// Duplicate rules can only set remediation_info and alert_info
	// to empty during an update, not on initial creation
	if isDuplicateRule {
		configRemdiationInfo := plan.RemediationInfo
		configAlertInfo := plan.AlertInfo
		diags = plan.wrap(ctx, payload.Resources[0])
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

func (r *cloudSecurityCustomRuleResource) getCloudPolicyRule(ctx context.Context, id string) (*models.ApimodelsRule, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := cloud_policies.GetRuleParams{
		Context: ctx,
		Ids:     []string{id},
	}

	resp, err := r.client.CloudPolicies.GetRule(&params)
	if err != nil {
		if notFound, ok := err.(*cloud_policies.GetRuleNotFound); ok {
			diags.Append(tferrors.NewNotFoundError(
				fmt.Sprintf("Failed to retrieve rule (404): %s, %+v", id, *notFound.Payload.Errors[0].Message),
			))
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
		diags.AddError(
			"Error Retrieving Rule",
			fmt.Sprintf("Failed to retrieve rule %s: API returned an empty response", id),
		)
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

func (r *cloudSecurityCustomRuleResource) updateCloudPolicyRule(ctx context.Context, plan *cloudSecurityCustomRuleResourceModel) (*models.ApimodelsRule, diag.Diagnostics) {
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
		var parentRule cloudSecurityCustomRuleResourceModel
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

	body.Controls = []*models.ApimodelsControlReference{}
	if len(plan.Controls.Elements()) > 0 {
		var controls []policyControl
		diags = plan.Controls.ElementsAs(ctx, &controls, false)
		if diags.HasError() {
			return nil, diags
		}
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
			fmt.Sprintf("Failed to update rule %s: API returned an empty response", plan.ID.ValueString()),
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

func (r *cloudSecurityCustomRuleResource) deleteCloudPolicyRule(ctx context.Context, id string) diag.Diagnostics {
	var diags diag.Diagnostics

	params := cloud_policies.DeleteRuleMixin0Params{
		Context: ctx,
		Ids:     []string{id},
	}

	_, err := r.client.CloudPolicies.DeleteRuleMixin0(&params)
	if err != nil {
		if _, ok := err.(*cloud_policies.DeleteRuleMixin0NotFound); ok {
			return diags
		}
		diags.AddError(
			"Error Deleting Rule",
			fmt.Sprintf("Failed to delete rule %s: \n\n %s", id, err.Error()),
		)
	}

	return diags
}

func convertAlertInfoToAPIFormat(ctx context.Context, alertInfo basetypes.ListValue, includeNumbering bool) (string, diag.Diagnostics) {
	var diags diag.Diagnostics
	var alertInfoStrings []string
	var convertedAlertInfo string

	if alertInfo.IsNull() || alertInfo.IsUnknown() || len(alertInfo.Elements()) == 0 {
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

	if info.IsNull() || info.IsUnknown() || len(info.Elements()) == 0 {
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
