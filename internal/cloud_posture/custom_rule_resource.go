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
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

var (
	_ resource.Resource                = &cloudPostureCustomRuleResource{}
	_ resource.ResourceWithConfigure   = &cloudPostureCustomRuleResource{}
	_ resource.ResourceWithImportState = &cloudPostureCustomRuleResource{}
)

var (
	documentationSection        string = "Cloud Posture"
	resourceMarkdownDescription string = "This resource manages custom cloud posture rules. " +
		"These rules can be created either by inheriting properties from a parent rule with minimal customization, or by fully customizing all attributes for maximum flexibility. " +
		"To create a rule based on a parent rule, utilize the `crowdstrike_cloud_posture_rules` data source to gather parent rule information to use in the new custom rule. " +
		"The `crowdstrike_cloud_compliance_framework_controls` data source can be used to query Falcon for compliance benchmark controls to associate with custom rules created with this resource. "
	requiredScopes []scopes.Scope = cloudPostureRuleScopes
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
					"Do not include numbering within this list. The Falcon console will automatically add numbering.",
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.LengthAtLeast(1),
					),
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
							Required:    true,
							Description: "The compliance framework",
						},
						"code": schema.StringAttribute{
							Required:    true,
							Description: "The compliance framework rule code",
						},
					},
				},
				Default: setdefault.StaticValue(types.SetNull(types.ObjectType{
					AttrTypes: map[string]attr.Type{
						"authority": types.StringType,
						"code":      types.StringType,
					},
				})),
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
					"Note: If `parent_rule_id` is defined, attack types will be inherited from the parent rule and cannot be specified using this field.",
				ElementType: types.StringType,
			},
			"logic": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Rego logic for the rule. " +
					"If this is not defined, then parent_rule_id must be defined. " +
					"When `parent_rule_id` is defined, `logic` from the parent rule is not visible, but it is used for triggering this rule.",
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
				Description: "Information about how to remediate issues detected by this rule. " +
					"Do not include numbering within this list. The Falcon console will automatically add numbering.",
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.LengthAtLeast(1),
					),
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

	// Match Cloud Platform and Cloud Provider until IAC is implemented
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
	if diags.HasError() {
		return diags
	}

	if rule.Severity != nil {
		m.Severity = types.StringValue(int32ToSeverity[int32(*rule.Severity)])
	}

	if !m.ParentRuleId.IsNull() {
		m.ParentRuleId = types.StringValue(rule.ParentRuleShortUUID)
	} else {
		m.Logic = types.StringValue(rule.Logic)
	}

	m.AttackTypes = types.SetValueMust(types.StringType, []attr.Value{})
	for _, attackType := range rule.AttackTypes {
		m.AttackTypes, diags = types.SetValue(types.StringType, append(m.AttackTypes.Elements(), types.StringValue(attackType)))
		if diags.HasError() {
			return diags
		}
	}

	var policyControls []policyControl
	for _, control := range rule.Controls {
		policyControls = append(policyControls, policyControl{
			Authority: types.StringPointerValue(control.Authority),
			Code:      types.StringPointerValue(control.Code),
		})
	}

	m.Controls, diags = types.SetValueFrom(
		ctx,
		types.ObjectType{AttrTypes: policyControl{}.AttributeTypes()},
		policyControls,
	)

	if diags.HasError() {
		return diags
	}

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

	body := &models.CommonCreateRuleRequest{
		Description:  plan.Description.ValueStringPointer(),
		Name:         plan.Name.ValueStringPointer(),
		Platform:     plan.CloudPlatform.ValueStringPointer(),
		Provider:     plan.CloudProvider.ValueStringPointer(),
		ResourceType: plan.ResourceType.ValueStringPointer(),
		Domain:       plan.Domain.ValueStringPointer(),
		Subdomain:    plan.Subdomain.ValueStringPointer(),
	}

	if plan.ParentRuleId.IsNull() {

		body.Logic = plan.Logic.ValueStringPointer()
		body.AlertInfo, diags = convertAlertInfoToAPIFormat(ctx, plan.AlertInfo, false)
		if diags.HasError() {
			return nil, diags
		}

		body.RemediationInfo, diags = convertRemediationInfoToAPIFormat(ctx, plan.RemediationInfo, false)
		if diags.HasError() {
			return nil, diags
		}

	} else {
		body.ParentRuleID = plan.ParentRuleId.ValueStringPointer()
		body.AlertInfo, diags = convertAlertInfoToAPIFormat(ctx, plan.AlertInfo, true)
		if diags.HasError() {
			return nil, diags
		}

		body.RemediationInfo, diags = convertRemediationInfoToAPIFormat(ctx, plan.RemediationInfo, true)
		if diags.HasError() {
			return nil, diags
		}
	}

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

	severity := severityToInt32[plan.Severity.ValueString()]
	body.Severity = &severity

	attackTypes := make([]string, 0, len(plan.AttackTypes.Elements()))
	for _, elem := range plan.AttackTypes.Elements() {
		if str, ok := elem.(types.String); ok {
			attackTypes = append(attackTypes, str.ValueString())
		}
	}

	body.AttackTypes = utils.Addr(strings.Join(attackTypes, ","))

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

	body := &models.CommonUpdateRuleRequest{
		Description: plan.Description.ValueString(),
		Name:        plan.Name.ValueString(),
		UUID:        plan.ID.ValueStringPointer(),
	}

	severity := severityToInt64[plan.Severity.ValueString()]
	body.Severity = severity

	attackTypes := make([]string, 0, len(plan.AttackTypes.Elements()))
	for _, elem := range plan.AttackTypes.Elements() {
		if str, ok := elem.(types.String); ok {
			attackTypes = append(attackTypes, str.ValueString())
		}
	}
	body.AttackTypes = attackTypes

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

	body.RuleLogicList = []*models.ApimodelsRuleLogic{
		{
			Platform: plan.CloudPlatform.ValueStringPointer(),
		},
	}

	var remediationInfo, alertInfo *string
	if plan.ParentRuleId.IsNull() {
		alertInfo, diags = convertAlertInfoToAPIFormat(ctx, plan.AlertInfo, false)
		if diags.HasError() {
			return nil, diags
		}

		remediationInfo, diags = convertRemediationInfoToAPIFormat(ctx, plan.RemediationInfo, false)
		if diags.HasError() {
			return nil, diags
		}

		body.RuleLogicList[0].Logic = plan.Logic.ValueString()
	} else {
		alertInfo, diags = convertAlertInfoToAPIFormat(ctx, plan.AlertInfo, true)
		if diags.HasError() {
			return nil, diags
		}

		remediationInfo, diags = convertRemediationInfoToAPIFormat(ctx, plan.RemediationInfo, true)
		if diags.HasError() {
			return nil, diags
		}
	}

	if remediationInfo != nil {
		body.RuleLogicList[0].RemediationInfo = remediationInfo
	}

	if alertInfo != nil {
		body.AlertInfo = *alertInfo
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

	resp, err := r.client.CloudPolicies.DeleteRule(&params)
	if err != nil {
		if internalServerError, ok := err.(*cloud_policies.DeleteRuleInternalServerError); ok {
			diags.AddError(
				"Error Deleting Rule",
				fmt.Sprintf("Failed to delete rule (500) %s: %+v", id, *internalServerError.Payload.Errors[0].Message),
			)
			return diags
		}

		diags.AddError(
			"Error Deleting Rule",
			fmt.Sprintf("Failed to delete rule: %s", err),
		)
		return diags
	}

	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		diags.AddError(
			"Error Deleting Rule",
			"Failed to delete rule: The API returned an empty payload. The rule may have already been deleted and will be removed from the Terraform state during the next run.",
		)
		return diags
	}

	payload := resp.GetPayload()

	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Error Deleting Rule",
			fmt.Sprintf("Failed to delete rule: %s", err.Error()),
		)
		return diags
	}

	return diags
}

func convertAlertInfoToAPIFormat(ctx context.Context, alertInfo basetypes.ListValue, includeNumbering bool) (*string, diag.Diagnostics) {
	var diags diag.Diagnostics
	var alertInfoStrings []string
	var convertedAlertInfo string

	if alertInfo.IsNull() || alertInfo.IsUnknown() {
		return nil, diags
	}

	// Duplicate rules require the numbering with |\n delimiters
	// for Alert Info while custom rules only require | without
	// newlines
	if includeNumbering {
		for i, elem := range alertInfo.Elements() {
			str, ok := elem.(types.String)
			if !ok {
				diags.AddError(
					"Error converting AlertInfo",
					fmt.Sprintf("Failed to convert element %d to string", i),
				)
				return nil, diags
			}
			alertInfoStrings = append(alertInfoStrings, fmt.Sprintf("%d. %s", i+1, str.ValueString()))
		}

		convertedAlertInfo = strings.Join(alertInfoStrings, "|\n")
	} else {
		diags = alertInfo.ElementsAs(ctx, &alertInfoStrings, false)
		convertedAlertInfo = strings.Join(alertInfoStrings, "|")
	}
	return &convertedAlertInfo, diags
}

func convertRemediationInfoToAPIFormat(ctx context.Context, info basetypes.ListValue, includeNumbering bool) (*string, diag.Diagnostics) {
	var diags diag.Diagnostics
	var infoStrings []string
	var convertedInfo string

	if info.IsNull() || info.IsUnknown() {
		return nil, diags
	}

	// Duplicate rules require the numbering with |\n delimiters
	// for Remediation info while custom rules only require | without
	// newlines
	if includeNumbering {
		for i, elem := range info.Elements() {
			str, ok := elem.(types.String)
			if !ok {
				diags.AddError(
					"Error converting RemediationInfo",
					fmt.Sprintf("Failed to convert element %d to string", i),
				)
				return nil, diags
			}
			infoStrings = append(infoStrings, fmt.Sprintf("Step %d. %s", i+1, str.ValueString()))
		}
		convertedInfo = strings.Join(infoStrings, "|\n")
	} else {
		diags = info.ElementsAs(ctx, &infoStrings, false)
		convertedInfo = strings.Join(infoStrings, "|")
	}

	return &convertedInfo, diags
}
