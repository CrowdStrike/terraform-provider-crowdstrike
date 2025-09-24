package cloud_posture

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
	"github.com/hashicorp/terraform-plugin-framework-validators/int32validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int32default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
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
	_ resource.ResourceWithValidateConfig = &cloudPostureCustomRuleResource{}
)

var (
	documentationSection        string         = "Cloud Posture"
	resourceMarkdownDescription string         = "This resource manages custom cloud posture rules. These rules can be created either by inheriting properties from a parent rule with minimal customization, or by fully customizing all attributes for maximum flexibility."
	requiredScopes              []scopes.Scope = cloudPostureRuleScopes
)

func NewCloudPostureCustomRuleResource() resource.Resource {
	return &cloudPostureCustomRuleResource{}
}

type cloudPostureCustomRuleResource struct {
	client *client.CrowdStrikeAPISpecification
}

type cloudPostureCustomRuleResourceModel struct {
	UUID            types.String `tfsdk:"uuid"`
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
	Severity        types.Int32  `tfsdk:"severity"`
	Subdomain       types.String `tfsdk:"subdomain"`
}

type policyControl struct {
	Authority types.String `tfsdk:"authority"`
	Code      types.String `tfsdk:"code"`
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
			"uuid": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier of the policy rule.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
						"must be a valid UUID in the format of 7c86a274-c04b-4292-9f03-dafae42bde97",
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
				Description: "A list of the alert logic and detection criteria for rule violations. Parent value will be used when parent_rule_id is defined.",
			},
			"controls": schema.SetNestedAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Security framework and compliance rule information.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"authority": schema.StringAttribute{
							Required:    true,
							Description: "This compliance framework",
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
				Optional:    true,
				Computed:    true,
				Description: "Specific attack types associated with the rule. Note: If 'parent_rule_id' is specified, these attack types will be inherited from the parent rule, and any values provided here will be ignored.",
				ElementType: types.StringType,
			},
			"logic": schema.StringAttribute{
				Optional:    true,
				Description: "Rego logic for the rule. If this is not defined, then parent_rule_id must be defined.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the policy rule.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"parent_rule_id": schema.StringAttribute{
				Optional:    true,
				Description: "UUID of the parent rule to inherit properties from. Required if logic is not specified.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
						"must be a valid UUID in the format of 7c86a274-c04b-4292-9f03-dafae42bde97",
					),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"cloud_platform": schema.StringAttribute{
				Required:    true,
				Description: "Cloud platform for the policy rule.",
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
				Description: "Information about how to remediate issues detected by this rule.",
			},
			"resource_type": schema.StringAttribute{
				Required:    true,
				Description: "The full resource type. Format examples: AWS: AWS::IAM::CredentialReport, Azure: Microsoft.Compute/virtualMachines, GCP: container.googleapis.com/Cluster.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"severity": schema.Int32Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int32default.StaticInt32(0),
				Description: "Severity of the rule. Valid values are 0 (critical), 1 (high), 2 (medium), 3 (informational).",
				Validators: []validator.Int32{
					int32validator.OneOf(0, 1, 2, 3),
				},
			},
			"subdomain": schema.StringAttribute{
				Required:    true,
				Description: "Subdomain for the policy rule. Valid values are 'IOM' (Indicators of Misconfiguration) or 'IaC' (Infrastructure as Code). IOM is only supported at this time.",
				Validators: []validator.String{
					stringvalidator.OneOf(
						"IOM",
						"IAC",
					),
				},
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

	rule, diags := r.createCloudPolicyRule(ctx, &plan)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	plan.AlertInfo = convertAlertRemediationInfoToTerraformState(rule.AlertInfo)

	plan.UUID = types.StringPointerValue(rule.UUID)
	plan.Name = types.StringPointerValue(rule.Name)
	plan.Description = types.StringPointerValue(rule.Description)
	plan.Domain = types.StringPointerValue(rule.Domain)
	plan.Subdomain = types.StringPointerValue(rule.Subdomain)
	plan.CloudPlatform = types.StringPointerValue(rule.RuleLogicList[0].Platform)
	plan.CloudProvider = types.StringPointerValue(rule.Provider)
	plan.ResourceType = types.StringPointerValue(rule.ResourceTypes[0].ResourceType)

	plan.RemediationInfo = convertAlertRemediationInfoToTerraformState(rule.Remediation)

	if rule.Severity != nil {
		plan.Severity = types.Int32Value(int32(*rule.Severity))
	}

	if !plan.ParentRuleId.IsNull() {
		plan.ParentRuleId = types.StringValue(rule.ParentRuleShortUUID)
	} else {
		plan.Logic = types.StringValue(rule.Logic)
	}

	plan.AttackTypes = types.SetValueMust(types.StringType, []attr.Value{})
	for _, attackType := range rule.AttackTypes {
		plan.AttackTypes, diags = types.SetValue(types.StringType, append(plan.AttackTypes.Elements(), types.StringValue(attackType)))
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
	}

	if len(rule.Controls) > 0 {
		plan.Controls, diags = convertControlsToTerraformState(rule.Controls)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
	}

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

	rule, diags := r.getCloudPolicyRule(ctx, state.UUID.ValueString())
	if diags.HasError() {
		for _, diag := range diags {
			if strings.Contains(diag.Detail(), "resource doesn't exist") {
				resp.State.RemoveResource(ctx)
				return
			}
		}
		resp.Diagnostics.Append(diags...)
		return
	}

	if rule == nil {
		return
	}

	state.AlertInfo = convertAlertRemediationInfoToTerraformState(rule.AlertInfo)

	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	state.UUID = types.StringPointerValue(rule.UUID)
	state.Name = types.StringPointerValue(rule.Name)
	state.Description = types.StringPointerValue(rule.Description)
	state.Domain = types.StringPointerValue(rule.Domain)
	state.Subdomain = types.StringPointerValue(rule.Subdomain)
	state.CloudPlatform = types.StringPointerValue(rule.RuleLogicList[0].Platform)
	state.CloudProvider = types.StringPointerValue(rule.Provider)
	state.ResourceType = types.StringPointerValue(rule.ResourceTypes[0].ResourceType)

	state.RemediationInfo = convertAlertRemediationInfoToTerraformState(rule.Remediation)

	if rule.Severity != nil {
		state.Severity = types.Int32Value(int32(*rule.Severity))
	}

	if !state.ParentRuleId.IsNull() {
		state.ParentRuleId = types.StringValue(rule.ParentRuleShortUUID)
	} else {
		state.Logic = types.StringValue(rule.Logic)
	}

	state.AttackTypes = types.SetValueMust(types.StringType, []attr.Value{})
	for _, attackType := range rule.AttackTypes {
		state.AttackTypes, diags = types.SetValue(types.StringType, append(state.AttackTypes.Elements(), types.StringValue(attackType)))
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
	}

	if len(rule.Controls) > 0 {
		state.Controls, diags = convertControlsToTerraformState(rule.Controls)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
	}

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

	rule, diags := r.updateCloudPolicyRule(ctx, &plan)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	plan.UUID = types.StringPointerValue(rule.UUID)
	plan.Name = types.StringPointerValue(rule.Name)
	plan.Description = types.StringPointerValue(rule.Description)
	plan.CloudPlatform = types.StringPointerValue(rule.RuleLogicList[0].Platform)
	plan.CloudProvider = types.StringPointerValue(rule.Provider)
	plan.AlertInfo = convertAlertRemediationInfoToTerraformState(rule.AlertInfo)
	plan.RemediationInfo = convertAlertRemediationInfoToTerraformState(rule.Remediation)

	if rule.Severity != nil {
		plan.Severity = types.Int32Value(int32(*rule.Severity))
	}

	plan.AttackTypes = types.SetValueMust(types.StringType, []attr.Value{})
	for _, attackType := range rule.AttackTypes {
		plan.AttackTypes, _ = types.SetValue(types.StringType, append(plan.AttackTypes.Elements(), types.StringValue(attackType)))
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
	}

	if !plan.ParentRuleId.IsNull() {
		plan.ParentRuleId = types.StringValue(rule.ParentRuleShortUUID)
	} else {
		plan.Logic = types.StringValue(rule.Logic)
	}

	if len(rule.Controls) > 0 {
		plan.Controls, diags = convertControlsToTerraformState(rule.Controls)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
	}

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

	diags := r.deleteCloudPolicyRule(ctx, state.UUID.ValueString())
	if diags.HasError() {
		for _, diag := range diags {
			if strings.Contains(diag.Detail(), "rule was not found") {
				resp.State.RemoveResource(ctx)
				resp.Diagnostics.AddWarning(
					"Resource Not Found",
					fmt.Sprintf("Rule %s was not found and is being removed from the state", state.UUID.ValueString()),
				)
				return
			}
		}

		resp.Diagnostics.Append(diags...)
		return
	}
}

func (r *cloudPostureCustomRuleResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("uuid"), req, resp)
}

func (r *cloudPostureCustomRuleResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config cloudPostureCustomRuleResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if config.Logic.IsNull() && config.ParentRuleId.IsNull() {
		resp.Diagnostics.AddError(
			"Invalid Configuration",
			"Either 'logic' or 'parent_rule_id' must be defined",
		)
	} else if !config.Logic.IsNull() && !config.ParentRuleId.IsNull() {
		resp.Diagnostics.AddError(
			"Invalid Configuration",
			"Only one of 'logic' or 'parent_rule_id' can be defined",
		)
	}

	if !config.ParentRuleId.IsNull() && !config.AttackTypes.IsNull() {
		resp.Diagnostics.AddError(
			"Invalid Configuration",
			"When 'parent_rule_id' is defined, 'attack_types' should not be specified as they will be inherited from the parent rule",
		)
	}

	if !config.AlertInfo.IsNull() {
		var alertInfoElements []basetypes.StringValue
		diags := config.AlertInfo.ElementsAs(ctx, &alertInfoElements, false)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}

		for _, element := range alertInfoElements {
			if element.ValueString() == "" {
				resp.Diagnostics.AddError(
					"Invalid Configuration",
					"AlertInfo cannot contain empty strings",
				)
				return
			}
		}
	}

	if !config.RemediationInfo.IsNull() {
		var RemediationInfoElements []basetypes.StringValue
		diags := config.RemediationInfo.ElementsAs(ctx, &RemediationInfoElements, false)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}

		for _, element := range RemediationInfoElements {
			if element.ValueString() == "" {
				resp.Diagnostics.AddError(
					"Invalid Configuration",
					"RemediationInfo cannot contain empty strings",
				)
				return
			}
		}
	}
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
		Severity:     plan.Severity.ValueInt32Pointer(),
	}

	if plan.ParentRuleId.IsNull() {
		var controls []policyControl
		body.Controls = []*models.DbmodelsControlReference{}
		diags := plan.Controls.ElementsAs(ctx, &controls, false)
		if diags.HasError() {
			return nil, diags
		}
		for _, control := range controls {
			body.Controls = append(body.Controls, &models.DbmodelsControlReference{
				Authority: control.Authority.ValueStringPointer(),
				Code:      control.Code.ValueStringPointer(),
			})
		}

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
		if notFound, ok := err.(*cloud_policies.CreateRuleBadRequest); ok {
			diags.AddError(
				"Error Creating Rule",
				fmt.Sprintf("Failed to create rule (400): %+v", *notFound.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		if notFound, ok := err.(*cloud_policies.CreateRuleConflict); ok {
			diags.AddError(
				"Error Creating Rule",
				fmt.Sprintf("Failed to create rule (409): %+v", *notFound.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		if notFound, ok := err.(*cloud_policies.CreateRuleInternalServerError); ok {
			diags.AddError(
				"Error Creating Rule",
				fmt.Sprintf("Failed to create rule (500): %+v", *notFound.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		diags.AddError(
			"Error Creating Rule",
			fmt.Sprintf("Failed to create rule %s: %+v", plan.Name.ValueString(), err),
		)

		return nil, diags
	}

	payload := resp.GetPayload()

	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Failed to create rule. Body Error",
			fmt.Sprintf("Failed to create rule: %s", err.Error()),
		)
		return nil, diags
	}

	return payload.Resources[0], diags
}

func (r *cloudPostureCustomRuleResource) getCloudPolicyRule(ctx context.Context, uuid string) (*models.ApimodelsRule, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := cloud_policies.GetRuleParams{
		Context: ctx,
		Ids:     []string{uuid},
	}

	resp, err := r.client.CloudPolicies.GetRule(&params)
	if err != nil {
		if notFound, ok := err.(*cloud_policies.GetRuleNotFound); ok {
			diags.AddError(
				"Error Retrieving Rule",
				fmt.Sprintf("Failed to retrieve rule (404): %s, %+v", uuid, *notFound.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		if notFound, ok := err.(*cloud_policies.GetRuleInternalServerError); ok {
			diags.AddError(
				"Error Retrieving Rule",
				fmt.Sprintf("Failed to retrieve rule (500): %s, %+v", uuid, *notFound.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		diags.AddError(
			"Error Retrieving Rule",
			fmt.Sprintf("Failed to retrieve rule %s: %+v", uuid, err),
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

func (r *cloudPostureCustomRuleResource) updateCloudPolicyRule(ctx context.Context, plan *cloudPostureCustomRuleResourceModel) (*models.ApimodelsRule, diag.Diagnostics) {
	var diags diag.Diagnostics

	body := &models.CommonUpdateRuleRequest{
		Description: plan.Description.ValueString(),
		Name:        plan.Name.ValueString(),
		Severity:    int64(plan.Severity.ValueInt32()),
		UUID:        plan.UUID.ValueStringPointer(),
	}

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

	if !plan.Severity.IsNull() {
		body.Severity = int64(plan.Severity.ValueInt32())
	}

	params := cloud_policies.UpdateRuleParams{
		Context: ctx,
		Body:    body,
	}

	resp, err := r.client.CloudPolicies.UpdateRule(&params)
	if err != nil {
		if notFound, ok := err.(*cloud_policies.UpdateRuleBadRequest); ok {
			diags.AddError(
				"Error Updating Rule",
				fmt.Sprintf("Failed to update rule (400): %+v", *notFound.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		if notFound, ok := err.(*cloud_policies.UpdateRuleConflict); ok {
			diags.AddError(
				"Error Updating Rule",
				fmt.Sprintf("Failed to update rule (409): %+v", *notFound.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		if notFound, ok := err.(*cloud_policies.UpdateRuleInternalServerError); ok {
			diags.AddError(
				"Error Updating Rule",
				fmt.Sprintf("Failed to update rule (500): %+v", *notFound.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		diags.AddError(
			"Error Updating Rule",
			fmt.Sprintf("Failed to update rule: %s", err),
		)
		return nil, diags
	}

	payload := resp.GetPayload()

	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Failed to update rule",
			fmt.Sprintf("Failed to update rule: %s", err.Error()),
		)
		return nil, diags
	}

	return payload.Resources[0], diags
}

func (r *cloudPostureCustomRuleResource) deleteCloudPolicyRule(ctx context.Context, uuid string) diag.Diagnostics {
	var diags diag.Diagnostics

	params := cloud_policies.DeleteRuleParams{
		Context: ctx,
		Ids:     []string{uuid},
	}

	resp, err := r.client.CloudPolicies.DeleteRule(&params)
	if err != nil {
		if notFound, ok := err.(*cloud_policies.DeleteRuleNotFound); ok {
			diags.AddError(
				"Error Deleting Rule",
				fmt.Sprintf("Failed to delete rule (404) %s: %+v", uuid, *notFound.Payload.Errors[0].Message),
			)
			return diags
		}

		if notFound, ok := err.(*cloud_policies.DeleteRuleInternalServerError); ok {
			diags.AddError(
				"Error Deleting Rule",
				fmt.Sprintf("Failed to delete rule (500) %s: %+v", uuid, *notFound.Payload.Errors[0].Message),
			)
			return diags
		}

		diags.AddError(
			"Error Deleting Rule",
			fmt.Sprintf("Failed to delete rule: %s", err),
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

func convertControlsToTerraformState(ruleControls []*models.ApimodelsControl) (basetypes.SetValue, diag.Diagnostics) {
	var diags diag.Diagnostics
	controls := make([]attr.Value, len(ruleControls))
	for i, control := range ruleControls {
		controlObj, err := types.ObjectValue(
			map[string]attr.Type{
				"authority": types.StringType,
				"code":      types.StringType,
			},
			map[string]attr.Value{
				"authority": types.StringPointerValue(control.Authority),
				"code":      types.StringPointerValue(control.Code),
			},
		)
		if err != nil {
			diags.AddError(
				"Failed to convert terraform state",
				"Failed to convert terraform state",
			)
			return basetypes.SetValue{}, diags
		}
		controls[i] = controlObj
	}

	convertedControls, diags := types.SetValue(
		types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"authority": types.StringType,
				"code":      types.StringType,
			},
		},
		controls,
	)
	if diags.HasError() {
		return basetypes.SetValue{}, diags
	}

	return convertedControls, nil
}
