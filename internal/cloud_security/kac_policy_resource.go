package cloudsecurity

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/admission_control_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                   = &cloudSecurityKacPolicyResource{}
	_ resource.ResourceWithConfigure      = &cloudSecurityKacPolicyResource{}
	_ resource.ResourceWithImportState    = &cloudSecurityKacPolicyResource{}
	_ resource.ResourceWithValidateConfig = &cloudSecurityKacPolicyResource{}
	_ resource.ResourceWithModifyPlan     = &cloudSecurityKacPolicyResource{}
)

var (
	kacPolicyDocumentationSection        = "Falcon Cloud Security"
	kacPolicyResourceMarkdownDescription = "This resource manages an Admission Control policy, which provides instructions to the Falcon Kubernetes Admission Controller (KAC) about what actions to take on objects at runtime."
	kacPolicyRequiredScopes              = cloudSecurityKacPolicyScopes
)

// Mutex for create and delete operations.
var (
	kacPolicyCreateMutex sync.Mutex
	kacPolicyDeleteMutex sync.Mutex
)

func NewCloudSecurityKacPolicyResource() resource.Resource {
	return &cloudSecurityKacPolicyResource{}
}

type cloudSecurityKacPolicyResource struct {
	client *client.CrowdStrikeAPISpecification
}

type cloudSecurityKacPolicyResourceModel struct {
	ID               types.String `tfsdk:"id"`
	Name             types.String `tfsdk:"name"`
	Description      types.String `tfsdk:"description"`
	Enabled          types.Bool   `tfsdk:"enabled"`
	HostGroups       types.Set    `tfsdk:"host_groups"`
	RuleGroups       types.List   `tfsdk:"rule_groups"`
	DefaultRuleGroup types.Object `tfsdk:"default_rule_group"`
	LastUpdated      types.String `tfsdk:"last_updated"`
}

type ruleGroupTFModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	Description     types.String `tfsdk:"description"`
	DenyOnError     types.Bool   `tfsdk:"deny_on_error"`
	ImageAssessment types.Object `tfsdk:"image_assessment"`
	Namespaces      types.Set    `tfsdk:"namespaces"`
	Labels          types.Set    `tfsdk:"labels"`
	DefaultRules    types.Object `tfsdk:"default_rules"`
	CustomRules     types.Set    `tfsdk:"custom_rules"`
}

type imageAssessmentTFModel struct {
	Enabled            types.Bool   `tfsdk:"enabled"`
	UnassessedHandling types.String `tfsdk:"unassessed_handling"`
}

type labelTFModel struct {
	Key      types.String `tfsdk:"key"`
	Value    types.String `tfsdk:"value"`
	Operator types.String `tfsdk:"operator"`
}

type customRuleTFModel struct {
	ID     types.String `tfsdk:"id"`
	Action types.String `tfsdk:"action"`
}

func (m *cloudSecurityKacPolicyResourceModel) wrap(
	ctx context.Context,
	policy *models.ModelsKACPolicy,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringPointerValue(policy.ID)
	m.Name = types.StringPointerValue(policy.Name)
	m.Description = flex.StringPointerToFramework(policy.Description)
	m.Enabled = types.BoolValue(*policy.IsEnabled)

	if policy.HostGroups != nil {
		hostGroupIDs, setValueDiags := types.SetValueFrom(ctx, types.StringType, policy.HostGroups)
		diags.Append(setValueDiags...)
		if diags.HasError() {
			return diags
		}
		m.HostGroups = hostGroupIDs
	} else if !m.HostGroups.IsNull() {
		m.HostGroups = types.SetValueMust(types.StringType, []attr.Value{})
	}

	// size of rule groups excludes the default rule group
	ruleGroups := make([]ruleGroupTFModel, 0, len(policy.RuleGroups)-1)
	for _, rg := range policy.RuleGroups {
		tfRuleGroup := ruleGroupTFModel{}
		diags.Append(tfRuleGroup.wrapRuleGroup(ctx, rg)...)

		// The default rule group is handled differently
		if rg.IsDefault != nil && *rg.IsDefault {
			defaultRuleGroup, objectDiags := types.ObjectValueFrom(ctx, ruleGroupAttrMap, tfRuleGroup)
			diags.Append(objectDiags...)

			m.DefaultRuleGroup = defaultRuleGroup
			continue
		}

		ruleGroups = append(ruleGroups, tfRuleGroup)
	}

	if len(ruleGroups) > 0 {
		ruleGroupsList, listValueDiags := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: ruleGroupAttrMap}, ruleGroups)
		diags.Append(listValueDiags...)
		if diags.HasError() {
			return diags
		}

		m.RuleGroups = ruleGroupsList
	} else if !m.RuleGroups.IsNull() {
		m.RuleGroups = types.ListValueMust(types.ObjectType{AttrTypes: ruleGroupAttrMap}, []attr.Value{})
	}

	return diags
}

func (r *cloudSecurityKacPolicyResource) Configure(
	_ context.Context,
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

func (r *cloudSecurityKacPolicyResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_security_kac_policy"
}

func (r *cloudSecurityKacPolicyResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(kacPolicyDocumentationSection, kacPolicyResourceMarkdownDescription, kacPolicyRequiredScopes),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for the Cloud Security KAC Policy.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the Kubernetes Admission Control policy.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description of the Kubernetes Admission Control policy.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Whether the policy is enabled.",
			},
			"host_groups": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Host Group ids to attach to the KAC policy.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(
						fwvalidators.StringNotWhitespace(),
					),
				},
			},
			"rule_groups": schema.ListNestedAttribute{
				Optional:    true,
				Description: "A list of KAC policy rule groups in order of highest to lowest priority. Reordering the list will change rule group precedence. When reordering the list of rule groups to update precedence, the rule group names must match the state, otherwise the provider will consider it a new rule group, or an in place update.",
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
					fwvalidators.ListObjectUniqueString("name"),
				},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "Identifier for the KAC policy rule group.",
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseStateForUnknown(),
							},
						},
						"name": schema.StringAttribute{
							Required:    true,
							Description: "Name of the KAC policy rule group.",
							Validators: []validator.String{
								fwvalidators.StringNotWhitespace(),
							},
						},
						"description": schema.StringAttribute{
							Optional:    true,
							Description: "Description of the KAC policy rule group.",
							Validators: []validator.String{
								fwvalidators.StringNotWhitespace(),
							},
						},
						"deny_on_error": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Default:     booldefault.StaticBool(false),
							Description: "Defines how KAC will handle an unrecognized error or timeout when processing an admission request. If set to \"false\", the pod or workload will be allowed to run.",
						},
						"image_assessment": schema.SingleNestedAttribute{
							Optional:    true,
							Computed:    true,
							Description: "When enabled, KAC applies image assessment policies to pods or workloads that are being created or updated on the Kubernetes cluster.",
							Default: objectdefault.StaticValue(
								types.ObjectValueMust(
									imageAssessmentAttrMap,
									map[string]attr.Value{
										"enabled":             types.BoolValue(false),
										"unassessed_handling": types.StringValue("Allow Without Alert"),
									},
								),
							),
							Attributes: map[string]schema.Attribute{
								"enabled": schema.BoolAttribute{
									Required:    true,
									Description: "Enable Image Assessment in KAC.",
								},
								"unassessed_handling": schema.StringAttribute{
									Required:            true,
									MarkdownDescription: "The action Falcon KAC should take when image is unassessed (i.e. unknown). Must be one of: [\"Alert\", \"Prevent\", \"Allow Without Alert\"].",
									Validators: []validator.String{
										stringvalidator.OneOf("Alert", "Prevent", "Allow Without Alert"),
									},
								},
							},
						},
						"namespaces": schema.SetAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Namespace selectors. Namespace must only include lowercased alphanumeric characters, dashes, and asterisk (for wildcard).",
							ElementType: types.StringType,
							Default: setdefault.StaticValue(
								types.SetValueMust(types.StringType, []attr.Value{types.StringValue("*")}),
							),
							Validators: []validator.Set{
								setvalidator.ValueStringsAre(
									stringvalidator.LengthAtMost(63),
									stringvalidator.RegexMatches(
										regexp.MustCompile(`^[a-z0-9*-]+$`),
										"namespace cannot be empty and must only include lowercased alphanumeric characters, dashes, and asterisk (for wildcard)",
									),
								),
							},
						},
						"labels": schema.SetNestedAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Pod or Service label selectors.",
							Default: setdefault.StaticValue(
								types.SetValueMust(
									types.ObjectType{AttrTypes: labelsAttrMap},
									[]attr.Value{
										types.ObjectValueMust(
											labelsAttrMap,
											map[string]attr.Value{
												"key":      types.StringValue("*"),
												"value":    types.StringValue("*"),
												"operator": types.StringValue("eq"),
											},
										),
									},
								),
							),
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"key": schema.StringAttribute{
										Required:            true,
										MarkdownDescription: "Label key. Key must only include alphanumeric characters and `.-_*/`, and cannot be longer than 253 characters.",
										Validators: []validator.String{
											stringvalidator.LengthAtMost(253),
											stringvalidator.RegexMatches(
												regexp.MustCompile(`^[a-zA-Z0-9._/*-]+$`),
												"label key cannot be empty, and must only include alphanumeric characters and [ . - _ * / ]",
											),
										},
									},
									"value": schema.StringAttribute{
										Required:            true,
										MarkdownDescription: "Label value. Label must only include alphanumeric characters and `.-_*`, and cannot be longer than 63 characters.",
										Validators: []validator.String{
											stringvalidator.LengthAtMost(63),
											stringvalidator.RegexMatches(
												regexp.MustCompile(`^[a-zA-Z0-9._*-]+$`),
												"label value cannot be empty, and must only include alphanumeric characters and [ . - _ * ]",
											),
										},
									},
									"operator": schema.StringAttribute{
										Required:    true,
										Description: "Label operator. Must be one of \"eq\" (equals) or \"neq\" (not equals)",
										Validators: []validator.String{
											stringvalidator.OneOf("eq", "neq"),
										},
									},
								},
							},
						},
						"default_rules": defaultRulesSchema,
						"custom_rules":  customRulesSchema,
					},
				},
			},
			"default_rule_group": schema.SingleNestedAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The default rule group always has the lowest precedence. Only deny_on_error, image_assessment, and default_rules are configurable for the default rule group.",
				Default: objectdefault.StaticValue(
					types.ObjectValueMust(
						ruleGroupAttrMap,
						map[string]attr.Value{
							"id":            types.StringUnknown(),
							"name":          types.StringUnknown(),
							"description":   types.StringUnknown(),
							"deny_on_error": types.BoolValue(false),
							"image_assessment": types.ObjectValueMust(
								imageAssessmentAttrMap,
								map[string]attr.Value{
									"enabled":             types.BoolValue(false),
									"unassessed_handling": types.StringValue("Allow Without Alert"),
								},
							),
							"namespaces":    types.SetUnknown(types.StringType),
							"labels":        types.SetUnknown(types.ObjectType{AttrTypes: labelsAttrMap}),
							"custom_rules":  types.SetNull(types.ObjectType{AttrTypes: customRulesAttrMap}),
							"default_rules": defaultRulesDefaultValue,
						},
					),
				),

				Attributes: map[string]schema.Attribute{
					"id": schema.StringAttribute{
						Computed:    true,
						Description: "Identifier for the default KAC policy rule group.",
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.UseStateForUnknown(),
						},
					},
					"name": schema.StringAttribute{
						Computed:    true,
						Description: "Name of the default KAC policy rule group.",
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.UseStateForUnknown(),
						},
					},
					"description": schema.StringAttribute{
						Computed:    true,
						Description: "Description of the default KAC policy rule group.",
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.UseStateForUnknown(),
						},
					},
					"deny_on_error": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Defines how KAC will handle an unrecognized error or timeout when processing an admission request. If set to \"false\", the pod or workload will be allowed to run.",
					},
					"image_assessment": schema.SingleNestedAttribute{
						Optional:    true,
						Computed:    true,
						Description: "When enabled, KAC applies image assessment policies to pods or workloads that are being created or updated on the Kubernetes cluster.",
						Default: objectdefault.StaticValue(
							types.ObjectValueMust(
								imageAssessmentAttrMap,
								map[string]attr.Value{
									"enabled":             types.BoolValue(false),
									"unassessed_handling": types.StringValue("Allow Without Alert"),
								},
							),
						),
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Required:    true,
								Description: "Enable Image Assessment in KAC.",
							},
							"unassessed_handling": schema.StringAttribute{
								Required:            true,
								MarkdownDescription: "The action KAC should take when image is unassessed (i.e. unknown). Must be one of: [\"Alert\", \"Prevent\", \"Allow Without Alert\"].",
								Validators: []validator.String{
									stringvalidator.OneOf("Alert", "Prevent", "Allow Without Alert"),
								},
							},
						},
					},
					"namespaces": schema.SetAttribute{
						Computed:    true,
						Description: "The default rule group namespace is `\"*\"`, which applies to all namespaces, and is not configurable.",
						ElementType: types.StringType,
						PlanModifiers: []planmodifier.Set{
							setplanmodifier.UseStateForUnknown(),
						},
					},
					"labels": schema.SetNestedAttribute{
						Computed:    true,
						Description: "The default rule group applies to all labels, and is not configurable.",
						PlanModifiers: []planmodifier.Set{
							setplanmodifier.UseStateForUnknown(),
						},
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"key": schema.StringAttribute{
									Computed:    true,
									Description: "The default rule group label key is `\"*\"`.",
								},
								"value": schema.StringAttribute{
									Computed:    true,
									Description: "The default rule group label value is `\"*\"`.",
								},
								"operator": schema.StringAttribute{
									Computed:    true,
									Description: "The default rule group label operator is `\"eq\" (equals)`.",
								},
							},
						},
					},
					"default_rules": defaultRulesSchema,
					"custom_rules":  customRulesSchema,
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the last Terraform update of the resource.",
			},
		},
	}
}

func (r *cloudSecurityKacPolicyResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	// Concurrent create operations are not thread safe. Force serialization with mutex.
	tflog.Debug(ctx, "[DEBUG] locking create operations for KAC policies")
	kacPolicyCreateMutex.Lock()
	tflog.Debug(ctx, "[DEBUG] locked create operations for KAC policies")
	defer func() {
		tflog.Debug(ctx, "[DEBUG] unlocking create operations for KAC policies")
		kacPolicyCreateMutex.Unlock()
		tflog.Debug(ctx, "[DEBUG] unlocked create operations for KAC policies")
	}()

	var plan cloudSecurityKacPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createRequest := &models.ModelsCreatePolicyRequest{
		Name:        plan.Name.ValueStringPointer(),
		Description: plan.Description.ValueString(),
	}

	params := admission_control_policies.NewAdmissionControlCreatePolicyParamsWithContext(ctx).
		WithBody(createRequest)
	createResponse, err := r.client.AdmissionControlPolicies.AdmissionControlCreatePolicy(params)
	if err != nil {
		var forbiddenError *admission_control_policies.AdmissionControlCreatePolicyForbidden
		if errors.As(err, &forbiddenError) {
			resp.Diagnostics.Append(tferrors.NewForbiddenError(tferrors.Create, cloudSecurityKacPolicyScopes))
			return
		}

		resp.Diagnostics.Append(tferrors.NewOperationError(tferrors.Create, err))
		return
	}

	if createResponse == nil || createResponse.Payload == nil || len(createResponse.Payload.Resources) == 0 {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	policy := createResponse.Payload.Resources[0]
	plan.ID = types.StringValue(*policy.ID)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Enabled.ValueBool() {
		updateRequest := &models.ModelsUpdatePolicyRequest{
			IsEnabled: plan.Enabled.ValueBoolPointer(),
		}

		updateParams := admission_control_policies.NewAdmissionControlUpdatePolicyParamsWithContext(ctx).
			WithBody(updateRequest).
			WithIds(plan.ID.ValueString())

		updateResponse, updateErr := r.client.AdmissionControlPolicies.AdmissionControlUpdatePolicy(updateParams)
		if updateErr != nil {
			resp.Diagnostics.Append(tferrors.NewOperationError(tferrors.Create, updateErr))
			return
		}

		if updateResponse == nil || updateResponse.Payload == nil || len(updateResponse.Payload.Resources) == 0 {
			resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
			return
		}

		policy = updateResponse.Payload.Resources[0]
	}

	updatedPolicy, hostGroupDiags := r.updateHostGroups(ctx, plan.ID.ValueString(), plan.HostGroups, basetypes.SetValue{})
	resp.Diagnostics.Append(hostGroupDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if updatedPolicy != nil {
		policy = updatedPolicy
	}

	policyWithRuleGroups, updateRuleGroupDiags := r.reconcileRuleGroupUpdates(ctx, plan, policy)
	resp.Diagnostics.Append(updateRuleGroupDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if policyWithRuleGroups != nil {
		policy = policyWithRuleGroups
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *cloudSecurityKacPolicyResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state cloudSecurityKacPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := admission_control_policies.NewAdmissionControlGetPoliciesParamsWithContext(ctx).
		WithIds([]string{state.ID.ValueString()})

	getResponse, err := r.client.AdmissionControlPolicies.AdmissionControlGetPolicies(params)
	if err != nil {
		var notFoundError *admission_control_policies.AdmissionControlGetPoliciesNotFound
		if errors.As(err, &notFoundError) {
			resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
			resp.State.RemoveResource(ctx)
			return
		}

		var forbiddenError *admission_control_policies.AdmissionControlGetPoliciesForbidden
		if errors.As(err, &forbiddenError) {
			resp.Diagnostics.Append(tferrors.NewForbiddenError(tferrors.Read, cloudSecurityKacPolicyScopes))
			return
		}

		resp.Diagnostics.Append(tferrors.NewOperationError(tferrors.Read, err))
		return
	}

	if getResponse == nil || getResponse.Payload == nil || len(getResponse.Payload.Resources) == 0 {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return
	}

	policy := getResponse.Payload.Resources[0]
	resp.Diagnostics.Append(state.wrap(ctx, policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *cloudSecurityKacPolicyResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var policy *models.ModelsKACPolicy
	var plan cloudSecurityKacPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state cloudSecurityKacPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !plan.Name.Equal(state.Name) || !plan.Description.Equal(state.Description) || !plan.Enabled.Equal(state.Enabled) {
		updateRequest := &models.ModelsUpdatePolicyRequest{}
		updateRequest.Name = plan.Name.ValueString()
		updateRequest.Description = plan.Description.ValueString()
		updateRequest.IsEnabled = plan.Enabled.ValueBoolPointer()

		params := admission_control_policies.NewAdmissionControlUpdatePolicyParamsWithContext(ctx).
			WithBody(updateRequest).
			WithIds(plan.ID.ValueString())

		updateResponse, err := r.client.AdmissionControlPolicies.AdmissionControlUpdatePolicy(params)
		if err != nil {
			var forbiddenError *admission_control_policies.AdmissionControlUpdatePolicyForbidden
			if errors.As(err, &forbiddenError) {
				resp.Diagnostics.Append(tferrors.NewForbiddenError(tferrors.Update, cloudSecurityKacPolicyScopes))
				return
			}

			resp.Diagnostics.Append(tferrors.NewOperationError(tferrors.Update, err))
			return
		}

		if updateResponse == nil || updateResponse.Payload == nil || len(updateResponse.Payload.Resources) == 0 {
			resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Update))
			return
		}

		policy = updateResponse.Payload.Resources[0]
	}

	updatedPolicy, hostGroupDiags := r.updateHostGroups(ctx, plan.ID.ValueString(), plan.HostGroups, state.HostGroups)
	resp.Diagnostics.Append(hostGroupDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if updatedPolicy != nil {
		policy = updatedPolicy
	}

	policyWithDeletedRuleGroups, deleteRuleGroupDiags := r.deleteRemovedRuleGroups(ctx, plan.ID.ValueString(), plan, state)
	resp.Diagnostics.Append(deleteRuleGroupDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if policyWithDeletedRuleGroups != nil {
		policy = policyWithDeletedRuleGroups
	}

	policyWithUpdatedRuleGroups, updateRuleGroupDiags := r.reconcileRuleGroupUpdates(ctx, plan, policy)
	resp.Diagnostics.Append(updateRuleGroupDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if policyWithUpdatedRuleGroups != nil {
		policy = policyWithUpdatedRuleGroups
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *cloudSecurityKacPolicyResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	// Concurrent delete operations are not thread safe. Force serialization with mutex.
	tflog.Debug(ctx, "[DEBUG] locking delete operations for KAC policies")
	kacPolicyDeleteMutex.Lock()
	tflog.Debug(ctx, "[DEBUG] locked delete operations for KAC policies")
	defer func() {
		tflog.Debug(ctx, "[DEBUG] unlocking delete operations for KAC policies")
		kacPolicyDeleteMutex.Unlock()
		tflog.Debug(ctx, "[DEBUG] unlocked delete operations for KAC policies")
	}()

	var state cloudSecurityKacPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Disable policy if it's enabled before deletion
	if state.Enabled.ValueBool() {
		disableBool := false
		updateRequest := &models.ModelsUpdatePolicyRequest{
			IsEnabled: &disableBool,
		}

		updateParams := admission_control_policies.NewAdmissionControlUpdatePolicyParamsWithContext(ctx).
			WithBody(updateRequest).
			WithIds(state.ID.ValueString())

		_, updateErr := r.client.AdmissionControlPolicies.AdmissionControlUpdatePolicy(updateParams)
		if updateErr != nil {
			resp.Diagnostics.Append(tferrors.NewOperationError(tferrors.Delete, updateErr))
			return
		}
	}

	params := admission_control_policies.NewAdmissionControlDeletePoliciesParamsWithContext(ctx).
		WithIds([]string{state.ID.ValueString()})

	_, err := r.client.AdmissionControlPolicies.AdmissionControlDeletePolicies(params)
	if err != nil {
		var forbiddenError *admission_control_policies.AdmissionControlDeletePoliciesForbidden
		if errors.As(err, &forbiddenError) {
			resp.Diagnostics.Append(tferrors.NewForbiddenError(tferrors.Delete, cloudSecurityKacPolicyScopes))
			return
		}

		resp.Diagnostics.Append(tferrors.NewOperationError(tferrors.Delete, err))
		return
	}
}

func (r *cloudSecurityKacPolicyResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *cloudSecurityKacPolicyResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var kacPolicyConfig cloudSecurityKacPolicyResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &kacPolicyConfig)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.validateCustomRulesPropagation(ctx, kacPolicyConfig)...)
}

func (r *cloudSecurityKacPolicyResource) ModifyPlan(
	ctx context.Context,
	req resource.ModifyPlanRequest,
	resp *resource.ModifyPlanResponse,
) {
	if req.Plan.Raw.IsNull() || req.Plan.Raw.Equal(req.State.Raw) {
		return
	}

	var plan, state cloudSecurityKacPolicyResourceModel
	var diags diag.Diagnostics
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	plan, diags = r.propagateCustomRules(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !req.State.Raw.IsNull() {
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}

		// Computed+Optional object attributes (default_rule_group) cause constant plan diffs
		// This causes computed values that need to be set on update (LastUpdated) to be marked
		// as Unknown, resulting in constant plan diffs.
		// When there are no plan changes and LastUpdated is Unknown revert it to prior state value.
		if plan.LastUpdated.IsUnknown() {
			planLastUpdated := plan.LastUpdated
			plan.LastUpdated = state.LastUpdated

			resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
			if resp.Diagnostics.HasError() {
				return
			}

			// Revert if LastUpdated is not the only change
			if !resp.Plan.Raw.Equal(req.State.Raw) {
				plan.LastUpdated = planLastUpdated
				resp.Diagnostics.Append(resp.Plan.Set(ctx, plan)...)
			}
		}

		plan, diags = r.matchRuleGroupIDsByName(ctx, plan, state)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	resp.Diagnostics.Append(resp.Plan.Set(ctx, plan)...)
}

func (r *cloudSecurityKacPolicyResource) matchRuleGroupIDsByName(
	ctx context.Context,
	plan cloudSecurityKacPolicyResourceModel,
	state cloudSecurityKacPolicyResourceModel,
) (cloudSecurityKacPolicyResourceModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	modifiedPlan := plan

	if plan.RuleGroups.IsNull() || plan.RuleGroups.IsUnknown() ||
		state.RuleGroups.IsNull() || state.RuleGroups.IsUnknown() {
		return modifiedPlan, diags
	}

	stateRuleGroups := flex.ExpandListAs[ruleGroupTFModel](ctx, state.RuleGroups, &diags)
	if diags.HasError() {
		return modifiedPlan, diags
	}

	stateRGNameToRG := make(map[string]ruleGroupTFModel)
	stateRGIndexToRG := make(map[int]ruleGroupTFModel)
	matchedIDs := make(map[string]bool)

	for i, stateRG := range stateRuleGroups {
		stateRGName := stateRG.Name.ValueString()

		stateRGNameToRG[stateRGName] = stateRG
		stateRGIndexToRG[i] = stateRG
	}

	// Convert plan rule groups and match IDs by name first
	planRuleGroups := flex.ExpandListAs[ruleGroupTFModel](ctx, plan.RuleGroups, &diags)
	if diags.HasError() {
		return modifiedPlan, diags
	}

	var modifiedRuleGroups []ruleGroupTFModel
	for _, planRG := range planRuleGroups {
		modifiedRG := planRG
		planRGName := planRG.Name.ValueString()

		if stateRG, exists := stateRGNameToRG[planRGName]; exists {
			// Preserve the ID from state for this named rule group
			modifiedRG.ID = stateRG.ID
			matchedIDs[stateRG.ID.ValueString()] = true
		} else {
			// Clear ID for matching by index on second pass
			modifiedRG.ID = types.StringUnknown()
		}

		modifiedRuleGroups = append(modifiedRuleGroups, modifiedRG)
	}

	// Second pass: for unmatched rule groups, try to preserve IDs by index position
	// if the same index exists in state and that ID hasn't been matched yet
	for i, modifiedRG := range modifiedRuleGroups {
		// Skip if already matched by name
		if matchedIDs[modifiedRG.ID.ValueString()] {
			continue
		}

		// Check if there's a rule group at the same index in state
		if stateRG, exists := stateRGIndexToRG[i]; exists {
			stateRGID := stateRG.ID.ValueString()

			// If this state ID hasn't been matched yet, preserve it
			if !matchedIDs[stateRGID] {
				modifiedRuleGroups[i].ID = types.StringValue(stateRGID)
				matchedIDs[stateRGID] = true
			}
		}
	}

	modifiedRuleGroupsList, listDiags := types.ListValueFrom(ctx, plan.RuleGroups.ElementType(ctx), modifiedRuleGroups)
	diags.Append(listDiags...)
	if diags.HasError() {
		return modifiedPlan, diags
	}

	modifiedPlan.RuleGroups = modifiedRuleGroupsList
	return modifiedPlan, diags
}

func (r *cloudSecurityKacPolicyResource) updateHostGroups(
	ctx context.Context,
	policyID string,
	planHostGroups types.Set,
	stateHostGroups types.Set,
) (*models.ModelsKACPolicy, diag.Diagnostics) {
	var updatedPolicy *models.ModelsKACPolicy

	hostGroupsToAdd, hostGroupsToRemove, diags := utils.SetIDsToModify(ctx, planHostGroups, stateHostGroups)

	if len(hostGroupsToRemove) > 0 {
		removeParams := admission_control_policies.NewAdmissionControlRemoveHostGroupsParamsWithContext(ctx).
			WithPolicyID(policyID).
			WithHostGroupIds(hostGroupsToRemove)

		removeResponse, err := r.client.AdmissionControlPolicies.AdmissionControlRemoveHostGroups(removeParams)
		if err != nil {
			var forbiddenError *admission_control_policies.AdmissionControlRemoveHostGroupsForbidden
			if errors.As(err, &forbiddenError) {
				diags.Append(tferrors.NewForbiddenError(tferrors.Update, cloudSecurityKacPolicyScopes))
				return nil, diags
			}

			diags.Append(tferrors.NewOperationError(tferrors.Update, err))
			return nil, diags
		}

		if removeResponse == nil || removeResponse.Payload == nil || len(removeResponse.Payload.Resources) == 0 {
			diags.Append(tferrors.NewEmptyResponseError(tferrors.Update))
			return nil, diags
		}

		updatedPolicy = removeResponse.Payload.Resources[0]
	}

	if len(hostGroupsToAdd) > 0 {
		addHostGroupRequest := &models.ModelsAddHostGroupRequest{
			ID:         &policyID,
			HostGroups: hostGroupsToAdd,
		}

		addParams := admission_control_policies.NewAdmissionControlAddHostGroupsParamsWithContext(ctx).
			WithBody(addHostGroupRequest)

		addResponse, err := r.client.AdmissionControlPolicies.AdmissionControlAddHostGroups(addParams)
		if err != nil {
			var forbiddenError *admission_control_policies.AdmissionControlAddHostGroupsForbidden
			if errors.As(err, &forbiddenError) {
				diags.Append(tferrors.NewForbiddenError(tferrors.Update, cloudSecurityKacPolicyScopes))
				return nil, diags
			}

			diags.Append(tferrors.NewOperationError(tferrors.Update, err))
			return nil, diags
		}

		if addResponse == nil || addResponse.Payload == nil || len(addResponse.Payload.Resources) == 0 {
			diags.Append(tferrors.NewEmptyResponseError(tferrors.Update))
			return nil, diags
		}

		updatedPolicy = addResponse.Payload.Resources[0]
	}

	return updatedPolicy, diags
}

func (r *cloudSecurityKacPolicyResource) deleteRemovedRuleGroups(
	ctx context.Context,
	policyID string,
	plan, state cloudSecurityKacPolicyResourceModel,
) (*models.ModelsKACPolicy, diag.Diagnostics) {
	var diags diag.Diagnostics

	stateRuleGroupIds, stateIdsDiags := state.getRuleGroupIds(ctx)
	diags.Append(stateIdsDiags...)
	if diags.HasError() {
		return nil, diags
	}

	planRuleGroupIds, planIdsDiags := plan.getRuleGroupIds(ctx)
	diags.Append(planIdsDiags...)
	if diags.HasError() {
		return nil, diags
	}

	ruleGroupsToDelete := findRuleGroupsToDelete(stateRuleGroupIds, planRuleGroupIds)

	if len(ruleGroupsToDelete) == 0 {
		return nil, diags
	}

	deleteParams := admission_control_policies.NewAdmissionControlDeleteRuleGroupsParamsWithContext(ctx).
		WithPolicyID(policyID).
		WithRuleGroupIds(ruleGroupsToDelete)

	deleteResponse, err := r.client.AdmissionControlPolicies.AdmissionControlDeleteRuleGroups(deleteParams)
	if err != nil {
		var forbiddenError *admission_control_policies.AdmissionControlDeleteRuleGroupsForbidden
		if errors.As(err, &forbiddenError) {
			diags.Append(tferrors.NewForbiddenError(tferrors.Update, cloudSecurityKacPolicyScopes))
			return nil, diags
		}

		diags.Append(tferrors.NewOperationError(tferrors.Update, err))
		return nil, diags
	}

	if deleteResponse == nil || deleteResponse.Payload == nil || len(deleteResponse.Payload.Resources) == 0 {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return nil, diags
	}

	return deleteResponse.Payload.Resources[0], diags
}

// reconcileRuleGroupUpdates takes the plan and compares it to the current state of the API policy response
// and reconciles the differences by creating new rule groups, updating attributes and rules, and replacing selectors.
func (r *cloudSecurityKacPolicyResource) reconcileRuleGroupUpdates(
	ctx context.Context,
	plan cloudSecurityKacPolicyResourceModel,
	apiKacPolicy *models.ModelsKACPolicy,
) (*models.ModelsKACPolicy, diag.Diagnostics) {
	var diags diag.Diagnostics

	if apiKacPolicy == nil {
		params := admission_control_policies.NewAdmissionControlGetPoliciesParamsWithContext(ctx).
			WithIds([]string{plan.ID.ValueString()})
		getResponse, err := r.client.AdmissionControlPolicies.AdmissionControlGetPolicies(params)
		if err != nil {
			var forbiddenError *admission_control_policies.AdmissionControlGetPoliciesForbidden
			if errors.As(err, &forbiddenError) {
				diags.Append(tferrors.NewForbiddenError(tferrors.Update, cloudSecurityKacPolicyScopes))
				return nil, diags
			}

			diags.Append(tferrors.NewOperationError(tferrors.Update, err))
			return nil, diags
		}

		if getResponse == nil || getResponse.Payload == nil || len(getResponse.Payload.Resources) == 0 {
			diags.Append(tferrors.NewEmptyResponseError(tferrors.Update))
			return nil, diags
		}

		apiKacPolicy = getResponse.Payload.Resources[0]
	}

	// The default rule group should always be last in the list of rule groups
	apiDefaultRuleGroup := apiKacPolicy.RuleGroups[len(apiKacPolicy.RuleGroups)-1]
	if !*apiDefaultRuleGroup.IsDefault {
		diags.AddError(
			"Error updating rule groups",
			"API returned default rule group in incorrect position.",
		)
		return nil, diags
	}

	var defaultRuleGroup ruleGroupTFModel
	if plan.DefaultRuleGroup.IsNull() || plan.DefaultRuleGroup.IsUnknown() {
		diags.Append(defaultRuleGroup.wrapRuleGroup(ctx, apiDefaultRuleGroup)...)
		if diags.HasError() {
			return nil, diags
		}
	} else {
		diags.Append(plan.DefaultRuleGroup.As(ctx, &defaultRuleGroup, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return nil, diags
		}

		if defaultRuleGroup.ID.IsUnknown() {
			defaultRuleGroup.ID = types.StringValue(*apiDefaultRuleGroup.ID)
			defaultRuleGroup.Name = types.StringValue(*apiDefaultRuleGroup.Name)
		}
	}

	planTFRuleGroups := flex.ExpandListAs[ruleGroupTFModel](ctx, plan.RuleGroups, &diags)
	if diags.HasError() {
		return nil, diags
	}

	planTFRuleGroups = append(planTFRuleGroups, defaultRuleGroup)

	updatedApiKacPolicy := r.createNewRuleGroups(ctx, &diags, plan.ID.ValueString(), planTFRuleGroups)
	if updatedApiKacPolicy != nil {
		apiKacPolicy = updatedApiKacPolicy
	}

	nameToIdMap := make(map[string]string)
	idToApiRuleGroupPointerMap := make(map[string]*models.ModelsKACPolicyRuleGroup)
	for _, apiRG := range apiKacPolicy.RuleGroups {
		nameToIdMap[*apiRG.Name] = *apiRG.ID
		idToApiRuleGroupPointerMap[*apiRG.ID] = apiRG
	}

	// Merge IDs into plan rule groups that do not have IDs
	for i, planRG := range planTFRuleGroups {
		if planRG.ID.IsNull() || planRG.ID.IsUnknown() {
			planTFRuleGroups[i].ID = types.StringValue(nameToIdMap[planRG.Name.ValueString()])
		}
	}

	updatedApiKacPolicy = r.updateRuleGroupPrecedence(ctx, &diags, plan.ID.ValueString(), planTFRuleGroups)
	if updatedApiKacPolicy != nil {
		apiKacPolicy = updatedApiKacPolicy
	}

	var planApiRuleGroups []models.ModelsKACPolicyRuleGroup
	for _, tfRG := range planTFRuleGroups {
		apiRG, convertDiags := tfRG.toApiModel(ctx)
		diags.Append(convertDiags...)
		if diags.HasError() {
			return nil, diags
		}
		planApiRuleGroups = append(planApiRuleGroups, apiRG)
	}

	var updateParams []*models.ModelsUpdateRuleGroup
	var replaceSelectorParams []*models.ModelsReplaceRuleGroupSelectors
	for _, planRG := range planApiRuleGroups {
		stateRG := idToApiRuleGroupPointerMap[*planRG.ID]
		rgUpdates := buildRuleGroupUpdates(&planRG, stateRG)

		if rgUpdates.updateRuleGroupParams != nil {
			updateParams = append(updateParams, rgUpdates.updateRuleGroupParams)
		}

		if rgUpdates.replaceRuleGroupSelectorParams != nil {
			replaceSelectorParams = append(replaceSelectorParams, rgUpdates.replaceRuleGroupSelectorParams)
		}
	}

	updatedApiKacPolicy = r.updateRuleGroupAttributesAndRules(ctx, &diags, plan.ID.ValueString(), updateParams)
	if updatedApiKacPolicy != nil {
		apiKacPolicy = updatedApiKacPolicy
	}

	updatedApiKacPolicy = r.replaceRuleGroupSelectors(ctx, &diags, plan.ID.ValueString(), replaceSelectorParams)
	if updatedApiKacPolicy != nil {
		apiKacPolicy = updatedApiKacPolicy
	}

	updatedApiKacPolicy, customRulesDiags := r.reconcileCustomRules(ctx, plan.ID.ValueString(), planTFRuleGroups, apiKacPolicy)
	diags.Append(customRulesDiags...)
	if diags.HasError() {
		return nil, diags
	}
	if updatedApiKacPolicy != nil {
		apiKacPolicy = updatedApiKacPolicy
	}

	return apiKacPolicy, diags
}

func (r *cloudSecurityKacPolicyResource) createNewRuleGroups(
	ctx context.Context,
	diags *diag.Diagnostics,
	policyID string,
	ruleGroups []ruleGroupTFModel,
) *models.ModelsKACPolicy {
	var newRuleGroups []*models.ModelsCreateRuleGroup
	for _, tfRG := range ruleGroups {
		// The default rule group is always created when creating a new KAC policy
		// Do not create a new rule group if ID already exists
		if tfRG.Name.ValueString() == defaultRuleGroupName || (!tfRG.ID.IsNull() && !tfRG.ID.IsUnknown()) {
			continue
		}

		apiRuleGroup := &models.ModelsCreateRuleGroup{
			Name:        tfRG.Name.ValueStringPointer(),
			Description: tfRG.Description.ValueStringPointer(),
		}
		newRuleGroups = append(newRuleGroups, apiRuleGroup)
	}

	if len(newRuleGroups) == 0 {
		return nil
	}

	createRequest := &models.ModelsCreatePolicyRuleGroupRequest{
		ID:         &policyID,
		RuleGroups: newRuleGroups,
	}

	params := admission_control_policies.NewAdmissionControlCreateRuleGroupsParamsWithContext(ctx).
		WithBody(createRequest)

	createResponse, err := r.client.AdmissionControlPolicies.AdmissionControlCreateRuleGroups(params)
	if err != nil {
		var forbiddenError *admission_control_policies.AdmissionControlCreateRuleGroupsForbidden
		if errors.As(err, &forbiddenError) {
			diags.Append(tferrors.NewForbiddenError(tferrors.Update, cloudSecurityKacPolicyScopes))
			return nil
		}

		diags.Append(tferrors.NewOperationError(tferrors.Update, err))
		return nil
	}

	if createResponse == nil || createResponse.Payload == nil || len(createResponse.Payload.Resources) == 0 {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return nil
	}

	return createResponse.Payload.Resources[0]
}

func (r *cloudSecurityKacPolicyResource) updateRuleGroupPrecedence(
	ctx context.Context,
	diags *diag.Diagnostics,
	policyID string,
	ruleGroups []ruleGroupTFModel,
) *models.ModelsKACPolicy {
	ruleGroupPrecedence := make([]*models.ModelsChangeRuleGroupPrecedence, 0, len(ruleGroups))
	for _, tfRG := range ruleGroups {
		ruleGroupPrecedence = append(ruleGroupPrecedence, &models.ModelsChangeRuleGroupPrecedence{ID: tfRG.ID.ValueStringPointer()})
	}

	// If there are 2 or less rule groups (1 custom and/or 1 default), updating precedence is unnecessary.
	if len(ruleGroupPrecedence) <= 2 {
		return nil
	}

	changePrecedenceRequest := &models.ModelsChangePolicyRuleGroupPrecedenceRequest{
		ID:         &policyID,
		RuleGroups: ruleGroupPrecedence,
	}

	params := admission_control_policies.NewAdmissionControlSetRuleGroupPrecedenceParamsWithContext(ctx).
		WithBody(changePrecedenceRequest)

	changePrecedenceResponse, err := r.client.AdmissionControlPolicies.AdmissionControlSetRuleGroupPrecedence(params)
	if err != nil {
		var forbiddenError *admission_control_policies.AdmissionControlSetRuleGroupPrecedenceForbidden
		if errors.As(err, &forbiddenError) {
			diags.Append(tferrors.NewForbiddenError(tferrors.Update, cloudSecurityKacPolicyScopes))
			return nil
		}

		diags.Append(tferrors.NewOperationError(tferrors.Update, err))
		return nil
	}

	if changePrecedenceResponse == nil || changePrecedenceResponse.Payload == nil || len(changePrecedenceResponse.Payload.Resources) == 0 {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return nil
	}

	return changePrecedenceResponse.Payload.Resources[0]
}

func (r *cloudSecurityKacPolicyResource) updateRuleGroupAttributesAndRules(
	ctx context.Context,
	diags *diag.Diagnostics,
	policyID string,
	apiUpdateRuleGroups []*models.ModelsUpdateRuleGroup,
) *models.ModelsKACPolicy {
	if len(apiUpdateRuleGroups) == 0 {
		return nil
	}

	updateRequest := &models.ModelsUpdatePolicyRuleGroupRequest{
		ID:         &policyID,
		RuleGroups: apiUpdateRuleGroups,
	}

	params := admission_control_policies.NewAdmissionControlUpdateRuleGroupsParamsWithContext(ctx).
		WithBody(updateRequest)

	updateResponse, err := r.client.AdmissionControlPolicies.AdmissionControlUpdateRuleGroups(params)
	if err != nil {
		var forbiddenError *admission_control_policies.AdmissionControlUpdateRuleGroupsForbidden
		if errors.As(err, &forbiddenError) {
			diags.Append(tferrors.NewForbiddenError(tferrors.Update, cloudSecurityKacPolicyScopes))
			return nil
		}

		diags.Append(tferrors.NewOperationError(tferrors.Update, err))
		return nil
	}

	if updateResponse == nil || updateResponse.Payload == nil || len(updateResponse.Payload.Resources) == 0 {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return nil
	}

	return updateResponse.Payload.Resources[0]
}

func (r *cloudSecurityKacPolicyResource) replaceRuleGroupSelectors(
	ctx context.Context,
	diags *diag.Diagnostics,
	policyID string,
	apiReplaceRuleGroupSelectors []*models.ModelsReplaceRuleGroupSelectors,
) *models.ModelsKACPolicy {
	if len(apiReplaceRuleGroupSelectors) == 0 {
		return nil
	}

	replaceSelectorRequest := &models.ModelsReplacePolicyRuleGroupSelectorsRequest{
		ID:         &policyID,
		RuleGroups: apiReplaceRuleGroupSelectors,
	}

	params := admission_control_policies.NewAdmissionControlReplaceRuleGroupSelectorsParamsWithContext(ctx).
		WithBody(replaceSelectorRequest)

	replaceSelectorsResponse, err := r.client.AdmissionControlPolicies.AdmissionControlReplaceRuleGroupSelectors(params)
	if err != nil {
		var forbiddenError *admission_control_policies.AdmissionControlReplaceRuleGroupSelectorsForbidden
		if errors.As(err, &forbiddenError) {
			diags.Append(tferrors.NewForbiddenError(tferrors.Update, cloudSecurityKacPolicyScopes))
			return nil
		}

		diags.Append(tferrors.NewOperationError(tferrors.Update, err))
		return nil
	}

	if replaceSelectorsResponse == nil || replaceSelectorsResponse.Payload == nil || len(replaceSelectorsResponse.Payload.Resources) == 0 {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return nil
	}

	return replaceSelectorsResponse.Payload.Resources[0]
}
