package cloudsecurity

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/admission_control_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &cloudSecurityKacPolicyResource{}
	_ resource.ResourceWithConfigure      = &cloudSecurityKacPolicyResource{}
	_ resource.ResourceWithImportState    = &cloudSecurityKacPolicyResource{}
	_ resource.ResourceWithValidateConfig = &cloudSecurityKacPolicyResource{}
)

var (
	kacPolicyDocumentationSection        = "Falcon Cloud Security"
	kacPolicyResourceMarkdownDescription = "This resource manages an admission control (KAC) policy, which provides instructions to the Falcon Kubernetes Admission Controller (KAC) about what actions to take on objects at runtime."
	kacPolicyRequiredScopes              = cloudSecurityKacPolicyScopes
)

func NewCloudSecurityKacPolicyResource() resource.Resource {
	return &cloudSecurityKacPolicyResource{}
}

type cloudSecurityKacPolicyResource struct {
	client *client.CrowdStrikeAPISpecification
}

type cloudSecurityKacPolicyResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	IsEnabled   types.Bool   `tfsdk:"is_enabled"`
	Precedence  types.Int32  `tfsdk:"precedence"`
}

func (m *cloudSecurityKacPolicyResourceModel) wrap(
	_ context.Context,
	policy *models.PolicyhandlerKACPolicy,
) {
	if policy.ID != nil {
		m.ID = types.StringValue(*policy.ID)
	}
	if policy.Name != nil {
		m.Name = types.StringValue(*policy.Name)
	}
	if policy.Description != nil && strings.TrimSpace(*policy.Description) != "" {
		m.Description = types.StringValue(*policy.Description)
	}

	m.IsEnabled = types.BoolValue(*policy.IsEnabled)
	m.Precedence = types.Int32PointerValue(policy.Precedence)
}

func (r *cloudSecurityKacPolicyResource) Configure(
	_ context.Context,
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
				Description: "Identifier for the Cloud Security Kac Policy.",
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
			"is_enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Whether the policy is enabled. Must be set to false before the policy can be deleted.",
			},
			"precedence": schema.Int32Attribute{
				Optional:    true,
				Computed:    true,
				Description: "The order of priority when evaluating KAC policies, 1 being the highest priority.",
			},
		},
	}
}

func (r *cloudSecurityKacPolicyResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan cloudSecurityKacPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createRequest := &models.APICreatePolicyRequest{
		Name: plan.Name.ValueStringPointer(),
	}

	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		createRequest.Description = plan.Description.ValueString()
	}

	params := admission_control_policies.NewAdmissionControlCreatePolicyParamsWithContext(ctx)
	params.SetBody(createRequest)

	createResponse, err := r.client.AdmissionControlPolicies.AdmissionControlCreatePolicy(params)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating KAC policy",
			fmt.Sprintf("Could not create KAC policy: %s", err.Error()),
		)
		return
	}

	if len(createResponse.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Error creating KAC policy",
			"No policy returned in create response",
		)
		return
	}

	policy := createResponse.Payload.Resources[0]
	plan.ID = types.StringValue(*policy.ID)

	if !plan.IsEnabled.IsNull() && !plan.IsEnabled.IsUnknown() && plan.IsEnabled.ValueBool() {
		updateRequest := &models.APIUpdatePolicyRequest{
			IsEnabled: plan.IsEnabled.ValueBool(),
		}

		updateParams := admission_control_policies.NewAdmissionControlUpdatePolicyParamsWithContext(ctx)
		updateParams.SetBody(updateRequest)
		updateParams.SetIds(plan.ID.ValueString())

		_, err := r.client.AdmissionControlPolicies.AdmissionControlUpdatePolicy(updateParams)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error updating KAC policy enabled status",
				fmt.Sprintf("Could not update KAC policy enabled status: %s", err.Error()),
			)
			return
		}
	}

	// Handle precedence update if needed
	if !plan.Precedence.IsNull() && !plan.Precedence.IsUnknown() {
		precedenceRequest := &models.APIUpdatePolicyPrecedenceRequest{
			ID:         plan.ID.ValueStringPointer(),
			Precedence: plan.Precedence.ValueInt32(),
		}

		precedenceParams := admission_control_policies.NewAdmissionControlUpdatePolicyPrecedenceParamsWithContext(ctx)
		precedenceParams.SetBody(precedenceRequest)

		precedenceResponse, err := r.client.AdmissionControlPolicies.AdmissionControlUpdatePolicyPrecedence(precedenceParams)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error updating KAC policy precedence",
				fmt.Sprintf("Could not update KAC policy precedence: %s", err.Error()),
			)
			return
		}

		// Use the response from precedence update if available
		if len(precedenceResponse.Payload.Resources) > 0 {
			policy = precedenceResponse.Payload.Resources[0]
		}
	}

	plan.wrap(ctx, policy)
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

	params := admission_control_policies.NewAdmissionControlGetPoliciesParamsWithContext(ctx)
	params.SetIds([]string{state.ID.ValueString()})

	getResponse, err := r.client.AdmissionControlPolicies.AdmissionControlGetPolicies(params)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading KAC policy",
			fmt.Sprintf("Could not read KAC policy %s: %s", state.ID.ValueString(), err.Error()),
		)
		return
	}

	if len(getResponse.Payload.Resources) == 0 {
		resp.State.RemoveResource(ctx)
		return
	}

	policy := getResponse.Payload.Resources[0]
	state.wrap(ctx, policy)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *cloudSecurityKacPolicyResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan cloudSecurityKacPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateRequest := &models.APIUpdatePolicyRequest{}

	if !plan.Name.IsNull() && !plan.Name.IsUnknown() {
		updateRequest.Name = plan.Name.ValueString()
	}

	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		updateRequest.Description = plan.Description.ValueString()
	}

	if !plan.IsEnabled.IsNull() && !plan.IsEnabled.IsUnknown() {
		updateRequest.IsEnabled = plan.IsEnabled.ValueBool()
	}

	params := admission_control_policies.NewAdmissionControlUpdatePolicyParamsWithContext(ctx)
	params.SetBody(updateRequest)
	params.SetIds(plan.ID.ValueString())

	updateResponse, err := r.client.AdmissionControlPolicies.AdmissionControlUpdatePolicy(params)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating KAC policy",
			fmt.Sprintf("Could not update KAC policy: %s", err.Error()),
		)
		return
	}

	if len(updateResponse.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Error updating KAC policy",
			"No policy returned in update response",
		)
		return
	}

	policy := updateResponse.Payload.Resources[0]

	// Handle precedence update separately if needed
	if !plan.Precedence.IsNull() && !plan.Precedence.IsUnknown() {
		precedenceRequest := &models.APIUpdatePolicyPrecedenceRequest{
			ID:         plan.ID.ValueStringPointer(),
			Precedence: plan.Precedence.ValueInt32(),
		}

		precedenceParams := admission_control_policies.NewAdmissionControlUpdatePolicyPrecedenceParamsWithContext(ctx)
		precedenceParams.SetBody(precedenceRequest)

		precedenceResponse, err := r.client.AdmissionControlPolicies.AdmissionControlUpdatePolicyPrecedence(precedenceParams)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error updating KAC policy precedence",
				fmt.Sprintf("Could not update KAC policy precedence: %s", err.Error()),
			)
			return
		}

		// Use the response from precedence update if available
		if len(precedenceResponse.Payload.Resources) > 0 {
			policy = precedenceResponse.Payload.Resources[0]
		}
	}

	plan.wrap(ctx, policy)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *cloudSecurityKacPolicyResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state cloudSecurityKacPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Verify policy is disabled before deletion
	if !state.IsEnabled.IsNull() && !state.IsEnabled.IsUnknown() && state.IsEnabled.ValueBool() {
		resp.Diagnostics.AddError(
			"Cannot delete enabled KAC policy",
			"The KAC policy must be disabled before it can be deleted.",
		)
		return
	}

	params := admission_control_policies.NewAdmissionControlDeletePoliciesParamsWithContext(ctx)
	params.SetIds([]string{state.ID.ValueString()})

	_, err := r.client.AdmissionControlPolicies.AdmissionControlDeletePolicies(params)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting KAC policy",
			fmt.Sprintf("Could not delete KAC policy %s: %s", state.ID.ValueString(), err.Error()),
		)
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
	var config cloudSecurityKacPolicyResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
}
