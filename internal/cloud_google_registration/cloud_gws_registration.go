package cloudgoogleregistration

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_google_cloud_registration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/swag"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                = &cloudGwsRegistrationResource{}
	_ resource.ResourceWithConfigure   = &cloudGwsRegistrationResource{}
	_ resource.ResourceWithImportState = &cloudGwsRegistrationResource{}
	_ resource.ResourceWithModifyPlan  = &cloudGwsRegistrationResource{}
)

func NewCloudGwsRegistrationResource() resource.Resource {
	return &cloudGwsRegistrationResource{}
}

type cloudGwsRegistrationResource struct {
	client *client.CrowdStrikeAPISpecification
}

type cloudGwsRegistrationResourceModel struct {
	ID                types.String `tfsdk:"id"`
	GcpRegistrationID types.String `tfsdk:"gcp_registration_id"`
	WifPoolID         types.String `tfsdk:"wif_pool_id"`
	WifProviderID     types.String `tfsdk:"wif_provider_id"`
	WifIdentitySource types.String `tfsdk:"wif_identity_source"`
	ServiceAccountID  types.String `tfsdk:"service_account_id"`
}

// wrap maps the Workspace block of the GCP registration to TF state.
func (m *cloudGwsRegistrationResourceModel) wrap(workspace *models.DtoWorkspaceProperties) {
	m.ID = types.StringValue(workspace.RegistrationID)

	var identity models.DtoWorkspaceFederatedIdentity
	if workspace.FederatedIdentity != nil {
		identity = *workspace.FederatedIdentity
	}
	m.WifPoolID = flex.StringValueToFramework(identity.IdentityPoolID)
	m.WifProviderID = flex.StringValueToFramework(identity.ProviderID)
	m.WifIdentitySource = flex.StringValueToFramework(identity.IdentitySource)
	m.ServiceAccountID = flex.StringValueToFramework(identity.ServiceAccountID)
}

func (r *cloudGwsRegistrationResource) Configure(
	ctx context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	providerConfig, ok := req.ProviderData.(config.ProviderConfig)

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

	r.client = providerConfig.Client
}

func (r *cloudGwsRegistrationResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_gws_registration"
}

func (r *cloudGwsRegistrationResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Falcon Cloud Security",
			"This resource adopts the Google Workspace registration of a Google Cloud registration in Falcon Cloud Security. Add the Google Workspace to the Google Cloud registration in the Falcon console first: this resource does not create it. The resource gives the Workload Identity Federation (WIF) values that the Google Workspace Terraform module needs. When you destroy this resource, Falcon deletes the Google Workspace registration.",
			gcpRegistrationScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The Google Workspace registration ID.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"gcp_registration_id": schema.StringAttribute{
				Required:    true,
				Description: "The ID of the Google Cloud registration that has the Google Workspace registration. You cannot change it: destroy this resource first.",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
			},
			"wif_pool_id": schema.StringAttribute{
				Computed:    true,
				Description: "The ID of the Workload Identity Federation (WIF) pool to create for the Google Workspace.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"wif_provider_id": schema.StringAttribute{
				Computed:    true,
				Description: "The ID of the Workload Identity Federation (WIF) provider to create in the pool.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"wif_identity_source": schema.StringAttribute{
				Computed:    true,
				Description: "The identity source of the Workload Identity Federation (WIF) provider: aws-sts or gcp-oidc.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"service_account_id": schema.StringAttribute{
				Computed:    true,
				Description: "The ID of the service account to create for the Google Workspace.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *cloudGwsRegistrationResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan cloudGwsRegistrationResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	workspace, diags := getWorkspace(ctx, r.client, plan.GcpRegistrationID.ValueString(), tferrors.Create)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if workspace.ConnectedThroughRegistration != nil {
		resp.Diagnostics.AddAttributeError(
			path.Root("gcp_registration_id"),
			"Google Workspace Registration Owned by Another Registration",
			fmt.Sprintf(
				"The Google Workspace registration of Google Cloud registration %s is connected through Google Cloud registration %s. Use that registration ID.",
				plan.GcpRegistrationID.ValueString(),
				swag.StringValue(workspace.ConnectedThroughRegistration.ID),
			),
		)
		return
	}

	// Settings mean that another Terraform state can manage this Workspace, and a second owner deletes it on destroy.
	if workspace.FederatedIdentity != nil && workspace.FederatedIdentity.SaUniqueID != "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("gcp_registration_id"),
			"Google Workspace Registration Already Configured",
			fmt.Sprintf(
				"The Google Workspace registration %s already has settings. Import this resource and crowdstrike_cloud_gws_registration_settings with the Google Cloud registration ID %s.",
				workspace.RegistrationID,
				plan.GcpRegistrationID.ValueString(),
			),
		)
		return
	}

	plan.wrap(workspace)

	if plan.WifPoolID.IsNull() || plan.WifProviderID.IsNull() || plan.WifIdentitySource.IsNull() || plan.ServiceAccountID.IsNull() {
		resp.Diagnostics.AddError(
			"Incomplete Google Workspace Registration",
			fmt.Sprintf(
				"The Google Workspace registration %s has no Workload Identity Federation (WIF) values. If the problem persists, please report this issue at: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues",
				plan.ID.ValueString(),
			),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *cloudGwsRegistrationResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state cloudGwsRegistrationResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	workspace, diags := getWorkspace(ctx, r.client, state.GcpRegistrationID.ValueString(), tferrors.Read)
	if tferrors.HasNotFoundError(diags) {
		resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// A different ID means that the Workspace was deleted and added again outside of Terraform.
	replaced := utils.IsKnown(state.ID) && state.ID.ValueString() != workspace.RegistrationID
	if workspace.ConnectedThroughRegistration != nil || replaced {
		resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
		resp.State.RemoveResource(ctx)
		return
	}

	state.wrap(workspace)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *cloudGwsRegistrationResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan, state cloudGwsRegistrationResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// ModifyPlan cannot see a value that is unknown at plan time, so the apply refuses it here.
	if !plan.GcpRegistrationID.Equal(state.GcpRegistrationID) {
		resp.Diagnostics.Append(gcpRegistrationIDChangeError())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// ModifyPlan refuses a gcp_registration_id change: a replacement deletes the Workspace, and Create cannot add one.
func (r *cloudGwsRegistrationResource) ModifyPlan(
	ctx context.Context,
	req resource.ModifyPlanRequest,
	resp *resource.ModifyPlanResponse,
) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}

	var stateID, planID types.String
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("gcp_registration_id"), &stateID)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("gcp_registration_id"), &planID)...)
	if resp.Diagnostics.HasError() || !utils.IsKnown(planID) || planID.Equal(stateID) {
		return
	}

	resp.Diagnostics.Append(gcpRegistrationIDChangeError())
}

func gcpRegistrationIDChangeError() diag.Diagnostic {
	return diag.NewAttributeErrorDiagnostic(
		path.Root("gcp_registration_id"),
		"Google Cloud Registration ID Cannot Change",
		"A new gcp_registration_id needs a new Google Workspace registration, and this resource cannot create one. A replacement deletes the current Google Workspace registration. Destroy this resource first, add the Google Workspace to the new Google Cloud registration in the Falcon console, and then apply again.",
	)
}

func (r *cloudGwsRegistrationResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state cloudGwsRegistrationResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	workspace, diags := getWorkspace(ctx, r.client, state.GcpRegistrationID.ValueString(), tferrors.Delete)
	if tferrors.HasNotFoundError(diags) {
		return
	}
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// The DELETE takes only the Google Cloud registration ID, so a Workspace added again outside of Terraform must stay.
	if workspace.ConnectedThroughRegistration != nil || workspace.RegistrationID != state.ID.ValueString() {
		tflog.Info(ctx, "Google Workspace registration already deleted", map[string]interface{}{
			"registration_id":         state.ID.ValueString(),
			"current_registration_id": workspace.RegistrationID,
			"gcp_registration_id":     state.GcpRegistrationID.ValueString(),
		})
		return
	}

	params := cloud_google_cloud_registration.NewCloudRegistrationGcpDeleteWorkspaceRegistrationParams()
	params.SetContext(ctx)
	params.SetGcpRegistrationID(state.GcpRegistrationID.ValueString())

	res, err := r.client.CloudGoogleCloudRegistration.CloudRegistrationGcpDeleteWorkspaceRegistration(params)
	if err != nil {
		apiDiag := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, gcpRegistrationScopes)
		if apiDiag.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(apiDiag)
		return
	}

	if res != nil && res.Payload != nil {
		if payloadDiag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Delete, res.Payload.Errors); payloadDiag != nil {
			resp.Diagnostics.Append(payloadDiag)
			return
		}
	}

	tflog.Info(ctx, "Google Workspace registration deleted", map[string]interface{}{
		"registration_id":     state.ID.ValueString(),
		"gcp_registration_id": state.GcpRegistrationID.ValueString(),
	})
}

func (r *cloudGwsRegistrationResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("gcp_registration_id"), req, resp)
}

// getWorkspace reads the Workspace block of a GCP registration; no Workspace is a not found error, no block is a read error.
func getWorkspace(
	ctx context.Context,
	apiClient *client.CrowdStrikeAPISpecification,
	gcpRegistrationID string,
	operation tferrors.Operation,
) (*models.DtoWorkspaceProperties, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := cloud_google_cloud_registration.NewCloudRegistrationGcpGetRegistrationParams()
	params.SetContext(ctx)
	params.SetIds(gcpRegistrationID)

	res, err := apiClient.CloudGoogleCloudRegistration.CloudRegistrationGcpGetRegistration(params)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(
			operation, err, gcpRegistrationScopes,
			tferrors.WithNotFoundDetail(fmt.Sprintf("No Google Cloud registration found for registration ID: %s.", gcpRegistrationID)),
		))
		return nil, diags
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		diags.Append(tferrors.NewEmptyResponseError(operation))
		return nil, diags
	}

	// The API leaves out the block only when it cannot read the Workspace; no Workspace is enabled=false.
	workspace := res.Payload.Resources[0].GoogleWorkspace
	if workspace == nil {
		diags.Append(diag.NewErrorDiagnostic(
			fmt.Sprintf("Failed to %s", operation),
			fmt.Sprintf("The response for Google Cloud registration %s has no Google Workspace block. Try again later.", gcpRegistrationID),
		))
		return nil, diags
	}

	// A connected block names the owner but can have no registration ID, so the callers check it first.
	if workspace.ConnectedThroughRegistration != nil {
		return workspace, diags
	}

	if workspace.RegistrationID == "" {
		diags.Append(tferrors.NewNotFoundError(
			fmt.Sprintf(
				"Google Cloud registration %s has no Google Workspace registration. Add the Google Workspace to the registration in the Falcon console.",
				gcpRegistrationID,
			),
		))
		return nil, diags
	}

	return workspace, diags
}
