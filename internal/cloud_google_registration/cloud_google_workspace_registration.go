package cloudgoogleregistration

import (
	"context"
	"fmt"
	"regexp"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_google_cloud_registration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/swag"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
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
	_ resource.Resource                = &cloudGoogleWorkspaceRegistrationResource{}
	_ resource.ResourceWithConfigure   = &cloudGoogleWorkspaceRegistrationResource{}
	_ resource.ResourceWithImportState = &cloudGoogleWorkspaceRegistrationResource{}
)

// customerIDFormat is the API rule for a Google Workspace customer ID.
var customerIDFormat = regexp.MustCompile(`^C[a-z0-9]+$`)

func NewCloudGoogleWorkspaceRegistrationResource() resource.Resource {
	return &cloudGoogleWorkspaceRegistrationResource{}
}

type cloudGoogleWorkspaceRegistrationResource struct {
	client *client.CrowdStrikeAPISpecification
}

type cloudGoogleWorkspaceRegistrationResourceModel struct {
	ID                types.String `tfsdk:"id"`
	RegistrationID    types.String `tfsdk:"registration_id"`
	CustomerID        types.String `tfsdk:"customer_id"`
	OrganizationID    types.String `tfsdk:"organization_id"`
	WifPoolID         types.String `tfsdk:"wif_pool_id"`
	WifProviderID     types.String `tfsdk:"wif_provider_id"`
	WifIdentitySource types.String `tfsdk:"wif_identity_source"`
	ServiceAccountID  types.String `tfsdk:"service_account_id"`
}

// wrap maps the Workspace block of the GCP registration to TF state.
func (m *cloudGoogleWorkspaceRegistrationResourceModel) wrap(workspace *models.DtoWorkspaceProperties) {
	m.ID = types.StringValue(workspace.RegistrationID)
	m.CustomerID = flex.StringValueToFramework(workspace.CustomerID)
	m.OrganizationID = flex.StringValueToFramework(workspace.OrganizationID)

	var identity models.DtoWorkspaceFederatedIdentity
	if workspace.FederatedIdentity != nil {
		identity = *workspace.FederatedIdentity
	}
	m.WifPoolID = flex.StringValueToFramework(identity.IdentityPoolID)
	m.WifProviderID = flex.StringValueToFramework(identity.ProviderID)
	m.WifIdentitySource = flex.StringValueToFramework(identity.IdentitySource)
	m.ServiceAccountID = flex.StringValueToFramework(identity.ServiceAccountID)
}

func (r *cloudGoogleWorkspaceRegistrationResource) Configure(
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

func (r *cloudGoogleWorkspaceRegistrationResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_google_workspace_registration"
}

func (r *cloudGoogleWorkspaceRegistrationResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Falcon Cloud Security",
			"This resource manages the Google Workspace registration of a Google Cloud registration in Falcon Cloud Security. If the Google Cloud registration already has a Google Workspace registration that has no settings, for example one that was added in the Falcon console, the resource adopts and updates it. The resource gives the Workload Identity Federation (WIF) values that the Google Workspace Terraform module needs. When you destroy this resource, Falcon deletes the Google Workspace registration.",
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
			"registration_id": schema.StringAttribute{
				Required:    true,
				Description: "The ID of the Google Cloud registration that has the Google Workspace registration. A change replaces the Google Workspace registration.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
			},
			"customer_id": schema.StringAttribute{
				Required:    true,
				Description: "The Google Workspace customer ID, for example C01abc2de. Falcon cannot change it after the Google Workspace Terraform module sends its settings, so a change replaces the Google Workspace registration.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthAtMost(64),
					stringvalidator.RegexMatches(customerIDFormat, "must be an uppercase C followed by lowercase letters and digits"),
				},
			},
			"organization_id": schema.StringAttribute{
				Required:    true,
				Description: "The ID of the Google Cloud organization of the Google Workspace. Must be numeric. Falcon refuses a change after the Google Workspace registration is complete.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(digitsOnly, "must be numeric"),
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
				Description: "The account name that Falcon selects for the service account that the Google Workspace Terraform module creates. Google gives the service account a different, numeric unique ID.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *cloudGoogleWorkspaceRegistrationResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan cloudGoogleWorkspaceRegistrationResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// A block with no Workspace is not an error here: the PATCH creates the Workspace.
	current, diags := getWorkspaceBlock(ctx, r.client, plan.RegistrationID.ValueString(), tferrors.Create)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if current.ConnectedThroughRegistration != nil {
		resp.Diagnostics.AddAttributeError(
			path.Root("registration_id"),
			"Google Workspace Registration Owned by Another Registration",
			fmt.Sprintf(
				"The Google Workspace registration of Google Cloud registration %s is connected through Google Cloud registration %s. Use that registration ID.",
				plan.RegistrationID.ValueString(),
				swag.StringValue(current.ConnectedThroughRegistration.ID),
			),
		)
		return
	}

	// Settings mean that another Terraform state can manage this Workspace, and a second owner deletes it on destroy.
	if current.FederatedIdentity != nil && current.FederatedIdentity.SaUniqueID != "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("registration_id"),
			"Google Workspace Registration Already Configured",
			fmt.Sprintf(
				"The Google Workspace registration %s already has settings. Import this resource and crowdstrike_cloud_google_workspace_registration_settings with the Google Cloud registration ID %s.",
				current.RegistrationID,
				plan.RegistrationID.ValueString(),
			),
		)
		return
	}

	workspace, diags := updateWorkspace(ctx, r.client, plan.RegistrationID.ValueString(), &models.DtoWorkspaceRequest{
		Enabled:        swag.Bool(true),
		CustomerID:     plan.CustomerID.ValueString(),
		OrganizationID: plan.OrganizationID.ValueString(),
	}, tferrors.Create, gcpRegistrationNotFoundDetail(plan.RegistrationID.ValueString()))
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.wrap(workspace)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

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

	tflog.Info(ctx, "Google Workspace registration created", map[string]interface{}{
		"registration_id":           plan.RegistrationID.ValueString(),
		"workspace_registration_id": plan.ID.ValueString(),
		"adopted":                   current.RegistrationID != "",
	})
}

func (r *cloudGoogleWorkspaceRegistrationResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state cloudGoogleWorkspaceRegistrationResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	workspace, diags := getWorkspace(ctx, r.client, state.RegistrationID.ValueString(), tferrors.Read)
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

func (r *cloudGoogleWorkspaceRegistrationResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan cloudGoogleWorkspaceRegistrationResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// A change of registration_id or customer_id replaces the resource, so only organization_id can change here.
	workspace, diags := updateWorkspace(ctx, r.client, plan.RegistrationID.ValueString(), &models.DtoWorkspaceRequest{
		OrganizationID: plan.OrganizationID.ValueString(),
	}, tferrors.Update, gcpRegistrationNotFoundDetail(plan.RegistrationID.ValueString()))
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.wrap(workspace)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *cloudGoogleWorkspaceRegistrationResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state cloudGoogleWorkspaceRegistrationResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	workspace, diags := getWorkspace(ctx, r.client, state.RegistrationID.ValueString(), tferrors.Delete)
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
			"registration_id":                   state.RegistrationID.ValueString(),
			"workspace_registration_id":         state.ID.ValueString(),
			"current_workspace_registration_id": workspace.RegistrationID,
		})
		return
	}

	params := cloud_google_cloud_registration.NewCloudRegistrationGcpDeleteWorkspaceRegistrationParams()
	params.SetContext(ctx)
	params.SetGcpRegistrationID(state.RegistrationID.ValueString())

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
		"registration_id":           state.RegistrationID.ValueString(),
		"workspace_registration_id": state.ID.ValueString(),
	})
}

func (r *cloudGoogleWorkspaceRegistrationResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("registration_id"), req, resp)
}

func gcpRegistrationNotFoundDetail(gcpRegistrationID string) string {
	return fmt.Sprintf("No Google Cloud registration found for registration ID: %s.", gcpRegistrationID)
}

// getWorkspaceBlock reads the Workspace block of a GCP registration; a block with no registration ID means no Workspace.
func getWorkspaceBlock(
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
			tferrors.WithNotFoundDetail(gcpRegistrationNotFoundDetail(gcpRegistrationID)),
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

	return workspace, diags
}

// getWorkspace reads the Workspace block of a GCP registration; no Workspace is a not found error, no block is a read error.
func getWorkspace(
	ctx context.Context,
	apiClient *client.CrowdStrikeAPISpecification,
	gcpRegistrationID string,
	operation tferrors.Operation,
) (*models.DtoWorkspaceProperties, diag.Diagnostics) {
	workspace, diags := getWorkspaceBlock(ctx, apiClient, gcpRegistrationID, operation)
	if diags.HasError() {
		return nil, diags
	}

	// A connected block names the owner but can have no registration ID, so the callers check it first.
	if workspace.ConnectedThroughRegistration != nil {
		return workspace, diags
	}

	if workspace.RegistrationID == "" {
		diags.Append(tferrors.NewNotFoundError(
			fmt.Sprintf("Google Cloud registration %s has no Google Workspace registration.", gcpRegistrationID),
		))
		return nil, diags
	}

	return workspace, diags
}

// updateWorkspace sends the Workspace block alone in the GCP PATCH, which creates or updates the Workspace, and returns it.
func updateWorkspace(
	ctx context.Context,
	apiClient *client.CrowdStrikeAPISpecification,
	gcpRegistrationID string,
	block *models.DtoWorkspaceRequest,
	operation tferrors.Operation,
	notFoundDetail string,
) (*models.DtoWorkspaceProperties, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := &cloud_google_cloud_registration.CloudRegistrationGcpUpdateRegistrationParams{
		Context: ctx,
		Ids:     gcpRegistrationID,
		Body: &models.DtoGCPRegistrationUpdateRequestExtV1{
			Resources: []*models.DtoUpdateGCPRegistrationRequest{
				{GoogleWorkspace: block},
			},
		},
	}

	res, err := apiClient.CloudGoogleCloudRegistration.CloudRegistrationGcpUpdateRegistration(params)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(
			operation, err, gcpRegistrationScopes,
			tferrors.WithNotFoundDetail(notFoundDetail),
		))
		return nil, diags
	}

	if res == nil || res.Payload == nil {
		diags.Append(tferrors.NewEmptyResponseError(operation))
		return nil, diags
	}

	if payloadDiag := tferrors.NewDiagnosticFromPayloadErrors(operation, res.Payload.Errors); payloadDiag != nil {
		diags.Append(payloadDiag)
		return nil, diags
	}

	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil ||
		res.Payload.Resources[0].GoogleWorkspace == nil || res.Payload.Resources[0].GoogleWorkspace.FederatedIdentity == nil {
		diags.Append(tferrors.NewEmptyResponseError(operation))
		return nil, diags
	}

	return res.Payload.Resources[0].GoogleWorkspace, diags
}
