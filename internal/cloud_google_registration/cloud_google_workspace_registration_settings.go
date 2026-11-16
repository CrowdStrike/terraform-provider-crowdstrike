package cloudgoogleregistration

import (
	"context"
	"fmt"
	"regexp"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
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
	_ resource.Resource                = &cloudGoogleWorkspaceRegistrationSettingsResource{}
	_ resource.ResourceWithConfigure   = &cloudGoogleWorkspaceRegistrationSettingsResource{}
	_ resource.ResourceWithImportState = &cloudGoogleWorkspaceRegistrationSettingsResource{}
	_ resource.ResourceWithModifyPlan  = &cloudGoogleWorkspaceRegistrationSettingsResource{}
)

var digitsOnly = regexp.MustCompile(`^[0-9]+$`)

func NewCloudGoogleWorkspaceRegistrationSettingsResource() resource.Resource {
	return &cloudGoogleWorkspaceRegistrationSettingsResource{}
}

type cloudGoogleWorkspaceRegistrationSettingsResource struct {
	client *client.CrowdStrikeAPISpecification
}

type cloudGoogleWorkspaceRegistrationSettingsResourceModel struct {
	RegistrationID          types.String `tfsdk:"registration_id"`
	WorkspaceRegistrationID types.String `tfsdk:"workspace_registration_id"`
	ServiceAccountEmail     types.String `tfsdk:"service_account_email"`
	ServiceAccountUniqueID  types.String `tfsdk:"service_account_unique_id"`
	WifPrincipal            types.String `tfsdk:"wif_principal"`
	WifProjectNumber        types.String `tfsdk:"wif_project_number"`
}

// wrap maps the stored Workspace settings to TF state; the callers check that FederatedIdentity is set.
func (m *cloudGoogleWorkspaceRegistrationSettingsResourceModel) wrap(workspace *models.DtoWorkspaceProperties) {
	identity := workspace.FederatedIdentity
	m.WorkspaceRegistrationID = types.StringValue(workspace.RegistrationID)
	m.ServiceAccountEmail = flex.StringValueToFramework(identity.SaEmail)
	m.ServiceAccountUniqueID = flex.StringValueToFramework(identity.SaUniqueID)
	m.WifPrincipal = flex.StringValueToFramework(identity.WifPrincipal)
	m.WifProjectNumber = flex.StringValueToFramework(identity.ProjectNumber)
}

func (r *cloudGoogleWorkspaceRegistrationSettingsResource) Configure(
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

func (r *cloudGoogleWorkspaceRegistrationSettingsResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_google_workspace_registration_settings"
}

func (r *cloudGoogleWorkspaceRegistrationSettingsResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Falcon Cloud Security",
			"This resource sends the output of the Google Workspace Terraform module to the Google Workspace registration of a Google Cloud registration in Falcon Cloud Security. Falcon then starts a health check of the Google Workspace registration. When you destroy this resource, Falcon clears these values.",
			gcpRegistrationScopes,
		),
		Attributes: map[string]schema.Attribute{
			"registration_id": schema.StringAttribute{
				Required:    true,
				Description: "The ID of the Google Cloud registration that has the Google Workspace registration.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
			},
			"workspace_registration_id": schema.StringAttribute{
				Computed:    true,
				Description: "The ID of the Google Workspace registration that has the settings.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"service_account_email": schema.StringAttribute{
				Required:    true,
				Description: "The email of the service account that the Google Workspace Terraform module created.",
				Validators: []validator.String{
					validators.StringIsEmailAddress(),
				},
			},
			"service_account_unique_id": schema.StringAttribute{
				Required:    true,
				Description: "The numeric unique ID that Google gave to the service account that the Google Workspace Terraform module created. It is not the service_account_id of the Google Workspace registration, which is the account name that Falcon selects.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(digitsOnly, "must be numeric"),
				},
			},
			"wif_principal": schema.StringAttribute{
				Required:    true,
				Description: "The Workload Identity Federation (WIF) principal that the Google Workspace Terraform module created.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^principal://iam\.googleapis\.com/`),
						"must start with principal://iam.googleapis.com/",
					),
				},
			},
			// No RequiresReplace: a replace clears the stored number first, so the API cannot refuse a changed number.
			"wif_project_number": schema.StringAttribute{
				Required:    true,
				Description: "The number of the Google Cloud project that has the Workload Identity Federation (WIF) pool.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(digitsOnly, "must be numeric"),
				},
			},
		},
	}
}

// ModifyPlan marks workspace_registration_id unknown when wif_principal changes, because a new principal can belong to a new Workspace.
func (r *cloudGoogleWorkspaceRegistrationSettingsResource) ModifyPlan(
	ctx context.Context,
	req resource.ModifyPlanRequest,
	resp *resource.ModifyPlanResponse,
) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}

	var plan, state cloudGoogleWorkspaceRegistrationSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !plan.WifPrincipal.Equal(state.WifPrincipal) {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("workspace_registration_id"), types.StringUnknown())...)
	}
}

func (r *cloudGoogleWorkspaceRegistrationSettingsResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan cloudGoogleWorkspaceRegistrationSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// The API refuses settings for another Workspace: wif_principal must end with its ID.
	workspace, diags := r.updateSettings(ctx, plan.RegistrationID.ValueString(), settingsFromModel(&plan), tferrors.Create)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.wrap(workspace)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *cloudGoogleWorkspaceRegistrationSettingsResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state cloudGoogleWorkspaceRegistrationSettingsResourceModel
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

	// A different ID means that the Workspace was deleted and added again; an import has no ID yet.
	replaced := utils.IsKnown(state.WorkspaceRegistrationID) && state.WorkspaceRegistrationID.ValueString() != workspace.RegistrationID
	// No service account unique ID means no settings; the GET fills a predicted email before any settings are sent.
	identity := workspace.FederatedIdentity
	if workspace.ConnectedThroughRegistration != nil || replaced || identity == nil || identity.SaUniqueID == "" {
		resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
		resp.State.RemoveResource(ctx)
		return
	}

	state.wrap(workspace)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *cloudGoogleWorkspaceRegistrationSettingsResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan cloudGoogleWorkspaceRegistrationSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	workspace, diags := r.updateSettings(ctx, plan.RegistrationID.ValueString(), settingsFromModel(&plan), tferrors.Update)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.wrap(workspace)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *cloudGoogleWorkspaceRegistrationSettingsResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state cloudGoogleWorkspaceRegistrationSettingsResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	current, diags := getWorkspace(ctx, r.client, state.RegistrationID.ValueString(), tferrors.Delete)
	if tferrors.HasNotFoundError(diags) {
		return
	}
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// The settings of a Workspace that was added again belong to that Workspace, so do not clear them.
	if current.ConnectedThroughRegistration != nil || current.RegistrationID != state.WorkspaceRegistrationID.ValueString() {
		tflog.Info(ctx, "Google Workspace registration settings not cleared: the Google Workspace registration was replaced", map[string]interface{}{
			"registration_id":                   state.RegistrationID.ValueString(),
			"workspace_registration_id":         state.WorkspaceRegistrationID.ValueString(),
			"current_workspace_registration_id": current.RegistrationID,
		})
		return
	}

	// Four empty values clear the settings.
	empty := ""
	clearRequest := &models.DtoWorkspaceSettingsRequest{
		SaEmail:       &empty,
		SaUniqueID:    &empty,
		WifPrincipal:  &empty,
		ProjectNumber: &empty,
	}

	workspace, diags := r.updateSettings(ctx, state.RegistrationID.ValueString(), clearRequest, tferrors.Delete)
	if tferrors.HasNotFoundError(diags) {
		return
	}
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if workspace.FederatedIdentity != nil && workspace.FederatedIdentity.SaUniqueID != "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("service_account_unique_id"),
			"Delete failed.",
			"The service account unique ID was returned after the attempt to remove it. This is a bug in the provider. Please report this issue here: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues",
		)
		return
	}

	tflog.Info(ctx, "Google Workspace registration settings cleared", map[string]interface{}{
		"registration_id":           state.RegistrationID.ValueString(),
		"workspace_registration_id": state.WorkspaceRegistrationID.ValueString(),
	})
}

func (r *cloudGoogleWorkspaceRegistrationSettingsResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("registration_id"), req, resp)
}

func settingsFromModel(m *cloudGoogleWorkspaceRegistrationSettingsResourceModel) *models.DtoWorkspaceSettingsRequest {
	return &models.DtoWorkspaceSettingsRequest{
		SaEmail:       m.ServiceAccountEmail.ValueStringPointer(),
		SaUniqueID:    m.ServiceAccountUniqueID.ValueStringPointer(),
		WifPrincipal:  m.WifPrincipal.ValueStringPointer(),
		ProjectNumber: m.WifProjectNumber.ValueStringPointer(),
	}
}

// updateSettings sends the settings alone in the Workspace block of the GCP PATCH, and returns the updated Workspace.
func (r *cloudGoogleWorkspaceRegistrationSettingsResource) updateSettings(
	ctx context.Context,
	gcpRegistrationID string,
	settings *models.DtoWorkspaceSettingsRequest,
	operation tferrors.Operation,
) (*models.DtoWorkspaceProperties, diag.Diagnostics) {
	return updateWorkspace(ctx, r.client, gcpRegistrationID, &models.DtoWorkspaceRequest{Settings: settings}, operation, fmt.Sprintf(
		"No Google Workspace registration found for Google Cloud registration ID: %s. Create it with crowdstrike_cloud_google_workspace_registration.",
		gcpRegistrationID,
	))
}
