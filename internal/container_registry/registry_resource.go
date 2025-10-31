package containerregistry

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/falcon_container_image"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &containerRegistryResource{}
	_ resource.ResourceWithConfigure      = &containerRegistryResource{}
	_ resource.ResourceWithImportState    = &containerRegistryResource{}
	_ resource.ResourceWithValidateConfig = &containerRegistryResource{}
)

// containerRegistryResource defines the resource implementation.
type containerRegistryResource struct {
	client *client.CrowdStrikeAPISpecification
}

// containerRegistryModel describes the resource data model.
type containerRegistryModel struct {
	ID               types.String `tfsdk:"id"`
	Type             types.String `tfsdk:"type"`
	URL              types.String `tfsdk:"url"`
	URLUniquenessKey types.String `tfsdk:"url_uniqueness_key"`
	UserDefinedAlias types.String `tfsdk:"user_defined_alias"`
	RefreshInterval  types.Int64  `tfsdk:"refresh_interval"`
	LastRefreshedAt  types.String `tfsdk:"last_refreshed_at"`
	NextRefreshAt    types.String `tfsdk:"next_refresh_at"`
	State            types.String `tfsdk:"state"`
	StateChangedAt   types.String `tfsdk:"state_changed_at"`
	CreatedAt        types.String `tfsdk:"created_at"`
	UpdatedAt        types.String `tfsdk:"updated_at"`

	// Generic credential fields (optional - used by some registry types)
	CredentialUsername types.String `tfsdk:"credential_username"`
	CredentialPassword types.String `tfsdk:"credential_password"`

	// AWS ECR specific fields
	AWSIAMRole    types.String `tfsdk:"aws_iam_role"`
	AWSExternalID types.String `tfsdk:"aws_external_id"`

	// GitHub/GitLab specific fields
	CredentialType types.String `tfsdk:"credential_type"`
	DomainURL      types.String `tfsdk:"domain_url"`

	// Google (GAR/GCR) specific fields
	ProjectID          types.String `tfsdk:"project_id"`
	ScopeName          types.String `tfsdk:"scope_name"`
	ServiceAccountJSON types.String `tfsdk:"service_account_json"`

	// Oracle specific fields
	CompartmentIDs types.String `tfsdk:"compartment_ids"`

	// Computed credential status fields
	CredentialExpired   types.Bool   `tfsdk:"credential_expired"`
	CredentialExpiredAt types.String `tfsdk:"credential_expired_at"`
	CredentialCreatedAt types.String `tfsdk:"credential_created_at"`
	CredentialUpdatedAt types.String `tfsdk:"credential_updated_at"`
}

// NewContainerRegistryResource is a helper function to simplify the provider implementation.
func NewContainerRegistryResource() resource.Resource {
	return &containerRegistryResource{}
}

// Metadata returns the resource type name.
func (r *containerRegistryResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_container_registry"
}

// Schema defines the schema for the resource.
func (r *containerRegistryResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf(
			"Container Registry --- This resource allows management of container registry connections in Falcon.\n\n%s",
			scopes.GenerateScopeDescription(containerRegistryScopes),
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The unique identifier of the registry connection",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"type": schema.StringAttribute{
				Required:    true,
				Description: "The type of registry (e.g., dockerhub, ecr, gcr, etc.)",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf(
						"dockerhub", "ecr", "gcr", "gar", "acr", "artifactory",
						"docker", "github", "gitlab", "icr", "mirantis", "nexus",
						"openshift", "oracle", "quay.io", "harbor",
					),
				},
			},
			"url": schema.StringAttribute{
				Required:    true,
				Description: "The URL used to log in to the registry",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"url_uniqueness_key": schema.StringAttribute{
				Optional:    true,
				Description: "The registry URL alias (for registries that support it)",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"user_defined_alias": schema.StringAttribute{
				Optional:    true,
				Description: "A user-friendly name for the registry connection (not required for ECR)",
			},
			// Generic credential fields (used by DockerHub, Harbor, ICR, etc.)
			"credential_username": schema.StringAttribute{
				Optional:    true,
				Description: "Username for registry authentication (required for dockerhub, docker, icr, artifactory, acr, nexus, openshift, quay.io, harbor)",
				Sensitive:   true,
			},
			"credential_password": schema.StringAttribute{
				Optional:    true,
				Description: "Password or token for registry authentication (required for dockerhub, docker, icr, artifactory, acr, nexus, openshift, quay.io, harbor, github, gitlab, oracle)",
				Sensitive:   true,
			},

			// AWS ECR specific fields
			"aws_iam_role": schema.StringAttribute{
				Optional:    true,
				Description: "AWS IAM role ARN for ECR authentication (required for ecr type)",
				Sensitive:   true,
			},
			"aws_external_id": schema.StringAttribute{
				Optional:    true,
				Description: "AWS external ID for ECR authentication (required for ecr type)",
				Sensitive:   true,
			},

			// GitHub/GitLab specific fields
			"credential_type": schema.StringAttribute{
				Optional:    true,
				Description: "Credential type for GitHub/GitLab (required for github, gitlab types)",
			},
			"domain_url": schema.StringAttribute{
				Optional:    true,
				Description: "Domain URL for GitHub/GitLab (required for github, gitlab types)",
			},

			// Google (GAR/GCR) specific fields
			"project_id": schema.StringAttribute{
				Optional:    true,
				Description: "Google Cloud project ID (required for gar, gcr types)",
			},
			"scope_name": schema.StringAttribute{
				Optional:    true,
				Description: "Scope name for Google Artifact Registry (required for gar type) or Oracle (required for oracle type)",
			},
			"service_account_json": schema.StringAttribute{
				Optional:    true,
				Description: "Service account JSON for Google registries (required for gar, gcr types)",
				Sensitive:   true,
			},

			// Oracle specific fields
			"compartment_ids": schema.StringAttribute{
				Optional:    true,
				Description: "Compartment IDs for Oracle Container Registry (required for oracle type)",
			},
			// Computed attributes
			"refresh_interval": schema.Int64Attribute{
				Computed:    true,
				Default:     int64default.StaticInt64(7200),
				Description: "The registry assessment interval in seconds",
			},
			"last_refreshed_at": schema.StringAttribute{
				Computed:    true,
				Description: "The last time the registry was assessed",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"next_refresh_at": schema.StringAttribute{
				Computed:    true,
				Description: "The registry's next scheduled assessment time",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"state": schema.StringAttribute{
				Computed:    true,
				Description: "The current state of the registry connection",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"state_changed_at": schema.StringAttribute{
				Computed:    true,
				Description: "The date and time of the registry connection's last state change",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "The date and time the registry connection was created",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "The date and time the registry connection was last updated",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"credential_expired": schema.BoolAttribute{
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Whether the registry credentials have expired",
			},
			"credential_expired_at": schema.StringAttribute{
				Computed:    true,
				Description: "The date and time the registry credentials expired",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"credential_created_at": schema.StringAttribute{
				Computed:    true,
				Description: "The date and time the registry connection credential was created",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"credential_updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "The date and time the registry connection credential was last updated",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *containerRegistryResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan containerRegistryModel

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create registry connection
	registryType := plan.Type.ValueString()
	registryURL := plan.URL.ValueString()
	userAlias := plan.UserDefinedAlias.ValueString()

	payload := &models.RegistryassessmentExternalRegistryPayload{
		Type:             &registryType,
		URL:              &registryURL,
		UserDefinedAlias: userAlias,
	}

	if !plan.URLUniquenessKey.IsNull() && !plan.URLUniquenessKey.IsUnknown() {
		urlKey := plan.URLUniquenessKey.ValueString()
		payload.URLUniquenessKey = urlKey
	}

	// Add registry-specific credential fields based on registry type
	credentialDetails := r.buildCredentialDetails(registryType, &plan)

	// Set the credential details if any were provided
	if len(credentialDetails) > 0 {
		payload.Credential = &models.RegistryassessmentExternalCredPayload{
			Details: credentialDetails,
		}
	}

	createParams := falcon_container_image.NewCreateRegistryEntitiesParams().WithBody(payload)

	tflog.Info(ctx, "Creating container registry connection")
	result, err := r.client.FalconContainerImage.CreateRegistryEntities(createParams)
	if err != nil {
		resp.Diagnostics.Append(newRegistryCreateError(fmt.Sprintf("Error creating registry connection: %s", err.Error())))
		return
	}

	if result.Payload == nil || result.Payload.Resources == nil {
		resp.Diagnostics.Append(newRegistryCreateError("No registry connection was returned from the API"))
		return
	}

	registry := result.Payload.Resources
	r.updateModelFromRegistry(&plan, registry)

	// Set state
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Read refreshes the Terraform state with the latest data.
func (r *containerRegistryResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state containerRegistryModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if state.ID.ValueString() == "" {
		return
	}

	// Get registry connection details
	getParams := falcon_container_image.NewReadRegistryEntitiesByUUIDParams().WithIds(state.ID.ValueString())

	tflog.Info(ctx, "Reading container registry connection", map[string]interface{}{"id": state.ID.ValueString()})
	result, err := r.client.FalconContainerImage.ReadRegistryEntitiesByUUID(getParams)
	if err != nil {
		resp.Diagnostics.Append(newRegistryReadError(fmt.Sprintf("Error reading registry connection: %s", err.Error())))
		return
	}

	if result.Payload == nil || len(result.Payload.Resources) == 0 {
		// Registry connection not found, remove from state
		resp.State.RemoveResource(ctx)
		return
	}

	registry := result.Payload.Resources[0]
	r.updateModelFromRegistry(&state, registry)

	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *containerRegistryResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan, state containerRegistryModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update registry connection
	updateParams := falcon_container_image.NewUpdateRegistryEntitiesParams().WithID(state.ID.ValueString()).WithBody(&models.RegistryassessmentExternalRegistryPatchPayload{
		UserDefinedAlias: plan.UserDefinedAlias.ValueString(),
	})

	tflog.Info(ctx, "Updating container registry connection", map[string]interface{}{"id": state.ID.ValueString()})
	result, err := r.client.FalconContainerImage.UpdateRegistryEntities(updateParams)
	if err != nil {
		resp.Diagnostics.Append(newRegistryUpdateError(fmt.Sprintf("Error updating registry connection: %s", err.Error())))
		return
	}

	if result.Payload == nil || result.Payload.Resources == nil {
		resp.Diagnostics.Append(newRegistryUpdateError("No registry connection was returned from the API"))
		return
	}

	registry := result.Payload.Resources
	r.updateModelFromRegistry(&plan, registry)

	// Set updated state
	diags := resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *containerRegistryResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state containerRegistryModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete registry connection
	deleteParams := falcon_container_image.NewDeleteRegistryEntitiesParams().WithIds(state.ID.ValueString())

	tflog.Info(ctx, "Deleting container registry connection", map[string]interface{}{"id": state.ID.ValueString()})
	_, err := r.client.FalconContainerImage.DeleteRegistryEntities(deleteParams)
	if err != nil {
		resp.Diagnostics.Append(newRegistryDeleteError(fmt.Sprintf("Error deleting registry connection: %s", err.Error())))
		return
	}
}

// Configure adds the provider configured client to the resource.
func (r *containerRegistryResource) Configure(
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

// ImportState implements the logic to support resource imports.
func (r *containerRegistryResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ValidateConfig validates the resource configuration.
func (r *containerRegistryResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config containerRegistryModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Skip validation if type is not set (will be caught by Required validation)
	if config.Type.IsNull() || config.Type.IsUnknown() {
		return
	}

	registryType := config.Type.ValueString()

	// Validate user_defined_alias is required for all registry types except ECR
	if registryType != "ecr" && (config.UserDefinedAlias.IsNull() || config.UserDefinedAlias.IsUnknown()) {
		resp.Diagnostics.AddAttributeError(
			path.Root("user_defined_alias"),
			"Missing required field",
			fmt.Sprintf("user_defined_alias is required when type is '%s'", registryType),
		)
	}

	// Validate registry-specific required credentials
	r.validateRegistryCredentials(registryType, &config, resp)
}

// buildCredentialDetails creates credential details map based on registry type and plan.
func (r *containerRegistryResource) buildCredentialDetails(registryType string, plan *containerRegistryModel) map[string]interface{} {
	credentialDetails := make(map[string]interface{})

	switch registryType {
	case "ecr":
		r.addECRCredentials(credentialDetails, plan)
	case "dockerhub", "docker", "icr", "artifactory", "acr", "nexus", "openshift", "quay.io", "harbor", "mirantis":
		r.addUsernamePasswordCredentials(credentialDetails, plan)
	case "github", "gitlab":
		r.addGitCredentials(credentialDetails, plan)
	case "gar":
		r.addGARCredentials(credentialDetails, plan)
	case "gcr":
		r.addGCRCredentials(credentialDetails, plan)
	case "oracle":
		r.addOracleCredentials(credentialDetails, plan)
	}

	return credentialDetails
}

// addECRCredentials adds AWS ECR specific credentials.
func (r *containerRegistryResource) addECRCredentials(credentialDetails map[string]interface{}, plan *containerRegistryModel) {
	if !plan.AWSIAMRole.IsNull() && !plan.AWSIAMRole.IsUnknown() {
		credentialDetails["aws_iam_role"] = plan.AWSIAMRole.ValueString()
	}
	if !plan.AWSExternalID.IsNull() && !plan.AWSExternalID.IsUnknown() {
		credentialDetails["aws_external_id"] = plan.AWSExternalID.ValueString()
	}
}

// addUsernamePasswordCredentials adds username/password credentials.
func (r *containerRegistryResource) addUsernamePasswordCredentials(credentialDetails map[string]interface{}, plan *containerRegistryModel) {
	if !plan.CredentialUsername.IsNull() && !plan.CredentialUsername.IsUnknown() {
		credentialDetails["username"] = plan.CredentialUsername.ValueString()
	}
	if !plan.CredentialPassword.IsNull() && !plan.CredentialPassword.IsUnknown() {
		credentialDetails["password"] = plan.CredentialPassword.ValueString()
	}
}

// addGitCredentials adds GitHub/GitLab specific credentials.
func (r *containerRegistryResource) addGitCredentials(credentialDetails map[string]interface{}, plan *containerRegistryModel) {
	if !plan.CredentialType.IsNull() && !plan.CredentialType.IsUnknown() {
		credentialDetails["credential_type"] = plan.CredentialType.ValueString()
	}
	if !plan.DomainURL.IsNull() && !plan.DomainURL.IsUnknown() {
		credentialDetails["domain_url"] = plan.DomainURL.ValueString()
	}
	if !plan.CredentialUsername.IsNull() && !plan.CredentialUsername.IsUnknown() {
		credentialDetails["username"] = plan.CredentialUsername.ValueString()
	}
	if !plan.CredentialPassword.IsNull() && !plan.CredentialPassword.IsUnknown() {
		credentialDetails["password"] = plan.CredentialPassword.ValueString()
	}
}

// addGARCredentials adds Google Artifact Registry specific credentials.
func (r *containerRegistryResource) addGARCredentials(credentialDetails map[string]interface{}, plan *containerRegistryModel) {
	if !plan.ProjectID.IsNull() && !plan.ProjectID.IsUnknown() {
		credentialDetails["project_id"] = plan.ProjectID.ValueString()
	}
	if !plan.ScopeName.IsNull() && !plan.ScopeName.IsUnknown() {
		credentialDetails["scope_name"] = plan.ScopeName.ValueString()
	}
	if !plan.ServiceAccountJSON.IsNull() && !plan.ServiceAccountJSON.IsUnknown() {
		credentialDetails["service_account_json"] = plan.ServiceAccountJSON.ValueString()
	}
}

// addGCRCredentials adds Google Container Registry specific credentials.
func (r *containerRegistryResource) addGCRCredentials(credentialDetails map[string]interface{}, plan *containerRegistryModel) {
	if !plan.ProjectID.IsNull() && !plan.ProjectID.IsUnknown() {
		credentialDetails["project_id"] = plan.ProjectID.ValueString()
	}
	if !plan.ServiceAccountJSON.IsNull() && !plan.ServiceAccountJSON.IsUnknown() {
		credentialDetails["service_account_json"] = plan.ServiceAccountJSON.ValueString()
	}
}

// addOracleCredentials adds Oracle Container Registry specific credentials.
func (r *containerRegistryResource) addOracleCredentials(credentialDetails map[string]interface{}, plan *containerRegistryModel) {
	if !plan.CompartmentIDs.IsNull() && !plan.CompartmentIDs.IsUnknown() {
		credentialDetails["compartment_ids"] = plan.CompartmentIDs.ValueString()
	}
	if !plan.CredentialPassword.IsNull() && !plan.CredentialPassword.IsUnknown() {
		credentialDetails["password"] = plan.CredentialPassword.ValueString()
	}
	if !plan.ScopeName.IsNull() && !plan.ScopeName.IsUnknown() {
		credentialDetails["scope_name"] = plan.ScopeName.ValueString()
	}
	if !plan.CredentialUsername.IsNull() && !plan.CredentialUsername.IsUnknown() {
		credentialDetails["username"] = plan.CredentialUsername.ValueString()
	}
}

// validateRegistryCredentials validates registry-specific required credentials.
func (r *containerRegistryResource) validateRegistryCredentials(registryType string, config *containerRegistryModel, resp *resource.ValidateConfigResponse) {
	switch registryType {
	case "ecr":
		r.validateECRCredentials(config, resp)
	case "dockerhub", "docker", "icr", "artifactory", "acr", "nexus", "openshift", "quay.io", "harbor":
		r.validateUsernamePasswordCredentials(config, resp, registryType)
	case "github", "gitlab":
		r.validateGitCredentials(config, resp, registryType)
	case "gar":
		r.validateGARCredentials(config, resp)
	case "gcr":
		r.validateGCRCredentials(config, resp)
	case "oracle":
		r.validateOracleCredentials(config, resp)
	case "mirantis":
		r.validateMirantisCredentials(config, resp)
	}
}

// validateECRCredentials validates AWS ECR specific credentials.
func (r *containerRegistryResource) validateECRCredentials(config *containerRegistryModel, resp *resource.ValidateConfigResponse) {
	if config.AWSIAMRole.IsNull() || config.AWSIAMRole.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("aws_iam_role"),
			"Missing required field for ECR registry",
			"aws_iam_role is required when type is 'ecr'",
		)
	}
	if config.AWSExternalID.IsNull() || config.AWSExternalID.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("aws_external_id"),
			"Missing required field for ECR registry",
			"aws_external_id is required when type is 'ecr'",
		)
	}
}

// validateUsernamePasswordCredentials validates username/password credentials.
func (r *containerRegistryResource) validateUsernamePasswordCredentials(config *containerRegistryModel, resp *resource.ValidateConfigResponse, registryType string) {
	if config.CredentialUsername.IsNull() || config.CredentialUsername.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("credential_username"),
			fmt.Sprintf("Missing required field for %s registry", registryType),
			fmt.Sprintf("credential_username is required when type is '%s'", registryType),
		)
	}
	if config.CredentialPassword.IsNull() || config.CredentialPassword.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("credential_password"),
			fmt.Sprintf("Missing required field for %s registry", registryType),
			fmt.Sprintf("credential_password is required when type is '%s'", registryType),
		)
	}
}

// validateGitCredentials validates GitHub/GitLab specific credentials.
func (r *containerRegistryResource) validateGitCredentials(config *containerRegistryModel, resp *resource.ValidateConfigResponse, registryType string) {
	if config.CredentialType.IsNull() || config.CredentialType.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("credential_type"),
			fmt.Sprintf("Missing required field for %s registry", registryType),
			fmt.Sprintf("credential_type is required when type is '%s'", registryType),
		)
	}
	if config.DomainURL.IsNull() || config.DomainURL.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("domain_url"),
			fmt.Sprintf("Missing required field for %s registry", registryType),
			fmt.Sprintf("domain_url is required when type is '%s'", registryType),
		)
	}
	if config.CredentialPassword.IsNull() || config.CredentialPassword.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("credential_password"),
			fmt.Sprintf("Missing required field for %s registry", registryType),
			fmt.Sprintf("credential_password (personal access token) is required when type is '%s'", registryType),
		)
	}
	if config.CredentialUsername.IsNull() || config.CredentialUsername.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("credential_username"),
			fmt.Sprintf("Missing required field for %s registry", registryType),
			fmt.Sprintf("credential_username is required when type is '%s'", registryType),
		)
	}
}

// validateGARCredentials validates Google Artifact Registry specific credentials.
func (r *containerRegistryResource) validateGARCredentials(config *containerRegistryModel, resp *resource.ValidateConfigResponse) {
	if config.ProjectID.IsNull() || config.ProjectID.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("project_id"),
			"Missing required field for Google Artifact Registry",
			"project_id is required when type is 'gar'",
		)
	}
	if config.ScopeName.IsNull() || config.ScopeName.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("scope_name"),
			"Missing required field for Google Artifact Registry",
			"scope_name is required when type is 'gar'",
		)
	}
	if config.ServiceAccountJSON.IsNull() || config.ServiceAccountJSON.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("service_account_json"),
			"Missing required field for Google Artifact Registry",
			"service_account_json is required when type is 'gar'",
		)
	}
}

// validateGCRCredentials validates Google Container Registry specific credentials.
func (r *containerRegistryResource) validateGCRCredentials(config *containerRegistryModel, resp *resource.ValidateConfigResponse) {
	if config.ProjectID.IsNull() || config.ProjectID.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("project_id"),
			"Missing required field for Google Container Registry",
			"project_id is required when type is 'gcr'",
		)
	}
	if config.ServiceAccountJSON.IsNull() || config.ServiceAccountJSON.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("service_account_json"),
			"Missing required field for Google Container Registry",
			"service_account_json is required when type is 'gcr'",
		)
	}
}

// validateOracleCredentials validates Oracle Container Registry specific credentials.
func (r *containerRegistryResource) validateOracleCredentials(config *containerRegistryModel, resp *resource.ValidateConfigResponse) {
	if config.CompartmentIDs.IsNull() || config.CompartmentIDs.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("compartment_ids"),
			"Missing required field for Oracle Container Registry",
			"compartment_ids is required when type is 'oracle'",
		)
	}
	if config.CredentialPassword.IsNull() || config.CredentialPassword.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("credential_password"),
			"Missing required field for Oracle Container Registry",
			"credential_password is required when type is 'oracle'",
		)
	}
	if config.ScopeName.IsNull() || config.ScopeName.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("scope_name"),
			"Missing required field for Oracle Container Registry",
			"scope_name is required when type is 'oracle'",
		)
	}
	if config.CredentialUsername.IsNull() || config.CredentialUsername.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("credential_username"),
			"Missing required field for Oracle Container Registry",
			"credential_username (tenancy email) is required when type is 'oracle'",
		)
	}
}

// validateMirantisCredentials validates Mirantis registry specific credentials.
func (r *containerRegistryResource) validateMirantisCredentials(config *containerRegistryModel, resp *resource.ValidateConfigResponse) {
	if config.CredentialUsername.IsNull() || config.CredentialUsername.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("credential_username"),
			"Missing required field for Mirantis registry",
			"credential_username is required when type is 'mirantis'",
		)
	}
	if config.CredentialPassword.IsNull() || config.CredentialPassword.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("credential_password"),
			"Missing required field for Mirantis registry",
			"credential_password is required when type is 'mirantis'",
		)
	}
}

// updateModelFromRegistry updates the Terraform model with data from the API response.
func (r *containerRegistryResource) updateModelFromRegistry(
	model *containerRegistryModel,
	registry *models.DomainExternalAPIRegistry,
) {
	// Use the common mapping function for shared fields
	common := mapCommonRegistryFields(registry)

	model.ID = common.ID
	model.Type = common.Type
	model.URL = common.URL
	model.UserDefinedAlias = common.UserDefinedAlias
	model.RefreshInterval = common.RefreshInterval
	model.LastRefreshedAt = common.LastRefreshedAt
	model.NextRefreshAt = common.NextRefreshAt
	model.State = common.State
	model.StateChangedAt = common.StateChangedAt
	model.CreatedAt = common.CreatedAt
	model.UpdatedAt = common.UpdatedAt
	model.CredentialExpired = common.CredentialExpired
	model.CredentialExpiredAt = common.CredentialExpiredAt
	model.CredentialCreatedAt = common.CredentialCreatedAt
	model.CredentialUpdatedAt = common.CredentialUpdatedAt

	// Note: Resource-specific fields like credentials are kept as-is in the model
	// since they come from user input, not from the API response
}
