package containerregistry

import (
	"context"
	"errors"
	"fmt"
	"strings"

	goopenapiruntime "github.com/go-openapi/runtime"

	"github.com/crowdstrike/gofalcon/falcon/client"
	fci "github.com/crowdstrike/gofalcon/falcon/client/falcon_container_image"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                   = &containerRegistryResource{}
	_ resource.ResourceWithConfigure      = &containerRegistryResource{}
	_ resource.ResourceWithImportState    = &containerRegistryResource{}
	_ resource.ResourceWithValidateConfig = &containerRegistryResource{}
)

var apiScopesReadWrite = []scopes.Scope{
	{Name: "Falcon Container Image", Read: true, Write: true},
}

var apiScopesRead = []scopes.Scope{
	{Name: "Falcon Container Image", Read: true, Write: false},
}

var registryTypes = []string{
	"acr", "artifactory", "docker", "dockerhub", "ecr",
	"gar", "gcr", "github", "gitlab", "harbor",
	"icr", "mirantis", "nexus", "openshift", "oracle", "quay.io",
}

func NewContainerRegistryResource() resource.Resource {
	return &containerRegistryResource{}
}

type containerRegistryResource struct {
	client *client.CrowdStrikeAPISpecification
}

type serviceAccountJSONModel struct {
	Type         types.String `tfsdk:"type"`
	PrivateKeyID types.String `tfsdk:"private_key_id"`
	PrivateKey   types.String `tfsdk:"private_key"`
	ClientEmail  types.String `tfsdk:"client_email"`
	ClientID     types.String `tfsdk:"client_id"`
	ProjectID    types.String `tfsdk:"project_id"`
}

var serviceAccountJSONAttrTypes = map[string]attr.Type{
	"type":           types.StringType,
	"private_key_id": types.StringType,
	"private_key":    types.StringType,
	"client_email":   types.StringType,
	"client_id":      types.StringType,
	"project_id":     types.StringType,
}

type credentialModel struct {
	Username                  types.String `tfsdk:"username"`
	Password                  types.String `tfsdk:"password"`
	AWSIAMRole                types.String `tfsdk:"aws_iam_role"`
	AWSExternalID             types.String `tfsdk:"aws_external_id"`
	AWSGovUsingCommercialConn types.Bool   `tfsdk:"aws_gov_using_commercial_connection"`
	DomainURL                 types.String `tfsdk:"domain_url"`
	CredentialType            types.String `tfsdk:"credential_type"`
	ProjectID                 types.String `tfsdk:"project_id"`
	ScopeName                 types.String `tfsdk:"scope_name"`
	Cert                      types.String `tfsdk:"cert"`
	AuthType                  types.String `tfsdk:"auth_type"`
	TenantID                  types.String `tfsdk:"tenant_id"`
	Client                    types.String `tfsdk:"client"`
	CompartmentIDs            types.Set    `tfsdk:"compartment_ids"`
	ServiceAccountJSON        types.Object `tfsdk:"service_account_json"`
	CredentialID              types.String `tfsdk:"credential_id"`
	CredentialExpired         types.Bool   `tfsdk:"credential_expired"`
	CredentialExpiredAt       types.String `tfsdk:"credential_expired_at"`
	CredentialCreatedAt       types.String `tfsdk:"credential_created_at"`
	CredentialUpdatedAt       types.String `tfsdk:"credential_updated_at"`
}

var credentialAttrTypes = map[string]attr.Type{
	"username":                            types.StringType,
	"password":                            types.StringType,
	"aws_iam_role":                        types.StringType,
	"aws_external_id":                     types.StringType,
	"aws_gov_using_commercial_connection": types.BoolType,
	"domain_url":                          types.StringType,
	"credential_type":                     types.StringType,
	"project_id":                          types.StringType,
	"scope_name":                          types.StringType,
	"cert":                                types.StringType,
	"auth_type":                           types.StringType,
	"tenant_id":                           types.StringType,
	"client":                              types.StringType,
	"compartment_ids":                     types.SetType{ElemType: types.StringType},
	"service_account_json":                types.ObjectType{AttrTypes: serviceAccountJSONAttrTypes},
	"credential_id":                       types.StringType,
	"credential_expired":                  types.BoolType,
	"credential_expired_at":               types.StringType,
	"credential_created_at":               types.StringType,
	"credential_updated_at":               types.StringType,
}

type containerRegistryResourceModel struct {
	ID                 types.String `tfsdk:"id"`
	LastUpdated        types.String `tfsdk:"last_updated"`
	URL                types.String `tfsdk:"url"`
	Type               types.String `tfsdk:"type"`
	UserDefinedAlias   types.String `tfsdk:"user_defined_alias"`
	URLUniquenessKey   types.String `tfsdk:"url_uniqueness_key"`
	CreatedAt          types.String `tfsdk:"created_at"`
	UpdatedAt          types.String `tfsdk:"updated_at"`
	State              types.String `tfsdk:"state"`
	StateChangedAt     types.String `tfsdk:"state_changed_at"`
	LastRefreshedAt    types.String `tfsdk:"last_refreshed_at"`
	NextRefreshAt      types.String `tfsdk:"next_refresh_at"`
	RefreshInterval    types.Int32  `tfsdk:"refresh_interval"`
	URLUniquenessAlias types.String `tfsdk:"url_uniqueness_alias"`
	Credential         types.Object `tfsdk:"credential"`
}

func (r *containerRegistryResource) Configure(
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

func (r *containerRegistryResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_container_registry"
}

func credentialSchemaAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"username": schema.StringAttribute{
			Optional:    true,
			Description: "Username for authentication. Required for: dockerhub, docker, github, gitlab, icr, artifactory, acr (password auth), mirantis, oracle, openshift, quay.io, nexus, harbor.",
			Validators:  []validator.String{fwvalidators.StringNotWhitespace()},
		},
		"password": schema.StringAttribute{
			Optional:    true,
			Sensitive:   true,
			Description: "Password, API key, or access token. Required for: dockerhub, docker, github, gitlab, icr, artifactory, acr (password auth), mirantis, oracle, openshift, quay.io, nexus, harbor.",
			Validators:  []validator.String{fwvalidators.StringNotWhitespace()},
		},
		"aws_iam_role": schema.StringAttribute{
			Optional:    true,
			Description: "AWS IAM role ARN. Required for: ecr.",
			Validators:  []validator.String{fwvalidators.StringNotWhitespace()},
		},
		"aws_external_id": schema.StringAttribute{
			Optional:    true,
			Description: "AWS external ID. Required for: ecr.",
			Validators:  []validator.String{fwvalidators.StringNotWhitespace()},
		},
		"aws_gov_using_commercial_connection": schema.BoolAttribute{
			Optional:    true,
			Computed:    true,
			Description: "Whether AWS GovCloud uses commercial connection. Optional for: ecr.",
			Default:     booldefault.StaticBool(false),
		},
		"domain_url": schema.StringAttribute{
			Optional:    true,
			Description: "Domain URL for API access. Required for: github, gitlab.",
			Validators:  []validator.String{fwvalidators.StringNotWhitespace()},
		},
		"credential_type": schema.StringAttribute{
			Optional:    true,
			Description: "Type of credential. Required for: github, gitlab. Valid value: PAT.",
			Validators:  []validator.String{stringvalidator.OneOf("PAT")},
		},
		"project_id": schema.StringAttribute{
			Optional:    true,
			Description: "GCP project ID. Required for: gar, gcr.",
			Validators:  []validator.String{fwvalidators.StringNotWhitespace()},
		},
		"scope_name": schema.StringAttribute{
			Optional:    true,
			Description: "Scope name. Required for: gar, oracle.",
			Validators:  []validator.String{fwvalidators.StringNotWhitespace()},
		},
		"cert": schema.StringAttribute{
			Optional:    true,
			Sensitive:   true,
			Description: "Azure service principal certificate as base64-encoded PEM. Required for: acr (certificate auth).",
			Validators:  []validator.String{fwvalidators.StringNotWhitespace()},
		},
		"auth_type": schema.StringAttribute{
			Optional:    true,
			Description: "Authentication type. Required for: acr (certificate auth). Valid value: cert.",
			Validators:  []validator.String{stringvalidator.OneOf("cert")},
		},
		"tenant_id": schema.StringAttribute{
			Optional:    true,
			Description: "Azure tenant ID. Required for: acr (certificate auth).",
			Validators:  []validator.String{fwvalidators.StringNotWhitespace()},
		},
		"client": schema.StringAttribute{
			Optional:    true,
			Description: "Azure client ID. Required for: acr (certificate auth).",
			Validators:  []validator.String{fwvalidators.StringNotWhitespace()},
		},
		"compartment_ids": schema.SetAttribute{
			ElementType: types.StringType,
			Optional:    true,
			Description: "Oracle compartment IDs. Required for: oracle.",
			Validators: []validator.Set{
				setvalidator.ValueStringsAre(fwvalidators.StringNotWhitespace()),
			},
		},
		"service_account_json": schema.SingleNestedAttribute{
			Optional:    true,
			Description: "GCP service account JSON. Required for: gar, gcr.",
			Attributes: map[string]schema.Attribute{
				"type": schema.StringAttribute{
					Optional:    true,
					Description: "Service account type. Typically service_account.",
					Validators:  []validator.String{fwvalidators.StringNotWhitespace()},
				},
				"private_key_id": schema.StringAttribute{
					Optional:    true,
					Description: "Private key ID.",
					Validators:  []validator.String{fwvalidators.StringNotWhitespace()},
				},
				"private_key": schema.StringAttribute{
					Optional:    true,
					Sensitive:   true,
					Description: "Private key.",
					Validators:  []validator.String{fwvalidators.StringNotWhitespace()},
				},
				"client_email": schema.StringAttribute{
					Optional:    true,
					Description: "Client email.",
					Validators:  []validator.String{fwvalidators.StringIsEmailAddress()},
				},
				"client_id": schema.StringAttribute{
					Optional:    true,
					Description: "Client ID.",
					Validators:  []validator.String{fwvalidators.StringNotWhitespace()},
				},
				"project_id": schema.StringAttribute{
					Optional:    true,
					Description: "Project ID.",
					Validators:  []validator.String{fwvalidators.StringNotWhitespace()},
				},
			},
		},
		"credential_id": schema.StringAttribute{
			Computed:    true,
			Description: "The ID of the credential.",
		},
		"credential_expired": schema.BoolAttribute{
			Computed:    true,
			Description: "Whether the credential has expired.",
		},
		"credential_expired_at": schema.StringAttribute{
			Computed:    true,
			Description: "Timestamp when the credential expired.",
		},
		"credential_created_at": schema.StringAttribute{
			Computed:    true,
			Description: "Timestamp when the credential was created.",
		},
		"credential_updated_at": schema.StringAttribute{
			Computed:    true,
			Description: "Timestamp when the credential was last updated.",
		},
	}
}

func (r *containerRegistryResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Falcon Container Image",
			"Manages container registry connections in CrowdStrike Falcon Container Security. This resource allows you to connect container registries for image scanning and vulnerability assessment.",
			apiScopesReadWrite,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The UUID of the registry entity.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the last Terraform update of the resource.",
			},
			"url": schema.StringAttribute{
				Required:    true,
				Description: "The URL of the container registry.",
				Validators:  []validator.String{fwvalidators.StringNotWhitespace()},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"type": schema.StringAttribute{
				Required:    true,
				Description: fmt.Sprintf("The type of container registry. Must be one of: %s.", formatRegistryTypes()),
				Validators:  []validator.String{stringvalidator.OneOf(registryTypes...)},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"user_defined_alias": schema.StringAttribute{
				Optional:    true,
				Description: "A user-defined friendly name for the registry.",
				Validators:  []validator.String{fwvalidators.StringNotWhitespace()},
			},
			"url_uniqueness_key": schema.StringAttribute{
				Optional:    true,
				Description: "A unique key for registries where multiple accounts can use the same URL (e.g., Docker Hub, Google registries).",
				Validators:  []validator.String{fwvalidators.StringNotWhitespace()},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when the registry was created.",
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when the registry was last updated.",
			},
			"state": schema.StringAttribute{
				Computed:    true,
				Description: "The current state of the registry entity.",
			},
			"state_changed_at": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when the state last changed.",
			},
			"last_refreshed_at": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when the registry was last refreshed.",
			},
			"next_refresh_at": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when the registry will be refreshed next.",
			},
			"refresh_interval": schema.Int32Attribute{
				Computed:    true,
				Description: "The refresh interval in seconds.",
			},
			"url_uniqueness_alias": schema.StringAttribute{
				Computed:    true,
				Description: "System-generated URL uniqueness alias.",
			},
			"credential": schema.SingleNestedAttribute{
				Required:    true,
				Description: "The credentials for accessing the registry. Required fields depend on the registry type.",
				Attributes:  credentialSchemaAttributes(),
			},
		},
	}
}

func (r *containerRegistryResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan containerRegistryResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	credDetails, diags := expandCredentialDetails(ctx, plan.Credential)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	body := &models.RegistryassessmentExternalRegistryPayload{
		URL:              plan.URL.ValueStringPointer(),
		Type:             plan.Type.ValueStringPointer(),
		URLUniquenessKey: plan.URLUniquenessKey.ValueString(),
		UserDefinedAlias: plan.UserDefinedAlias.ValueString(),
		Credential: &models.RegistryassessmentExternalCredPayload{
			Details: credDetails,
		},
	}

	res, err := r.client.FalconContainerImage.CreateRegistryEntities(
		fci.NewCreateRegistryEntitiesParams().WithContext(ctx).WithBody(body),
	)

	// gofalcon expects 201 but the API may return 200, which is treated as an unexpected error.
	// In that case, fall through to findRegistryByURL to locate the created entity.
	var apiErr *goopenapiruntime.APIError
	if err != nil && !(errors.As(err, &apiErr) && apiErr.Code == 200) {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Create, err, apiScopesReadWrite))
		return
	}

	if err == nil {
		if res == nil || res.Payload == nil {
			resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
			return
		}

		if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Create, res.Payload.Errors); diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}
	}

	if res == nil || res.Payload == nil || res.Payload.Resources == nil {
		// The API returns 200 (treated as error by gofalcon) or null resources. Find the created entity by URL.
		registry, diags := r.findRegistryByURL(ctx, plan.URL.ValueString(), plan.Type.ValueString(), plan.UserDefinedAlias.ValueString())
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		if registry == nil {
			resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
			return
		}
		resp.Diagnostics.Append(plan.wrap(ctx, registry)...)
		if resp.Diagnostics.HasError() {
			return
		}
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
		if resp.Diagnostics.HasError() {
			return
		}
		plan.LastUpdated = utils.GenerateUpdateTimestamp()
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, res.Payload.Resources)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *containerRegistryResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state containerRegistryResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	res, err := r.client.FalconContainerImage.ReadRegistryEntitiesByUUID(
		fci.NewReadRegistryEntitiesByUUIDParams().WithContext(ctx).WithIds(state.ID.ValueString()),
	)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, apiScopesReadWrite)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			tflog.Warn(ctx, "registry entity not found, removing from state", map[string]interface{}{"id": state.ID.ValueString()})
			resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		tflog.Warn(ctx, "registry entity not found, removing from state", map[string]interface{}{"id": state.ID.ValueString()})
		resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
		resp.State.RemoveResource(ctx)
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, res.Payload.Resources[0])...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *containerRegistryResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan containerRegistryResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	credDetails, diags := expandCredentialDetails(ctx, plan.Credential)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	body := &models.RegistryassessmentExternalRegistryPatchPayload{
		UserDefinedAlias: plan.UserDefinedAlias.ValueString(),
		Credential: &models.APICredPayload{
			Type:    plan.Type.ValueStringPointer(),
			Details: credDetails,
		},
	}

	res, err := r.client.FalconContainerImage.UpdateRegistryEntities(
		fci.NewUpdateRegistryEntitiesParams().WithContext(ctx).WithID(plan.ID.ValueString()).WithBody(body),
	)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopesReadWrite))
		return
	}

	if res == nil || res.Payload == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Update, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	if res.Payload.Resources == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, res.Payload.Resources)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *containerRegistryResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state containerRegistryResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	res, err := r.client.FalconContainerImage.DeleteRegistryEntities(
		fci.NewDeleteRegistryEntitiesParams().WithContext(ctx).WithIds(state.ID.ValueString()),
	)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, apiScopesReadWrite)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}

	if res != nil && res.Payload != nil {
		if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Delete, res.Payload.Errors); diag != nil {
			resp.Diagnostics.Append(diag)
		}
	}
}

func (r *containerRegistryResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *containerRegistryResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var cfg containerRegistryResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if cfg.Type.IsNull() || cfg.Type.IsUnknown() {
		return
	}
	if cfg.Credential.IsNull() || cfg.Credential.IsUnknown() {
		return
	}

	var cred credentialModel
	resp.Diagnostics.Append(cfg.Credential.As(ctx, &cred, basetypes.ObjectAsOptions{})...)
	if resp.Diagnostics.HasError() {
		return
	}

	registryType := cfg.Type.ValueString()
	credPath := path.Root("credential")

	switch registryType {
	case "ecr":
		requireStringField(&resp.Diagnostics, credPath.AtName("aws_iam_role"), cred.AWSIAMRole, "aws_iam_role", registryType)
		requireStringField(&resp.Diagnostics, credPath.AtName("aws_external_id"), cred.AWSExternalID, "aws_external_id", registryType)
	case "dockerhub", "docker", "icr", "mirantis", "harbor", "artifactory", "nexus", "openshift", "quay.io":
		requireStringField(&resp.Diagnostics, credPath.AtName("username"), cred.Username, "username", registryType)
		requireStringField(&resp.Diagnostics, credPath.AtName("password"), cred.Password, "password", registryType)
	case "github", "gitlab":
		requireStringField(&resp.Diagnostics, credPath.AtName("username"), cred.Username, "username", registryType)
		requireStringField(&resp.Diagnostics, credPath.AtName("password"), cred.Password, "password", registryType)
		requireStringField(&resp.Diagnostics, credPath.AtName("domain_url"), cred.DomainURL, "domain_url", registryType)
		requireStringField(&resp.Diagnostics, credPath.AtName("credential_type"), cred.CredentialType, "credential_type", registryType)
	case "gar":
		requireStringField(&resp.Diagnostics, credPath.AtName("project_id"), cred.ProjectID, "project_id", registryType)
		requireStringField(&resp.Diagnostics, credPath.AtName("scope_name"), cred.ScopeName, "scope_name", registryType)
		requireObjectField(&resp.Diagnostics, credPath.AtName("service_account_json"), cred.ServiceAccountJSON, "service_account_json", registryType)
	case "gcr":
		requireStringField(&resp.Diagnostics, credPath.AtName("project_id"), cred.ProjectID, "project_id", registryType)
		requireObjectField(&resp.Diagnostics, credPath.AtName("service_account_json"), cred.ServiceAccountJSON, "service_account_json", registryType)
	case "acr":
		hasCert := !cred.Cert.IsNull() && !cred.Cert.IsUnknown() && cred.Cert.ValueString() != ""
		hasPassword := !cred.Password.IsNull() && !cred.Password.IsUnknown() && cred.Password.ValueString() != ""
		if hasCert {
			requireStringField(&resp.Diagnostics, credPath.AtName("auth_type"), cred.AuthType, "auth_type", registryType)
			requireStringField(&resp.Diagnostics, credPath.AtName("tenant_id"), cred.TenantID, "tenant_id", registryType)
			requireStringField(&resp.Diagnostics, credPath.AtName("client"), cred.Client, "client", registryType)
		} else if hasPassword {
			requireStringField(&resp.Diagnostics, credPath.AtName("username"), cred.Username, "username", registryType)
		} else {
			resp.Diagnostics.AddAttributeError(
				credPath,
				"Invalid Credential for acr",
				"For acr registry type, either (username + password) or (cert + auth_type + tenant_id + client) must be provided.",
			)
		}
	case "oracle":
		requireStringField(&resp.Diagnostics, credPath.AtName("username"), cred.Username, "username", registryType)
		requireStringField(&resp.Diagnostics, credPath.AtName("password"), cred.Password, "password", registryType)
		requireStringField(&resp.Diagnostics, credPath.AtName("scope_name"), cred.ScopeName, "scope_name", registryType)
		if cred.CompartmentIDs.IsNull() || cred.CompartmentIDs.IsUnknown() || len(cred.CompartmentIDs.Elements()) == 0 {
			resp.Diagnostics.AddAttributeError(
				credPath.AtName("compartment_ids"),
				"Missing Required Field",
				fmt.Sprintf("compartment_ids is required for %s registry type and must not be empty.", registryType),
			)
		}
	}
}

func requireStringField(diags *diag.Diagnostics, attrPath path.Path, val types.String, fieldName, registryType string) {
	if val.IsNull() || val.IsUnknown() || val.ValueString() == "" {
		diags.AddAttributeError(
			attrPath,
			"Missing Required Field",
			fmt.Sprintf("%s is required for %s registry type.", fieldName, registryType),
		)
	}
}

func requireObjectField(diags *diag.Diagnostics, attrPath path.Path, val types.Object, fieldName, registryType string) {
	if val.IsNull() || val.IsUnknown() {
		diags.AddAttributeError(
			attrPath,
			"Missing Required Field",
			fmt.Sprintf("%s is required for %s registry type.", fieldName, registryType),
		)
	}
}

// wrap converts the API response to the Terraform model, preserving
// credential input fields (write-only from the API's perspective).
func (m *containerRegistryResourceModel) wrap(
	ctx context.Context,
	apiRegistry *models.DomainExternalAPIRegistry,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = flex.StringPointerToFramework(apiRegistry.ID)
	m.URL = flex.StringPointerToFramework(apiRegistry.URL)
	m.Type = flex.StringPointerToFramework(apiRegistry.Type)
	m.UserDefinedAlias = flex.StringPointerToFramework(apiRegistry.UserDefinedAlias)
	m.URLUniquenessAlias = flex.StringPointerToFramework(apiRegistry.URLUniquenessAlias)
	m.CreatedAt = flex.StringPointerToFramework(apiRegistry.CreatedAt)
	m.UpdatedAt = flex.StringPointerToFramework(apiRegistry.UpdatedAt)
	m.State = flex.StringPointerToFramework(apiRegistry.State)
	m.StateChangedAt = flex.StringPointerToFramework(apiRegistry.StateChangedAt)
	m.LastRefreshedAt = flex.StringPointerToFramework(apiRegistry.LastRefreshedAt)
	m.NextRefreshAt = flex.StringPointerToFramework(apiRegistry.NextRefreshAt)
	m.RefreshInterval = flex.Int32PointerToFramework(apiRegistry.RefreshInterval)

	// Merge computed credential fields from API response while preserving input fields.
	existingCred := credentialModel{
		CompartmentIDs:     types.SetValueMust(types.StringType, []attr.Value{}),
		ServiceAccountJSON: types.ObjectNull(serviceAccountJSONAttrTypes),
	}
	if !m.Credential.IsNull() && !m.Credential.IsUnknown() {
		diags.Append(m.Credential.As(ctx, &existingCred, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return diags
		}
	}

	if apiRegistry.Credential != nil {
		existingCred.CredentialID = flex.StringPointerToFramework(apiRegistry.Credential.ID)
		existingCred.CredentialExpired = types.BoolPointerValue(apiRegistry.Credential.Expired)
		existingCred.CredentialExpiredAt = flex.StringPointerToFramework(apiRegistry.Credential.ExpiredAt)
		existingCred.CredentialCreatedAt = flex.StringPointerToFramework(apiRegistry.Credential.CreatedAt)
		existingCred.CredentialUpdatedAt = flex.StringPointerToFramework(apiRegistry.Credential.UpdatedAt)
	}

	credObj, credDiags := types.ObjectValueFrom(ctx, credentialAttrTypes, existingCred)
	diags.Append(credDiags...)
	if diags.HasError() {
		return diags
	}
	m.Credential = credObj

	return diags
}

// expandCredentialDetails builds the credential details map to send to the API.
func expandCredentialDetails(ctx context.Context, credObj types.Object) (map[string]interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics

	var cred credentialModel
	diags.Append(credObj.As(ctx, &cred, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil, diags
	}

	details := map[string]interface{}{}

	if !cred.Username.IsNull() && !cred.Username.IsUnknown() {
		details["username"] = cred.Username.ValueString()
	}
	if !cred.Password.IsNull() && !cred.Password.IsUnknown() {
		details["password"] = cred.Password.ValueString()
	}
	if !cred.AWSIAMRole.IsNull() && !cred.AWSIAMRole.IsUnknown() {
		details["aws_iam_role"] = cred.AWSIAMRole.ValueString()
	}
	if !cred.AWSExternalID.IsNull() && !cred.AWSExternalID.IsUnknown() {
		details["aws_external_id"] = cred.AWSExternalID.ValueString()
	}
	if !cred.AWSGovUsingCommercialConn.IsNull() && !cred.AWSGovUsingCommercialConn.IsUnknown() {
		details["aws_gov_using_commercial_connection"] = cred.AWSGovUsingCommercialConn.ValueBool()
	}
	if !cred.DomainURL.IsNull() && !cred.DomainURL.IsUnknown() {
		details["domain_url"] = cred.DomainURL.ValueString()
	}
	if !cred.CredentialType.IsNull() && !cred.CredentialType.IsUnknown() {
		details["credential_type"] = cred.CredentialType.ValueString()
	}
	if !cred.ProjectID.IsNull() && !cred.ProjectID.IsUnknown() {
		details["project_id"] = cred.ProjectID.ValueString()
	}
	if !cred.ScopeName.IsNull() && !cred.ScopeName.IsUnknown() {
		details["scope_name"] = cred.ScopeName.ValueString()
	}
	if !cred.Cert.IsNull() && !cred.Cert.IsUnknown() {
		details["cert"] = cred.Cert.ValueString()
	}
	if !cred.AuthType.IsNull() && !cred.AuthType.IsUnknown() {
		details["auth_type"] = cred.AuthType.ValueString()
	}
	if !cred.TenantID.IsNull() && !cred.TenantID.IsUnknown() {
		details["tenant_id"] = cred.TenantID.ValueString()
	}
	if !cred.Client.IsNull() && !cred.Client.IsUnknown() {
		details["client"] = cred.Client.ValueString()
	}
	if !cred.CompartmentIDs.IsNull() && !cred.CompartmentIDs.IsUnknown() {
		var ids []string
		diags.Append(cred.CompartmentIDs.ElementsAs(ctx, &ids, false)...)
		if !diags.HasError() {
			details["compartment_ids"] = ids
		}
	}
	if !cred.ServiceAccountJSON.IsNull() && !cred.ServiceAccountJSON.IsUnknown() {
		var sa serviceAccountJSONModel
		diags.Append(cred.ServiceAccountJSON.As(ctx, &sa, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			saMap := map[string]interface{}{}
			if !sa.Type.IsNull() && !sa.Type.IsUnknown() {
				saMap["type"] = sa.Type.ValueString()
			}
			if !sa.PrivateKeyID.IsNull() && !sa.PrivateKeyID.IsUnknown() {
				saMap["private_key_id"] = sa.PrivateKeyID.ValueString()
			}
			if !sa.PrivateKey.IsNull() && !sa.PrivateKey.IsUnknown() {
				saMap["private_key"] = sa.PrivateKey.ValueString()
			}
			if !sa.ClientEmail.IsNull() && !sa.ClientEmail.IsUnknown() {
				saMap["client_email"] = sa.ClientEmail.ValueString()
			}
			if !sa.ClientID.IsNull() && !sa.ClientID.IsUnknown() {
				saMap["client_id"] = sa.ClientID.ValueString()
			}
			if !sa.ProjectID.IsNull() && !sa.ProjectID.IsUnknown() {
				saMap["project_id"] = sa.ProjectID.ValueString()
			}
			details["service_account_json"] = saMap
		}
	}

	return details, diags
}

// findRegistryByURL searches all registry entities for one matching the given URL.
// If userDefinedAlias is set, it is used as an additional filter to disambiguate registries
// with the same URL (e.g. multiple Docker Hub accounts). Falls back to URL-only matching
// and returns the most recently created entry.
// Used when the Create API returns 200 with null resources.
// Note: url_uniqueness_key is not returned by the API so cannot be used for matching.
func (r *containerRegistryResource) findRegistryByURL(
	ctx context.Context,
	url string,
	registryType string,
	userDefinedAlias string,
) (*models.DomainExternalAPIRegistry, diag.Diagnostics) {
	var diags diag.Diagnostics

	listRes, err := r.client.FalconContainerImage.ReadRegistryEntities(
		fci.NewReadRegistryEntitiesParams().WithContext(ctx),
	)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Create, err, apiScopesReadWrite))
		return nil, diags
	}
	if listRes == nil || listRes.Payload == nil {
		return nil, diags
	}

	// Iterate in reverse to prefer the most recently created entry when multiple match.
	ids := listRes.Payload.Resources
	var fallback *models.DomainExternalAPIRegistry
	for i := len(ids) - 1; i >= 0; i-- {
		id := ids[i]
		if id == "" {
			continue
		}
		entRes, err := r.client.FalconContainerImage.ReadRegistryEntitiesByUUID(
			fci.NewReadRegistryEntitiesByUUIDParams().WithContext(ctx).WithIds(id),
		)
		if err != nil || entRes == nil || entRes.Payload == nil || len(entRes.Payload.Resources) == 0 || entRes.Payload.Resources[0] == nil {
			continue
		}
		reg := entRes.Payload.Resources[0]
		if reg.URL == nil || *reg.URL != url {
			continue
		}
		if reg.Type == nil || *reg.Type != registryType {
			continue
		}
		if userDefinedAlias != "" && reg.UserDefinedAlias != nil && *reg.UserDefinedAlias == userDefinedAlias {
			return reg, diags
		}
		if fallback == nil {
			fallback = reg
		}
	}

	return fallback, diags
}

func formatRegistryTypes() string {
	quoted := make([]string, len(registryTypes))
	for i, t := range registryTypes {
		quoted[i] = "`" + t + "`"
	}
	return strings.Join(quoted, ", ")
}
