package falconcontainerimage

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/falcon_container_image"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
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
)

var (
	_ resource.Resource                   = &falconContainerImageResource{}
	_ resource.ResourceWithConfigure      = &falconContainerImageResource{}
	_ resource.ResourceWithImportState    = &falconContainerImageResource{}
	_ resource.ResourceWithValidateConfig = &falconContainerImageResource{}
)

type falconContainerImageResource struct {
	client *client.CrowdStrikeAPISpecification
}

type falconContainerImageResourceModel struct {
	ID                 types.String `tfsdk:"id"`
	URL                types.String `tfsdk:"url"`
	Type               types.String `tfsdk:"type"`
	UserDefinedAlias   types.String `tfsdk:"user_defined_alias"`
	URLUniquenessKey   types.String `tfsdk:"url_uniqueness_key"`
	CreatedAt          types.String `tfsdk:"created_at"`
	UpdatedAt          types.String `tfsdk:"updated_at"`
	LastRefreshedAt    types.String `tfsdk:"last_refreshed_at"`
	NextRefreshAt      types.String `tfsdk:"next_refresh_at"`
	StateChangedAt     types.String `tfsdk:"state_changed_at"`
	State              types.String `tfsdk:"state"`
	RefreshInterval    types.Int64  `tfsdk:"refresh_interval"`
	URLUniquenessAlias types.String `tfsdk:"url_uniqueness_alias"`
	Credential         types.Object `tfsdk:"credential"`
}

type credentialModel struct {
	Username                         types.String `tfsdk:"username"`
	Password                         types.String `tfsdk:"password"`
	AWSIAMRole                       types.String `tfsdk:"aws_iam_role"`
	AWSExternalID                    types.String `tfsdk:"aws_external_id"`
	AWSGovUsingCommercialConnection  types.Bool   `tfsdk:"aws_gov_using_commercial_connection"`
	DomainURL                        types.String `tfsdk:"domain_url"`
	CredentialType                   types.String `tfsdk:"credential_type"`
	ProjectID                        types.String `tfsdk:"project_id"`
	ScopeName                        types.String `tfsdk:"scope_name"`
	Cert                             types.String `tfsdk:"cert"`
	AuthType                         types.String `tfsdk:"auth_type"`
	TenantID                         types.String `tfsdk:"tenant_id"`
	Client                           types.String `tfsdk:"client"`
	CompartmentIDs                   types.Set    `tfsdk:"compartment_ids"`
	ServiceAccountJSON               types.Object `tfsdk:"service_account_json"`
	CredentialID                     types.String `tfsdk:"credential_id"`
	CredentialExpired                types.Bool   `tfsdk:"credential_expired"`
	CredentialExpiredAt              types.String `tfsdk:"credential_expired_at"`
	CredentialCreatedAt              types.String `tfsdk:"credential_created_at"`
	CredentialUpdatedAt              types.String `tfsdk:"credential_updated_at"`
}

type serviceAccountJSONModel struct {
	Type         types.String `tfsdk:"type"`
	PrivateKeyID types.String `tfsdk:"private_key_id"`
	PrivateKey   types.String `tfsdk:"private_key"`
	ClientEmail  types.String `tfsdk:"client_email"`
	ClientID     types.String `tfsdk:"client_id"`
	ProjectID    types.String `tfsdk:"project_id"`
}

func NewFalconContainerImageResource() resource.Resource {
	return &falconContainerImageResource{}
}

func (r *falconContainerImageResource) Metadata(
	ctx context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_falcon_container_image"
}

func (r *falconContainerImageResource) Schema(
	ctx context.Context,
	req resource.SchemaRequest,
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
			"url": schema.StringAttribute{
				Required:    true,
				Description: "The URL of the container registry. Must match the format expected by the registry type.",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"type": schema.StringAttribute{
				Required:    true,
				Description: "The type of container registry. Must be one of: `acr`, `artifactory`, `docker`, `dockerhub`, `ecr`, `gar`, `gcr`, `github`, `gitlab`, `harbor`, `icr`, `mirantis`, `nexus`, `openshift`, `oracle`, `quay.io`.",
				Validators: []validator.String{
					stringvalidator.OneOf("acr", "artifactory", "docker", "dockerhub", "ecr", "gar", "gcr", "github", "gitlab", "harbor", "icr", "mirantis", "nexus", "openshift", "oracle", "quay.io"),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"user_defined_alias": schema.StringAttribute{
				Optional:    true,
				Description: "A user-defined friendly name for the registry.",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
			},
			"url_uniqueness_key": schema.StringAttribute{
				Optional:    true,
				Description: "A unique key for registries where multiple accounts can use the same URL (e.g., Docker Hub, Google registries).",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
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
			"last_refreshed_at": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when the registry was last refreshed.",
			},
			"next_refresh_at": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when the registry will be refreshed next.",
			},
			"state_changed_at": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when the state last changed.",
			},
			"state": schema.StringAttribute{
				Computed:    true,
				Description: "The current state of the registry entity.",
			},
			"refresh_interval": schema.Int64Attribute{
				Computed:    true,
				Description: "The refresh interval in seconds.",
			},
			"url_uniqueness_alias": schema.StringAttribute{
				Computed:    true,
				Description: "System-generated URL uniqueness alias.",
			},
			"credential": schema.SingleNestedAttribute{
				Required:    true,
				Description: "The credentials for accessing the registry.",
				Attributes: map[string]schema.Attribute{
					"username": schema.StringAttribute{
						Optional:    true,
						Description: "Username for authentication. Required for: `dockerhub`, `docker`, `github`, `gitlab`, `icr`, `artifactory`, `acr` (password auth), `mirantis`, `oracle`, `openshift`, `quay.io`, `nexus`, `harbor`.",
						Validators: []validator.String{
							validators.StringNotWhitespace(),
						},
					},
					"password": schema.StringAttribute{
						Optional:    true,
						Sensitive:   true,
						Description: "Password, API key, or access token. Required for: `dockerhub`, `docker`, `github`, `gitlab`, `icr`, `artifactory`, `acr` (password auth), `mirantis`, `oracle`, `openshift`, `quay.io`, `nexus`, `harbor`.",
						Validators: []validator.String{
							validators.StringNotWhitespace(),
						},
					},
					"aws_iam_role": schema.StringAttribute{
						Optional:    true,
						Description: "AWS IAM role ARN. Required for: `ecr`.",
						Validators: []validator.String{
							validators.StringNotWhitespace(),
						},
					},
					"aws_external_id": schema.StringAttribute{
						Optional:    true,
						Description: "AWS external ID. Required for: `ecr`.",
						Validators: []validator.String{
							validators.StringNotWhitespace(),
						},
					},
					"aws_gov_using_commercial_connection": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Whether AWS GovCloud uses commercial connection. Optional for: `ecr`.",
						Default:     booldefault.StaticBool(false),
					},
					"domain_url": schema.StringAttribute{
						Optional:    true,
						Description: "Domain URL for API access. Required for: `github`, `gitlab`.",
						Validators: []validator.String{
							validators.StringNotWhitespace(),
						},
					},
					"credential_type": schema.StringAttribute{
						Optional:    true,
						Description: "Type of credential. Required for: `github`, `gitlab`. Valid value: `PAT`.",
						Validators: []validator.String{
							stringvalidator.OneOf("PAT"),
						},
					},
					"project_id": schema.StringAttribute{
						Optional:    true,
						Description: "GCP project ID. Required for: `gar`, `gcr`.",
						Validators: []validator.String{
							validators.StringNotWhitespace(),
						},
					},
					"scope_name": schema.StringAttribute{
						Optional:    true,
						Description: "Scope name. Required for: `gar`, `oracle`.",
						Validators: []validator.String{
							validators.StringNotWhitespace(),
						},
					},
					"cert": schema.StringAttribute{
						Optional:    true,
						Sensitive:   true,
						Description: "Azure service principal certificate as base64-encoded PEM. Required for: `acr` (certificate auth).",
						Validators: []validator.String{
							validators.StringNotWhitespace(),
						},
					},
					"auth_type": schema.StringAttribute{
						Optional:    true,
						Description: "Authentication type. Required for: `acr` (certificate auth). Valid value: `cert`.",
						Validators: []validator.String{
							stringvalidator.OneOf("cert"),
						},
					},
					"tenant_id": schema.StringAttribute{
						Optional:    true,
						Description: "Azure tenant ID. Required for: `acr` (certificate auth).",
						Validators: []validator.String{
							validators.StringNotWhitespace(),
						},
					},
					"client": schema.StringAttribute{
						Optional:    true,
						Description: "Azure client ID. Required for: `acr` (certificate auth).",
						Validators: []validator.String{
							validators.StringNotWhitespace(),
						},
					},
					"compartment_ids": schema.SetAttribute{
						ElementType: types.StringType,
						Optional:    true,
						Description: "Oracle compartment IDs. Required for: `oracle`.",
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(validators.StringNotWhitespace()),
						},
					},
					"service_account_json": schema.SingleNestedAttribute{
						Optional:    true,
						Description: "GCP service account JSON. Required for: `gar`, `gcr`.",
						Attributes: map[string]schema.Attribute{
							"type": schema.StringAttribute{
								Optional:    true,
								Description: "Service account type. Typically `service_account`.",
								Validators: []validator.String{
									validators.StringNotWhitespace(),
								},
							},
							"private_key_id": schema.StringAttribute{
								Optional:    true,
								Description: "Private key ID.",
								Validators: []validator.String{
									validators.StringNotWhitespace(),
								},
							},
							"private_key": schema.StringAttribute{
								Optional:    true,
								Sensitive:   true,
								Description: "Private key.",
								Validators: []validator.String{
									validators.StringNotWhitespace(),
								},
							},
							"client_email": schema.StringAttribute{
								Optional:    true,
								Description: "Client email.",
								Validators: []validator.String{
									validators.StringIsEmailAddress(),
								},
							},
							"client_id": schema.StringAttribute{
								Optional:    true,
								Description: "Client ID.",
								Validators: []validator.String{
									validators.StringNotWhitespace(),
								},
							},
							"project_id": schema.StringAttribute{
								Optional:    true,
								Description: "Project ID.",
								Validators: []validator.String{
									validators.StringNotWhitespace(),
								},
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
				},
			},
		},
	}
}

func (r *falconContainerImageResource) Configure(
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
			"Expected *client.CrowdStrikeAPISpecification, got something else.",
		)
		return
	}

	r.client = client
}

func (r *falconContainerImageResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan falconContainerImageResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	credDetails, diags := buildCredentialDetails(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload := &models.RegistryassessmentExternalRegistryPayload{
		URL:  plan.URL.ValueStringPointer(),
		Type: plan.Type.ValueStringPointer(),
		Credential: &models.RegistryassessmentExternalCredPayload{
			Details: credDetails,
		},
	}

	if utils.IsKnown(plan.UserDefinedAlias) {
		payload.UserDefinedAlias = plan.UserDefinedAlias.ValueString()
	}
	if utils.IsKnown(plan.URLUniquenessKey) {
		payload.URLUniquenessKey = plan.URLUniquenessKey.ValueString()
	}

	params := falcon_container_image.NewCreateRegistryEntitiesParams().
		WithContext(ctx).
		WithBody(payload)

	res, err := r.client.FalconContainerImage.CreateRegistryEntities(params)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Create, err, apiScopesReadWrite))
		return
	}

	if res == nil || res.Payload == nil || res.Payload.Resources == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Create, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	registry := res.Payload.Resources
	resp.Diagnostics.Append(plan.wrap(ctx, registry)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *falconContainerImageResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state falconContainerImageResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := falcon_container_image.NewReadRegistryEntitiesByUUIDParams().
		WithContext(ctx).
		WithIds(state.ID.ValueString())

	res, err := r.client.FalconContainerImage.ReadRegistryEntitiesByUUID(params)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, apiScopesReadWrite)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	registry := res.Payload.Resources[0]
	resp.Diagnostics.Append(state.wrap(ctx, registry)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *falconContainerImageResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan, state falconContainerImageResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	credDetails, diags := buildCredentialDetails(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload := &models.RegistryassessmentExternalRegistryPatchPayload{
		Credential: &models.APICredPayload{
			Details: credDetails,
			Type:    state.Type.ValueStringPointer(),
		},
	}

	if utils.IsKnown(plan.UserDefinedAlias) {
		payload.UserDefinedAlias = plan.UserDefinedAlias.ValueString()
	}

	params := falcon_container_image.NewUpdateRegistryEntitiesParams().
		WithContext(ctx).
		WithID(state.ID.ValueString()).
		WithBody(payload)

	res, err := r.client.FalconContainerImage.UpdateRegistryEntities(params)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopesReadWrite))
		return
	}

	if res == nil || res.Payload == nil || res.Payload.Resources == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Update, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	registry := res.Payload.Resources
	resp.Diagnostics.Append(plan.wrap(ctx, registry)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *falconContainerImageResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state falconContainerImageResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := falcon_container_image.NewDeleteRegistryEntitiesParams().
		WithContext(ctx).
		WithIds(state.ID.ValueString())

	_, err := r.client.FalconContainerImage.DeleteRegistryEntities(params)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, apiScopesReadWrite)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(diag)
	}
}

func (r *falconContainerImageResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *falconContainerImageResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config falconContainerImageResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !utils.IsKnown(config.Type) || !utils.IsKnown(config.Credential) {
		return
	}

	registryType := config.Type.ValueString()

	var cred credentialModel
	resp.Diagnostics.Append(config.Credential.As(ctx, &cred, basetypes.ObjectAsOptions{})...)
	if resp.Diagnostics.HasError() {
		return
	}

	validateCredentials := func(required []string) {
		for _, field := range required {
			var isSet bool
			switch field {
			case "username":
				isSet = utils.IsKnown(cred.Username)
			case "password":
				isSet = utils.IsKnown(cred.Password)
			case "aws_iam_role":
				isSet = utils.IsKnown(cred.AWSIAMRole)
			case "aws_external_id":
				isSet = utils.IsKnown(cred.AWSExternalID)
			case "domain_url":
				isSet = utils.IsKnown(cred.DomainURL)
			case "credential_type":
				isSet = utils.IsKnown(cred.CredentialType)
			case "project_id":
				isSet = utils.IsKnown(cred.ProjectID)
			case "scope_name":
				isSet = utils.IsKnown(cred.ScopeName)
			case "cert":
				isSet = utils.IsKnown(cred.Cert)
			case "auth_type":
				isSet = utils.IsKnown(cred.AuthType)
			case "tenant_id":
				isSet = utils.IsKnown(cred.TenantID)
			case "client":
				isSet = utils.IsKnown(cred.Client)
			case "compartment_ids":
				isSet = utils.IsKnown(cred.CompartmentIDs)
			case "service_account_json":
				isSet = utils.IsKnown(cred.ServiceAccountJSON)
				if isSet {
					var sa serviceAccountJSONModel
					if d := cred.ServiceAccountJSON.As(ctx, &sa, basetypes.ObjectAsOptions{}); d.HasError() {
						resp.Diagnostics.Append(d...)
						return
					}
					if !utils.IsKnown(sa.Type) || !utils.IsKnown(sa.PrivateKeyID) ||
						!utils.IsKnown(sa.PrivateKey) || !utils.IsKnown(sa.ClientEmail) ||
						!utils.IsKnown(sa.ClientID) || !utils.IsKnown(sa.ProjectID) {
						resp.Diagnostics.AddAttributeError(
							path.Root("credential").AtName("service_account_json"),
							"Missing Required Service Account Fields",
							fmt.Sprintf("For registry type %q, all service_account_json fields (type, private_key_id, private_key, client_email, client_id, project_id) are required.", registryType),
						)
						return
					}
				}
			}

			if !isSet {
				resp.Diagnostics.AddAttributeError(
					path.Root("credential").AtName(field),
					"Missing Required Credential Field",
					fmt.Sprintf("For registry type %q, the field %q is required in credential details.", registryType, field),
				)
			}
		}
	}

	switch registryType {
	case "ecr":
		validateCredentials([]string{"aws_iam_role", "aws_external_id"})

	case "dockerhub", "docker", "icr", "mirantis", "harbor", "artifactory", "nexus", "openshift", "quay.io":
		validateCredentials([]string{"username", "password"})

	case "github", "gitlab":
		validateCredentials([]string{"username", "password", "domain_url", "credential_type"})

	case "gar":
		validateCredentials([]string{"project_id", "scope_name", "service_account_json"})

	case "gcr":
		validateCredentials([]string{"project_id", "service_account_json"})

	case "acr":
		hasUsernamePassword := utils.IsKnown(cred.Username) && utils.IsKnown(cred.Password)
		hasCertAuth := utils.IsKnown(cred.Cert) && utils.IsKnown(cred.AuthType) &&
			utils.IsKnown(cred.TenantID) && utils.IsKnown(cred.Client)

		if !hasUsernamePassword && !hasCertAuth {
			resp.Diagnostics.AddAttributeError(
				path.Root("credential"),
				"Invalid ACR Credentials",
				"For registry type \"acr\", either (username + password) OR (cert + auth_type + tenant_id + client) must be provided.",
			)
		}

	case "oracle":
		validateCredentials([]string{"username", "password", "compartment_ids", "scope_name"})
	}
}

func (m *falconContainerImageResourceModel) wrap(
	ctx context.Context,
	registry *models.DomainExternalAPIRegistry,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringPointerValue(registry.ID)
	m.URL = types.StringPointerValue(registry.URL)
	m.Type = types.StringPointerValue(registry.Type)
	m.UserDefinedAlias = types.StringPointerValue(registry.UserDefinedAlias)
	m.URLUniquenessAlias = types.StringPointerValue(registry.URLUniquenessAlias)
	m.CreatedAt = types.StringPointerValue(registry.CreatedAt)
	m.UpdatedAt = types.StringPointerValue(registry.UpdatedAt)
	m.LastRefreshedAt = types.StringPointerValue(registry.LastRefreshedAt)
	m.NextRefreshAt = types.StringPointerValue(registry.NextRefreshAt)
	m.StateChangedAt = types.StringPointerValue(registry.StateChangedAt)
	m.State = types.StringPointerValue(registry.State)

	if registry.RefreshInterval != nil {
		m.RefreshInterval = types.Int64Value(int64(*registry.RefreshInterval))
	}

	if registry.Credential != nil {
		credAttrTypes := credentialAttrTypes()
		credAttrs := map[string]attr.Value{
			"credential_id":         types.StringPointerValue(registry.Credential.ID),
			"credential_expired":    types.BoolPointerValue(registry.Credential.Expired),
			"credential_expired_at": types.StringPointerValue(registry.Credential.ExpiredAt),
			"credential_created_at": types.StringPointerValue(registry.Credential.CreatedAt),
			"credential_updated_at": types.StringPointerValue(registry.Credential.UpdatedAt),
		}

		if !m.Credential.IsNull() {
			var existingCred credentialModel
			if d := m.Credential.As(ctx, &existingCred, basetypes.ObjectAsOptions{}); !d.HasError() {
				credAttrs["username"] = existingCred.Username
				credAttrs["password"] = existingCred.Password
				credAttrs["aws_iam_role"] = existingCred.AWSIAMRole
				credAttrs["aws_external_id"] = existingCred.AWSExternalID
				credAttrs["aws_gov_using_commercial_connection"] = existingCred.AWSGovUsingCommercialConnection
				credAttrs["domain_url"] = existingCred.DomainURL
				credAttrs["credential_type"] = existingCred.CredentialType
				credAttrs["project_id"] = existingCred.ProjectID
				credAttrs["scope_name"] = existingCred.ScopeName
				credAttrs["cert"] = existingCred.Cert
				credAttrs["auth_type"] = existingCred.AuthType
				credAttrs["tenant_id"] = existingCred.TenantID
				credAttrs["client"] = existingCred.Client
				credAttrs["compartment_ids"] = existingCred.CompartmentIDs
				credAttrs["service_account_json"] = existingCred.ServiceAccountJSON
			}
		}

		credObj, d := types.ObjectValue(credAttrTypes, credAttrs)
		diags.Append(d...)
		m.Credential = credObj
	}

	return diags
}

func credentialAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
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
		"service_account_json":                types.ObjectType{AttrTypes: serviceAccountJSONAttrTypes()},
		"credential_id":                       types.StringType,
		"credential_expired":                  types.BoolType,
		"credential_expired_at":               types.StringType,
		"credential_created_at":               types.StringType,
		"credential_updated_at":               types.StringType,
	}
}

func serviceAccountJSONAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"type":           types.StringType,
		"private_key_id": types.StringType,
		"private_key":    types.StringType,
		"client_email":   types.StringType,
		"client_id":      types.StringType,
		"project_id":     types.StringType,
	}
}

func buildCredentialDetails(ctx context.Context, m *falconContainerImageResourceModel) (interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics

	var cred credentialModel
	diags.Append(m.Credential.As(ctx, &cred, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil, diags
	}

	result := make(map[string]interface{})

	if utils.IsKnown(cred.Username) {
		result["username"] = cred.Username.ValueString()
	}
	if utils.IsKnown(cred.Password) {
		result["password"] = cred.Password.ValueString()
	}
	if utils.IsKnown(cred.AWSIAMRole) {
		result["aws_iam_role"] = cred.AWSIAMRole.ValueString()
	}
	if utils.IsKnown(cred.AWSExternalID) {
		result["aws_external_id"] = cred.AWSExternalID.ValueString()
	}
	if utils.IsKnown(cred.AWSGovUsingCommercialConnection) {
		result["aws_gov_using_commercial_connection"] = cred.AWSGovUsingCommercialConnection.ValueBool()
	}
	if utils.IsKnown(cred.DomainURL) {
		result["domain_url"] = cred.DomainURL.ValueString()
	}
	if utils.IsKnown(cred.CredentialType) {
		result["credential_type"] = cred.CredentialType.ValueString()
	}
	if utils.IsKnown(cred.ProjectID) {
		result["project_id"] = cred.ProjectID.ValueString()
	}
	if utils.IsKnown(cred.ScopeName) {
		result["scope_name"] = cred.ScopeName.ValueString()
	}
	if utils.IsKnown(cred.Cert) {
		result["cert"] = cred.Cert.ValueString()
	}
	if utils.IsKnown(cred.AuthType) {
		result["auth_type"] = cred.AuthType.ValueString()
	}
	if utils.IsKnown(cred.TenantID) {
		result["tenant_id"] = cred.TenantID.ValueString()
	}
	if utils.IsKnown(cred.Client) {
		result["client"] = cred.Client.ValueString()
	}
	if utils.IsKnown(cred.CompartmentIDs) {
		var compartments []string
		diags.Append(cred.CompartmentIDs.ElementsAs(ctx, &compartments, false)...)
		if len(compartments) > 0 {
			result["compartment_ids"] = compartments
		}
	}
	if utils.IsKnown(cred.ServiceAccountJSON) {
		var sa serviceAccountJSONModel
		diags.Append(cred.ServiceAccountJSON.As(ctx, &sa, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			saMap := make(map[string]interface{})
			if utils.IsKnown(sa.Type) {
				saMap["type"] = sa.Type.ValueString()
			}
			if utils.IsKnown(sa.PrivateKeyID) {
				saMap["private_key_id"] = sa.PrivateKeyID.ValueString()
			}
			if utils.IsKnown(sa.PrivateKey) {
				saMap["private_key"] = sa.PrivateKey.ValueString()
			}
			if utils.IsKnown(sa.ClientEmail) {
				saMap["client_email"] = sa.ClientEmail.ValueString()
			}
			if utils.IsKnown(sa.ClientID) {
				saMap["client_id"] = sa.ClientID.ValueString()
			}
			if utils.IsKnown(sa.ProjectID) {
				saMap["project_id"] = sa.ProjectID.ValueString()
			}
			if len(saMap) > 0 {
				result["service_account_json"] = saMap
			}
		}
	}

	return result, diags
}
