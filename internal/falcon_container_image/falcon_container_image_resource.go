package falconcontainerimage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/falcon_container_image"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/runtime"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
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
	Username                        types.String `tfsdk:"username"`
	Password                        types.String `tfsdk:"password"`
	AWSIAMRole                      types.String `tfsdk:"aws_iam_role"`
	AWSExternalID                   types.String `tfsdk:"aws_external_id"`
	AWSGovUsingCommercialConnection types.Bool   `tfsdk:"aws_gov_using_commercial_connection"`
	DomainURL                       types.String `tfsdk:"domain_url"`
	CredentialType                  types.String `tfsdk:"credential_type"`
	ProjectID                       types.String `tfsdk:"project_id"`
	ScopeName                       types.String `tfsdk:"scope_name"`
	Cert                            types.String `tfsdk:"cert"`
	AuthType                        types.String `tfsdk:"auth_type"`
	TenantID                        types.String `tfsdk:"tenant_id"`
	Client                          types.String `tfsdk:"client"`
	CompartmentIDs                  types.Set    `tfsdk:"compartment_ids"`
	ServiceAccountJSON              types.Object `tfsdk:"service_account_json"`
	CredentialID                    types.String `tfsdk:"credential_id"`
	CredentialExpired               types.Bool   `tfsdk:"credential_expired"`
	CredentialExpiredAt             types.String `tfsdk:"credential_expired_at"`
	CredentialCreatedAt             types.String `tfsdk:"credential_created_at"`
	CredentialUpdatedAt             types.String `tfsdk:"credential_updated_at"`
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
				Computed:    true,
				Description: "A user-defined friendly name for the registry. When omitted, Terraform retains the value returned by the API. Once set, this value can be updated but not cleared via Terraform due to API limitations.",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
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
								Required:    true,
								Description: "Service account type. Typically `service_account`.",
								Validators: []validator.String{
									validators.StringNotWhitespace(),
								},
							},
							"private_key_id": schema.StringAttribute{
								Required:    true,
								Description: "Private key ID.",
								Validators: []validator.String{
									validators.StringNotWhitespace(),
								},
							},
							"private_key": schema.StringAttribute{
								Required:    true,
								Sensitive:   true,
								Description: "Private key.",
								Validators: []validator.String{
									validators.StringNotWhitespace(),
								},
							},
							"client_email": schema.StringAttribute{
								Required:    true,
								Description: "Client email.",
								Validators: []validator.String{
									validators.StringIsEmailAddress(),
								},
							},
							"client_id": schema.StringAttribute{
								Required:    true,
								Description: "Client ID.",
								Validators: []validator.String{
									validators.StringNotWhitespace(),
								},
							},
							"project_id": schema.StringAttribute{
								Required:    true,
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
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.UseStateForUnknown(),
						},
					},
					"credential_expired": schema.BoolAttribute{
						Computed:    true,
						Description: "Whether the credential has expired.",
						PlanModifiers: []planmodifier.Bool{
							boolplanmodifier.UseStateForUnknown(),
						},
					},
					"credential_expired_at": schema.StringAttribute{
						Computed:    true,
						Description: "Timestamp when the credential expired.",
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.UseStateForUnknown(),
						},
					},
					"credential_created_at": schema.StringAttribute{
						Computed:    true,
						Description: "Timestamp when the credential was created.",
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.UseStateForUnknown(),
						},
					},
					"credential_updated_at": schema.StringAttribute{
						Computed:    true,
						Description: "Timestamp when the credential was last updated.",
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.UseStateForUnknown(),
						},
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

	providerConfig, ok := req.ProviderData.(config.ProviderConfig)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected config.ProviderConfig, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = providerConfig.Client
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

	// Retry the create up to maxAttempts times. A 400 "failed to validate registry
	// credential" is transient for ECR when an IAM role has just been created and
	// hasn't propagated across AWS yet; sleeping between attempts gives it time to
	// settle. For all other registry types the error is permanent (bad credentials)
	// so we skip retrying entirely.
	const (
		maxAttempts   = 5
		retryInterval = 15 * time.Second
	)
	ecrRetryEnabled := plan.Type.ValueString() == "ecr"

	var (
		res          *falcon_container_image.CreateRegistryEntitiesCreated
		lastErr      error
		credValError bool
	)
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		res, lastErr = r.client.FalconContainerImage.CreateRegistryEntities(params)
		if lastErr == nil {
			break
		}
		credValError = isCredentialValidationError(lastErr)
		if !credValError || !ecrRetryEnabled || attempt == maxAttempts {
			break
		}
		tflog.Debug(ctx, "registry credential validation failed, retrying after IAM propagation delay",
			map[string]any{
				"attempt":  attempt,
				"max":      maxAttempts,
				"delay_ms": retryInterval.Milliseconds(),
				"url":      plan.URL.ValueString(),
			})
		select {
		case <-ctx.Done():
			resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Create, ctx.Err(), apiScopesReadWrite))
			return
		case <-time.After(retryInterval):
		}
	}

	if lastErr != nil {
		// After exhausting retries, check whether CrowdStrike may have persisted the
		// record despite the error (async validation) or if a duplicate already exists
		// (status 200 with empty body from a previous failed apply).
		if credValError || isUnrecognized200Error(lastErr) {
			registry, findErr := r.findRegistryByURL(ctx, plan.URL.ValueString(), plan.URLUniquenessKey.ValueString())
			if findErr == nil && registry != nil {
				resp.Diagnostics.AddWarning(
					"Registry Created with Credential Validation Pending",
					"The registry was created but CrowdStrike reported a credential validation issue. "+
						"This is expected when IAM roles have not yet fully propagated. "+
						"The resource has been saved to state; CrowdStrike will retry validation automatically.",
				)
				plan.ID = types.StringValue(*registry.ID)
				resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
				if resp.Diagnostics.HasError() {
					return
				}
				resp.Diagnostics.Append(plan.wrap(ctx, registry)...)
				resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
				return
			}
		}
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Create, lastErr, apiScopesReadWrite))
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

	if res.Payload.Resources.ID == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}
	plan.ID = types.StringValue(*res.Payload.Resources.ID)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "created falcon container image registry", map[string]any{
		"id":   plan.ID.ValueString(),
		"url":  plan.URL.ValueString(),
		"type": plan.Type.ValueString(),
	})

	registry := res.Payload.Resources
	resp.Diagnostics.Append(plan.wrap(ctx, registry)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// isCredentialValidationError returns true for 400 responses where CrowdStrike
// reports that it cannot validate the registry credential. This is a transient
// error when the underlying IAM role has been created but not yet propagated.
func isCredentialValidationError(err error) bool {
	if err == nil {
		return false
	}
	// Fast path: check the structured payload when available.
	type badRequestPayload interface {
		GetPayload() *models.DomainExternalRegistryResponse
	}
	if brErr, ok := err.(badRequestPayload); ok {
		if payload := brErr.GetPayload(); payload != nil {
			for _, e := range payload.Errors {
				if e != nil && e.Message != nil && strings.Contains(*e.Message, "failed to validate registry credential") {
					return true
				}
			}
		}
	}
	// Fallback: match against err.Error(), which prints the API *response* body via
	// fmt.Sprintf("%+v", payload) — it contains only CrowdStrike's error fields, not
	// any credential data from the request. This covers cases where the errors slice
	// is empty but the message appears elsewhere in the response, or where the
	// transport wraps the error before returning it.
	return strings.Contains(err.Error(), "failed to validate registry credential")
}

// isUnrecognized200Error returns true for HTTP 200 responses that fall into the
// swagger default case (not a defined response code for this endpoint). CrowdStrike
// returns 200 with an empty body when a duplicate URL is submitted, indicating the
// registry already exists.
func isUnrecognized200Error(err error) bool {
	if err == nil {
		return false
	}
	apiErr, ok := err.(*runtime.APIError)
	return ok && apiErr.Code == 200
}

// findRegistryByURL scans all registry entities to find one matching the given URL
// and, when non-empty, url_uniqueness_key. Returns nil if no match is found.
func (r *falconContainerImageResource) findRegistryByURL(
	ctx context.Context,
	targetURL string,
	urlUniquenessKey string,
) (*models.DomainExternalAPIRegistry, error) {
	const pageSize = int64(100)
	offset := int64(0)

	for {
		limit := pageSize
		listParams := falcon_container_image.NewReadRegistryEntitiesParams().
			WithContext(ctx).
			WithLimit(&limit).
			WithOffset(&offset)

		listRes, err := r.client.FalconContainerImage.ReadRegistryEntities(listParams)
		if err != nil {
			return nil, fmt.Errorf("listing registry entities: %w", err)
		}
		if listRes == nil || listRes.Payload == nil || len(listRes.Payload.Resources) == 0 {
			return nil, nil
		}

		for _, id := range listRes.Payload.Resources {
			byIDParams := falcon_container_image.NewReadRegistryEntitiesByUUIDParams().
				WithContext(ctx).
				WithIds(id)

			byIDRes, err := r.client.FalconContainerImage.ReadRegistryEntitiesByUUID(byIDParams)
			if err != nil {
				tflog.Debug(ctx, "findRegistryByURL: skipping ID that could not be fetched",
					map[string]any{"id": id, "error": err.Error()})
				continue
			}
			if byIDRes == nil || byIDRes.Payload == nil || len(byIDRes.Payload.Resources) == 0 {
				continue
			}

			reg := byIDRes.Payload.Resources[0]
			if reg == nil || reg.URL == nil || reg.ID == nil {
				continue
			}
			if *reg.URL != targetURL {
				continue
			}
			if urlUniquenessKey != "" {
				if reg.URLUniquenessAlias == nil || *reg.URLUniquenessAlias != urlUniquenessKey {
					continue
				}
			}
			return reg, nil
		}

		// Stop when we've received a partial page (no more results).
		if int64(len(listRes.Payload.Resources)) < pageSize {
			return nil, nil
		}
		offset += pageSize
	}
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
			tflog.Debug(ctx, "falcon container image registry not found, removing from state", map[string]any{"id": state.ID.ValueString()})
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		tflog.Debug(ctx, "falcon container image registry not found, removing from state", map[string]any{"id": state.ID.ValueString()})
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

	tflog.Debug(ctx, "updated falcon container image registry", map[string]any{
		"id":   state.ID.ValueString(),
		"url":  state.URL.ValueString(),
		"type": state.Type.ValueString(),
	})

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

	tflog.Debug(ctx, "deleting falcon container image registry", map[string]any{"id": state.ID.ValueString()})

	_, err := r.client.FalconContainerImage.DeleteRegistryEntities(params)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, apiScopesReadWrite)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			tflog.Debug(ctx, "falcon container image registry already deleted", map[string]any{"id": state.ID.ValueString()})
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
			var val attr.Value
			switch field {
			case "username":
				val = cred.Username
			case "password":
				val = cred.Password
			case "aws_iam_role":
				val = cred.AWSIAMRole
			case "aws_external_id":
				val = cred.AWSExternalID
			case "domain_url":
				val = cred.DomainURL
			case "credential_type":
				val = cred.CredentialType
			case "project_id":
				val = cred.ProjectID
			case "scope_name":
				val = cred.ScopeName
			case "cert":
				val = cred.Cert
			case "auth_type":
				val = cred.AuthType
			case "tenant_id":
				val = cred.TenantID
			case "client":
				val = cred.Client
			case "compartment_ids":
				val = cred.CompartmentIDs
			case "service_account_json":
				val = cred.ServiceAccountJSON
			}

			// Unknown means the value comes from another resource and will be
			// resolved at apply time — skip validation rather than error.
			if val == nil || val.IsUnknown() {
				continue
			}

			if val.IsNull() {
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
		// If any credential fields are unknown, skip ACR validation — values arrive at apply time.
		acrUnknown := cred.Username.IsUnknown() || cred.Password.IsUnknown() ||
			cred.Cert.IsUnknown() || cred.AuthType.IsUnknown() ||
			cred.TenantID.IsUnknown() || cred.Client.IsUnknown()
		if !acrUnknown {
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
		}

	case "oracle":
		validateCredentials([]string{"username", "password", "compartment_ids", "scope_name"})
		if utils.IsKnown(cred.CompartmentIDs) && len(cred.CompartmentIDs.Elements()) == 0 {
			resp.Diagnostics.AddAttributeError(
				path.Root("credential").AtName("compartment_ids"),
				"Missing Required Credential Field",
				`For registry type "oracle", compartment_ids must contain at least one compartment ID.`,
			)
		}
	}
}

func (m *falconContainerImageResourceModel) wrap(
	ctx context.Context,
	registry *models.DomainExternalAPIRegistry,
) diag.Diagnostics {
	var diags diag.Diagnostics

	// Preserve user-set fields the API does not return.
	existingURLUniquenessKey := m.URLUniquenessKey

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
			// Computed fields populated from API response.
			"credential_id":         types.StringPointerValue(registry.Credential.ID),
			"credential_expired":    types.BoolPointerValue(registry.Credential.Expired),
			"credential_expired_at": types.StringPointerValue(registry.Credential.ExpiredAt),
			"credential_created_at": types.StringPointerValue(registry.Credential.CreatedAt),
			"credential_updated_at": types.StringPointerValue(registry.Credential.UpdatedAt),
			// Write-only fields: initialized as null so types.ObjectValue always
			// receives all required keys. Overwritten below when state is available.
			"username":                            types.StringNull(),
			"password":                            types.StringNull(),
			"aws_iam_role":                        types.StringNull(),
			"aws_external_id":                     types.StringNull(),
			"aws_gov_using_commercial_connection": types.BoolNull(),
			"domain_url":                          types.StringNull(),
			"credential_type":                     types.StringNull(),
			"project_id":                          types.StringNull(),
			"scope_name":                          types.StringNull(),
			"cert":                                types.StringNull(),
			"auth_type":                           types.StringNull(),
			"tenant_id":                           types.StringNull(),
			"client":                              types.StringNull(),
			"compartment_ids":                     types.SetNull(types.StringType),
			"service_account_json":                types.ObjectNull(serviceAccountJSONAttrTypes()),
		}

		if !m.Credential.IsNull() {
			var existingCred credentialModel
			diags.Append(m.Credential.As(ctx, &existingCred, basetypes.ObjectAsOptions{})...)
			if !diags.HasError() {
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

	m.URLUniquenessKey = existingURLUniquenessKey

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
