package falconcontainerimage

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/falcon_container_image"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var apiScopesRead = []scopes.Scope{
	{
		Name:  "Falcon Container Image",
		Read:  true,
		Write: false,
	},
}

var (
	_ datasource.DataSource              = &falconContainerImageDataSource{}
	_ datasource.DataSourceWithConfigure = &falconContainerImageDataSource{}
)

type falconContainerImageDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type falconContainerImageDataSourceModel struct {
	ID                     types.String `tfsdk:"id"`
	URL                    types.String `tfsdk:"url"`
	Type                   types.String `tfsdk:"type"`
	UserDefinedAlias       types.String `tfsdk:"user_defined_alias"`
	URLUniquenessAlias     types.String `tfsdk:"url_uniqueness_alias"`
	State                  types.String `tfsdk:"state"`
	CreatedAt              types.String `tfsdk:"created_at"`
	UpdatedAt              types.String `tfsdk:"updated_at"`
	LastRefreshedAt        types.String `tfsdk:"last_refreshed_at"`
	NextRefreshAt          types.String `tfsdk:"next_refresh_at"`
	StateChangedAt         types.String `tfsdk:"state_changed_at"`
	RefreshInterval        types.Int64  `tfsdk:"refresh_interval"`
	CredentialID           types.String `tfsdk:"credential_id"`
	CredentialExpired      types.Bool   `tfsdk:"credential_expired"`
	CredentialExpiredAt    types.String `tfsdk:"credential_expired_at"`
	CredentialCreatedAt    types.String `tfsdk:"credential_created_at"`
	CredentialUpdatedAt    types.String `tfsdk:"credential_updated_at"`
}

func NewFalconContainerImageDataSource() datasource.DataSource {
	return &falconContainerImageDataSource{}
}

func (d *falconContainerImageDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_falcon_container_image"
}

func (d *falconContainerImageDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Falcon Container Image",
			"Retrieves information about a container registry connection in CrowdStrike Falcon Container Security.",
			apiScopesRead,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required:    true,
				Description: "The UUID of the registry entity to query.",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
			},
			"url": schema.StringAttribute{
				Computed:    true,
				Description: "The URL of the container registry.",
			},
			"type": schema.StringAttribute{
				Computed:    true,
				Description: "The type of container registry.",
			},
			"user_defined_alias": schema.StringAttribute{
				Computed:    true,
				Description: "User-defined friendly name for the registry.",
			},
			"url_uniqueness_alias": schema.StringAttribute{
				Computed:    true,
				Description: "System-generated URL uniqueness alias.",
			},
			"state": schema.StringAttribute{
				Computed:    true,
				Description: "The current state of the registry entity.",
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
			"refresh_interval": schema.Int64Attribute{
				Computed:    true,
				Description: "The refresh interval in seconds.",
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
	}
}

func (d *falconContainerImageDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data falconContainerImageDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	registryID := data.ID.ValueString()

	tflog.Debug(ctx, "Reading falcon container image registry", map[string]interface{}{
		"id": registryID,
	})

	params := falcon_container_image.NewReadRegistryEntitiesByUUIDParams().WithContext(ctx)
	params.SetIds(registryID)

	response, err := d.client.FalconContainerImage.ReadRegistryEntitiesByUUID(params)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewOperationError(tferrors.Read, err))
		return
	}

	if response == nil || response.Payload == nil {
		resp.Diagnostics.AddError(
			"Invalid API Response",
			"Received nil response from API",
		)
		return
	}

	payload := response.GetPayload()

	if err := falcon.AssertNoError(payload.Errors); err != nil {
		resp.Diagnostics.Append(tferrors.NewOperationError(tferrors.Read, err))
		return
	}

	if len(payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Registry Not Found",
			fmt.Sprintf("Registry with ID %s not found", registryID),
		)
		return
	}

	registry := payload.Resources[0]

	diags := data.wrap(ctx, registry)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (d *falconContainerImageDataSource) Configure(
	_ context.Context,
	req datasource.ConfigureRequest,
	resp *datasource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	cfg, ok := req.ProviderData.(config.ProviderConfig)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf(
				"Expected config.ProviderConfig, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)
		return
	}

	d.client = cfg.Client
}

func (m *falconContainerImageDataSourceModel) wrap(
	_ context.Context,
	registry *models.DomainExternalAPIRegistry,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringPointerValue(registry.ID)
	m.URL = types.StringPointerValue(registry.URL)
	m.Type = types.StringPointerValue(registry.Type)
	m.UserDefinedAlias = types.StringPointerValue(registry.UserDefinedAlias)
	m.URLUniquenessAlias = types.StringPointerValue(registry.URLUniquenessAlias)
	m.State = types.StringPointerValue(registry.State)
	m.CreatedAt = types.StringPointerValue(registry.CreatedAt)
	m.UpdatedAt = types.StringPointerValue(registry.UpdatedAt)
	m.LastRefreshedAt = types.StringPointerValue(registry.LastRefreshedAt)
	m.NextRefreshAt = types.StringPointerValue(registry.NextRefreshAt)
	m.StateChangedAt = types.StringPointerValue(registry.StateChangedAt)

	if registry.RefreshInterval != nil {
		m.RefreshInterval = types.Int64Value(int64(*registry.RefreshInterval))
	}

	if registry.Credential != nil {
		m.CredentialID = types.StringPointerValue(registry.Credential.ID)
		m.CredentialExpired = types.BoolPointerValue(registry.Credential.Expired)
		m.CredentialExpiredAt = types.StringPointerValue(registry.Credential.ExpiredAt)
		m.CredentialCreatedAt = types.StringPointerValue(registry.Credential.CreatedAt)
		m.CredentialUpdatedAt = types.StringPointerValue(registry.Credential.UpdatedAt)
	}

	return diags
}
