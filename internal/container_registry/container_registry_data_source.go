package containerregistry

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	fci "github.com/crowdstrike/gofalcon/falcon/client/falcon_container_image"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &containerRegistryDataSource{}
	_ datasource.DataSourceWithConfigure = &containerRegistryDataSource{}
)

var apiScopesRead = []scopes.Scope{
	{Name: "Falcon Container Image", Read: true, Write: false},
}

func NewContainerRegistryDataSource() datasource.DataSource {
	return &containerRegistryDataSource{}
}

type containerRegistryDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type containerRegistryDataSourceModel struct {
	ID                  types.String      `tfsdk:"id"`
	URL                 types.String      `tfsdk:"url"`
	Type                types.String      `tfsdk:"type"`
	UserDefinedAlias    types.String      `tfsdk:"user_defined_alias"`
	URLUniquenessAlias  types.String      `tfsdk:"url_uniqueness_alias"`
	CreatedAt           timetypes.RFC3339 `tfsdk:"created_at"`
	UpdatedAt           timetypes.RFC3339 `tfsdk:"updated_at"`
	State               types.String      `tfsdk:"state"`
	StateChangedAt      timetypes.RFC3339 `tfsdk:"state_changed_at"`
	LastRefreshedAt     timetypes.RFC3339 `tfsdk:"last_refreshed_at"`
	NextRefreshAt       timetypes.RFC3339 `tfsdk:"next_refresh_at"`
	RefreshInterval     types.Int32       `tfsdk:"refresh_interval"`
	CredentialID        types.String      `tfsdk:"credential_id"`
	CredentialExpired   types.Bool        `tfsdk:"credential_expired"`
	CredentialExpiredAt timetypes.RFC3339 `tfsdk:"credential_expired_at"`
	CredentialCreatedAt timetypes.RFC3339 `tfsdk:"credential_created_at"`
	CredentialUpdatedAt timetypes.RFC3339 `tfsdk:"credential_updated_at"`
}

func (d *containerRegistryDataSource) Configure(
	_ context.Context,
	req datasource.ConfigureRequest,
	resp *datasource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	providerConfig, ok := req.ProviderData.(config.ProviderConfig)
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

	d.client = providerConfig.Client
}

func (d *containerRegistryDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_container_registry"
}

func (d *containerRegistryDataSource) Schema(
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
				Required:            true,
				MarkdownDescription: "The UUID of the registry entity.",
			},
			"user_defined_alias": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "A user-defined friendly name for the registry.",
			},
			"url": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The URL of the container registry.",
			},
			"type": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The type of container registry.",
			},
			"url_uniqueness_alias": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "System-generated URL uniqueness alias.",
			},
			"created_at": schema.StringAttribute{
				CustomType:          timetypes.RFC3339Type{},
				Computed:            true,
				MarkdownDescription: "Timestamp when the registry was created.",
			},
			"updated_at": schema.StringAttribute{
				CustomType:          timetypes.RFC3339Type{},
				Computed:            true,
				MarkdownDescription: "Timestamp when the registry was last updated.",
			},
			"state": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The current state of the registry entity.",
			},
			"state_changed_at": schema.StringAttribute{
				CustomType:          timetypes.RFC3339Type{},
				Computed:            true,
				MarkdownDescription: "Timestamp when the state last changed.",
			},
			"last_refreshed_at": schema.StringAttribute{
				CustomType:          timetypes.RFC3339Type{},
				Computed:            true,
				MarkdownDescription: "Timestamp when the registry was last refreshed.",
			},
			"next_refresh_at": schema.StringAttribute{
				CustomType:          timetypes.RFC3339Type{},
				Computed:            true,
				MarkdownDescription: "Timestamp when the registry will be refreshed next.",
			},
			"refresh_interval": schema.Int32Attribute{
				Computed:            true,
				MarkdownDescription: "The refresh interval in seconds.",
			},
			"credential_id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The ID of the credential.",
			},
			"credential_expired": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether the credential has expired.",
			},
			"credential_expired_at": schema.StringAttribute{
				CustomType:          timetypes.RFC3339Type{},
				Computed:            true,
				MarkdownDescription: "Timestamp when the credential expired.",
			},
			"credential_created_at": schema.StringAttribute{
				CustomType:          timetypes.RFC3339Type{},
				Computed:            true,
				MarkdownDescription: "Timestamp when the credential was created.",
			},
			"credential_updated_at": schema.StringAttribute{
				CustomType:          timetypes.RFC3339Type{},
				Computed:            true,
				MarkdownDescription: "Timestamp when the credential was last updated.",
			},
		},
	}
}

func (d *containerRegistryDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var state containerRegistryDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	res, err := d.client.FalconContainerImage.ReadRegistryEntitiesByUUID(
		fci.NewReadRegistryEntitiesByUUIDParams().WithContext(ctx).WithIds(state.ID.ValueString()),
	)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, apiScopesRead)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			tflog.Warn(ctx, "registry entity not found", map[string]interface{}{"id": state.ID.ValueString()})
			resp.Diagnostics.Append(tferrors.NewNotFoundError(
				fmt.Sprintf("No container registry found with ID %q.", state.ID.ValueString()),
			))
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewNotFoundError(
			fmt.Sprintf("No container registry found with ID %q.", state.ID.ValueString()),
		))
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	reg := res.Payload.Resources[0]
	state.ID = flex.StringPointerToFramework(reg.ID)
	state.URL = flex.StringPointerToFramework(reg.URL)
	state.Type = flex.StringPointerToFramework(reg.Type)
	state.UserDefinedAlias = flex.StringPointerToFramework(reg.UserDefinedAlias)
	state.URLUniquenessAlias = flex.StringPointerToFramework(reg.URLUniquenessAlias)
	state.State = flex.StringPointerToFramework(reg.State)
	state.RefreshInterval = flex.Int32PointerToFramework(reg.RefreshInterval)

	state.CreatedAt, resp.Diagnostics = appendRFC3339(resp.Diagnostics, reg.CreatedAt)
	state.UpdatedAt, resp.Diagnostics = appendRFC3339(resp.Diagnostics, reg.UpdatedAt)
	state.StateChangedAt, resp.Diagnostics = appendRFC3339(resp.Diagnostics, reg.StateChangedAt)
	state.LastRefreshedAt, resp.Diagnostics = appendRFC3339(resp.Diagnostics, reg.LastRefreshedAt)
	state.NextRefreshAt, resp.Diagnostics = appendRFC3339(resp.Diagnostics, reg.NextRefreshAt)

	if reg.Credential != nil {
		state.CredentialID = flex.StringPointerToFramework(reg.Credential.ID)
		state.CredentialExpired = types.BoolPointerValue(reg.Credential.Expired)
		state.CredentialExpiredAt, resp.Diagnostics = appendRFC3339(resp.Diagnostics, reg.Credential.ExpiredAt)
		state.CredentialCreatedAt, resp.Diagnostics = appendRFC3339(resp.Diagnostics, reg.Credential.CreatedAt)
		state.CredentialUpdatedAt, resp.Diagnostics = appendRFC3339(resp.Diagnostics, reg.Credential.UpdatedAt)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
