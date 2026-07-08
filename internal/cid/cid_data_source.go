package cid

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_download"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const (
	dataSourceDocumentationSection = "Host Setup and Management"
	dataSourceMarkdownDescription  = "Returns the Customer ID (CID) and Customer ID Checksum (CCID) for the Falcon tenant authenticated by the provider."
)

var dataSourceApiScopes = []scopes.Scope{
	{Name: "Sensor Download", Read: true, Write: false},
}

var (
	_ datasource.DataSource              = &cidDataSource{}
	_ datasource.DataSourceWithConfigure = &cidDataSource{}
)

type cidDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type cidDataSourceModel struct {
	CCID types.String `tfsdk:"ccid"`
	CID  types.String `tfsdk:"cid"`
}

func NewCIDDataSource() datasource.DataSource {
	return &cidDataSource{}
}

func (d *cidDataSource) Configure(
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

func (d *cidDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cid"
}

func (d *cidDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			dataSourceDocumentationSection,
			dataSourceMarkdownDescription,
			dataSourceApiScopes,
		),
		Attributes: map[string]schema.Attribute{
			"ccid": schema.StringAttribute{
				Computed:    true,
				Description: "Customer ID Checksum. A 32-character CID followed by a 2-character checksum suffix in the form 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX-YY'. Returned verbatim from the API.",
			},
			"cid": schema.StringAttribute{
				Computed:    true,
				Description: "The 32-character Customer ID. Derived from 'ccid' by removing the '-YY' checksum suffix and lowercasing.",
			},
		},
	}
}

func (d *cidDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data cidDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := sensor_download.NewGetSensorInstallersCCIDByQueryParamsWithContext(ctx)
	res, err := d.client.SensorDownload.GetSensorInstallersCCIDByQuery(params)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Read, err, dataSourceApiScopes,
		))
		return
	}

	if res == nil || res.Payload == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	if len(res.Payload.Resources) == 0 {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return
	}

	ccid := res.Payload.Resources[0]
	data.CCID = types.StringValue(ccid)
	data.CID = types.StringValue(stripChecksum(ccid))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func stripChecksum(ccid string) string {
	idx := strings.LastIndex(ccid, "-")
	if idx < 0 {
		return strings.ToLower(ccid)
	}
	return strings.ToLower(ccid[:idx])
}
