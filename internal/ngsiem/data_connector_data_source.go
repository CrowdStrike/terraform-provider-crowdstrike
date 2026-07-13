package ngsiem

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ngsiem"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &dataConnectorDataSource{}
	_ datasource.DataSourceWithConfigure = &dataConnectorDataSource{}
)

const (
	dataConnectorDataSourceDocumentationSection = "Next-Gen SIEM"
	dataConnectorDataSourceMarkdownDescription  = "Reads a single NG-SIEM connector from the catalog by its exact name, returning its catalog ID, supported parsers, type, and vendor metadata."
)

var dataConnectorDataSourceApiScopes = []scopes.Scope{
	{Name: "NGSIEM Data Connections API", Read: true, Write: false},
}

// NewDataConnectorDataSource creates a new NG-SIEM connector data source.
func NewDataConnectorDataSource() datasource.DataSource {
	return &dataConnectorDataSource{}
}

type dataConnectorDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type dataConnectorDataSourceModel struct {
	Name              types.String `tfsdk:"name"`
	ID                types.String `tfsdk:"id"`
	Parsers           types.List   `tfsdk:"parsers"`
	Type              types.String `tfsdk:"type"`
	Description       types.String `tfsdk:"description"`
	VendorName        types.String `tfsdk:"vendor_name"`
	VendorProductName types.String `tfsdk:"vendor_product_name"`
	LogSources        types.List   `tfsdk:"log_sources"`
	Subscription      types.String `tfsdk:"subscription"`
}

func (m *dataConnectorDataSourceModel) wrap(
	ctx context.Context,
	connector models.DataconnectionmanagementDataConnector,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = flex.StringPointerToFramework(connector.ID)
	m.Name = flex.StringPointerToFramework(connector.Name)
	m.Type = flex.StringPointerToFramework(connector.Type)
	m.Description = flex.StringValueToFramework(connector.Description)
	m.VendorName = flex.StringPointerToFramework(connector.VendorName)
	m.VendorProductName = flex.StringPointerToFramework(connector.VendorProductName)
	m.Subscription = flex.StringValueToFramework(connector.Subscription)

	parsers, d := flex.FlattenStringValueList(ctx, connector.Parsers)
	diags.Append(d...)
	m.Parsers = parsers

	logSources, d := flex.FlattenStringValueList(ctx, connector.LogSources)
	diags.Append(d...)
	m.LogSources = logSources

	return diags
}

func (d *dataConnectorDataSource) Configure(
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

func (d *dataConnectorDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_ngsiem_data_connector"
}

func (d *dataConnectorDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			dataConnectorDataSourceDocumentationSection,
			dataConnectorDataSourceMarkdownDescription,
			dataConnectorDataSourceApiScopes,
		),
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The exact name of the connector to look up (case-sensitive), e.g. `Amazon S3 Access Log Data Connector`.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The connector catalog ID.",
			},
			"parsers": schema.ListAttribute{
				ElementType:         types.StringType,
				Computed:            true,
				MarkdownDescription: "All parsers the connector supports.",
			},
			"type": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The connector type (`PULL` or `PUSH`).",
			},
			"description": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The connector description.",
			},
			"vendor_name": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The vendor name (e.g. `AmazonWebServices`).",
			},
			"vendor_product_name": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The vendor product name (e.g. `Amazon S3 Access Logs`).",
			},
			"log_sources": schema.ListAttribute{
				ElementType:         types.StringType,
				Computed:            true,
				MarkdownDescription: "Log sources declared by the connector.",
			},
			"subscription": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The subscription the connector belongs to (e.g. `Next-Gen SIEM`).",
			},
		},
	}
}

func (d *dataConnectorDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var state dataConnectorDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := state.Name.ValueString()
	filter := fmt.Sprintf("name:'%s'", name)
	params := ngsiem.NewExternalListDataConnectorsParamsWithContext(ctx)
	params.SetFilter(&filter)

	res, err := d.client.Ngsiem.ExternalListDataConnectors(params)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Read, err, dataConnectorDataSourceApiScopes,
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

	matches := make([]*models.DataconnectionmanagementDataConnector, 0, len(res.Payload.Resources))
	for _, connector := range res.Payload.Resources {
		if connector == nil || connector.Name == nil {
			continue
		}
		if *connector.Name == name {
			matches = append(matches, connector)
		}
	}

	if len(matches) == 0 {
		resp.Diagnostics.AddError(
			"No connector found",
			fmt.Sprintf(
				"No NG-SIEM connector found with name %q. Names are matched case-sensitively.",
				name,
			),
		)
		return
	}

	if len(matches) > 1 {
		resp.Diagnostics.AddError(
			"Multiple connectors found",
			fmt.Sprintf(
				"Found %d NG-SIEM connectors matching name %q. Refine the name to match a single connector.",
				len(matches),
				name,
			),
		)
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, *matches[0])...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
