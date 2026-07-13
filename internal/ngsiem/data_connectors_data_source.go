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
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &dataConnectorsDataSource{}
	_ datasource.DataSourceWithConfigure = &dataConnectorsDataSource{}
)

var dataConnectorsDataSourceScopes = []scopes.Scope{
	{
		Name: "NGSIEM Data Connections API",
		Read: true,
	},
}

// NewDataConnectorsDataSource creates a new instance of the connectors data source.
func NewDataConnectorsDataSource() datasource.DataSource {
	return &dataConnectorsDataSource{}
}

type dataConnectorsDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type dataConnectorModel struct {
	ID                types.String `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	Parsers           types.List   `tfsdk:"parsers"`
	Type              types.String `tfsdk:"type"`
	Description       types.String `tfsdk:"description"`
	VendorName        types.String `tfsdk:"vendor_name"`
	VendorProductName types.String `tfsdk:"vendor_product_name"`
	LogSources        types.List   `tfsdk:"log_sources"`
	Subscription      types.String `tfsdk:"subscription"`
}

func (m dataConnectorModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":                  types.StringType,
		"name":                types.StringType,
		"parsers":             types.ListType{ElemType: types.StringType},
		"type":                types.StringType,
		"description":         types.StringType,
		"vendor_name":         types.StringType,
		"vendor_product_name": types.StringType,
		"log_sources":         types.ListType{ElemType: types.StringType},
		"subscription":        types.StringType,
	}
}

type dataConnectorsDataSourceModel struct {
	Filter     types.String `tfsdk:"filter"`
	Connectors types.List   `tfsdk:"connectors"`
}

func (d *dataConnectorsDataSource) Configure(
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

func (d *dataConnectorsDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_ngsiem_data_connectors"
}

func (d *dataConnectorsDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Next-Gen SIEM",
			"Reads the NG-SIEM connector catalog and returns a list of connectors, each with its catalog ID, supported parsers, type, and vendor metadata. Supports an optional FQL filter.",
			dataConnectorsDataSourceScopes,
		),
		Attributes: map[string]schema.Attribute{
			"filter": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Optional [FQL](https://falcon.crowdstrike.com/documentation/page/abbd7b48/falcon-query-language-fql) filter to narrow the catalog. " +
					"Filterable fields: `type` (`PULL` or `PUSH`), `name`, `vendor_name`, `vendor_product_name`, and `subscription`. " +
					"Example: `type:'PULL'+vendor_name:'AmazonWebServices'`. If omitted, all connectors are returned.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"connectors": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The list of connectors in the catalog matching the filter.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The connector catalog ID.",
						},
						"name": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The connector name.",
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
				},
			},
		},
	}
}

func (d *dataConnectorsDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data dataConnectorsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var filter *string
	if utils.IsKnown(data.Filter) {
		f := data.Filter.ValueString()
		filter = &f
	}

	connectors, diags := d.fetchAllConnectors(ctx, filter)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	connectorModels := make([]dataConnectorModel, 0, len(connectors))
	for _, c := range connectors {
		if c == nil {
			continue
		}
		connectorModels = append(connectorModels, mapConnectorToDataModel(ctx, c, &resp.Diagnostics))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	data.Connectors = utils.SliceToListTypeObject(ctx, connectorModels, dataConnectorModel{}.AttributeTypes(), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// fetchAllConnectors pages through every connector matching the filter. The API
// may return fewer connectors per page than the reported total, so the read
// loops on Offset until it has collected all matching connectors.
func (d *dataConnectorsDataSource) fetchAllConnectors(
	ctx context.Context,
	filter *string,
) ([]*models.DataconnectionmanagementDataConnector, diag.Diagnostics) {
	var diags diag.Diagnostics
	var allConnectors []*models.DataconnectionmanagementDataConnector
	var offset int64

	for {
		params := &ngsiem.ExternalListDataConnectorsParams{
			Context: ctx,
			Offset:  &offset,
			Filter:  filter,
		}

		res, err := d.client.Ngsiem.ExternalListDataConnectors(params)
		if err != nil {
			diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, dataConnectorsDataSourceScopes))
			return nil, diags
		}

		if res == nil || res.Payload == nil {
			break
		}
		if d := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); d != nil {
			diags.Append(d)
			return nil, diags
		}

		pageCount := len(res.Payload.Resources)
		allConnectors = append(allConnectors, res.Payload.Resources...)

		var total int64
		if res.Payload.Meta != nil && res.Payload.Meta.Pagination != nil && res.Payload.Meta.Pagination.Total != nil {
			total = *res.Payload.Meta.Pagination.Total
		}

		tflog.Debug(ctx, "[datasource] Retrieved ngsiem connectors page",
			map[string]any{
				"page_count":  pageCount,
				"total_count": len(allConnectors),
				"total":       total,
			})

		// Stop when the page is empty (nothing more to fetch, and a guard
		// against a missing total) or once every reported connector for this
		// filter has been collected.
		if pageCount == 0 || (total > 0 && int64(len(allConnectors)) >= total) {
			break
		}
		offset += int64(pageCount)
	}

	return allConnectors, diags
}

func mapConnectorToDataModel(
	ctx context.Context,
	c *models.DataconnectionmanagementDataConnector,
	diags *diag.Diagnostics,
) dataConnectorModel {
	m := dataConnectorModel{
		ID:                flex.StringPointerToFramework(c.ID),
		Name:              flex.StringPointerToFramework(c.Name),
		Type:              flex.StringPointerToFramework(c.Type),
		Description:       flex.StringValueToFramework(c.Description),
		VendorName:        flex.StringPointerToFramework(c.VendorName),
		VendorProductName: flex.StringPointerToFramework(c.VendorProductName),
		Subscription:      flex.StringValueToFramework(c.Subscription),
	}

	parsers, parsersDiags := flex.FlattenStringValueList(ctx, c.Parsers)
	diags.Append(parsersDiags...)
	m.Parsers = parsers

	logSources, logSourcesDiags := flex.FlattenStringValueList(ctx, c.LogSources)
	diags.Append(logSourcesDiags...)
	m.LogSources = logSources

	return m
}
