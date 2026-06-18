package ngsiemdataconnection

import (
	"context"
	"fmt"

	apiclient "github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &ngsiemDataConnectorsDataSource{}
	_ datasource.DataSourceWithConfigure = &ngsiemDataConnectorsDataSource{}
)

var dataSourceMarkdownDescription string = "List the available CrowdStrike Next-Gen SIEM data connectors, and optionally resolve a connector's ID by its exact name (for use as `connector_id` on a `crowdstrike_ngsiem_data_connection`)."

func NewNgsiemDataConnectorsDataSource() datasource.DataSource {
	return &ngsiemDataConnectorsDataSource{}
}

type ngsiemDataConnectorsDataSource struct {
	client *apiclient.CrowdStrikeAPISpecification
}

type ngsiemDataConnectorsDataSourceModel struct {
	ByName     types.String          `tfsdk:"by_name"`
	ID         types.String          `tfsdk:"id"`
	Connectors []connectorEntryModel `tfsdk:"connectors"`
}

type connectorEntryModel struct {
	ID                types.String `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	Type              types.String `tfsdk:"type"`
	Description       types.String `tfsdk:"description"`
	VendorName        types.String `tfsdk:"vendor_name"`
	VendorProductName types.String `tfsdk:"vendor_product_name"`
	Parsers           types.List   `tfsdk:"parsers"`
}

func (d *ngsiemDataConnectorsDataSource) Configure(
	ctx context.Context,
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

func (d *ngsiemDataConnectorsDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_ngsiem_data_connectors"
}

func (d *ngsiemDataConnectorsDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(documentationSection, dataSourceMarkdownDescription, apiScopesRead),
		Attributes: map[string]schema.Attribute{
			"by_name": schema.StringAttribute{
				Optional:    true,
				Description: "Exact connector name to match (e.g. `HEC / HTTP Event Connector`). When set, `id` is populated with that connector's ID and the lookup errors if no connector matches.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "ID of the connector matched by `by_name`. Null when `by_name` is not set.",
			},
			"connectors": schema.ListNestedAttribute{
				Computed:    true,
				Description: "All available Next-Gen SIEM data connectors.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id":                  schema.StringAttribute{Computed: true, Description: "Connector ID."},
						"name":                schema.StringAttribute{Computed: true, Description: "Connector display name."},
						"type":                schema.StringAttribute{Computed: true, Description: "Connector type: `PUSH` (the source pushes data to an ingest URL; manageable with `crowdstrike_ngsiem_data_connection`) or `PULL` (CrowdStrike fetches from the source)."},
						"description":         schema.StringAttribute{Computed: true, Description: "Connector description."},
						"vendor_name":         schema.StringAttribute{Computed: true, Description: "Vendor name."},
						"vendor_product_name": schema.StringAttribute{Computed: true, Description: "Vendor product name."},
						"parsers": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "Preset parser package name(s) for this connector. Generic connectors (for example HEC and Cribl) return an empty list; for those you set the parser yourself on the data connection.",
						},
					},
				},
			},
		},
	}
}

func (d *ngsiemDataConnectorsDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var state ngsiemDataConnectorsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	connectors, err := listConnectors(ctx, d.client)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, apiScopesRead))
		return
	}

	state.Connectors = make([]connectorEntryModel, 0, len(connectors))
	for _, c := range connectors {
		// ListValueFrom (not flex.FlattenStringValueList) keeps an empty result as [] not null, per docs.
		parsers, diags := types.ListValueFrom(ctx, types.StringType, c.Parsers)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		state.Connectors = append(state.Connectors, connectorEntryModel{
			ID:                types.StringValue(c.ID),
			Name:              types.StringValue(c.Name),
			Type:              types.StringValue(c.Type),
			Description:       types.StringValue(c.Description),
			VendorName:        types.StringValue(c.VendorName),
			VendorProductName: types.StringValue(c.VendorProductName),
			Parsers:           parsers,
		})
	}

	state.ID = types.StringNull()
	if !state.ByName.IsNull() && !state.ByName.IsUnknown() {
		match, err := findConnectorByName(connectors, state.ByName.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Connector not found", err.Error())
			return
		}
		state.ID = types.StringValue(match.ID)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
