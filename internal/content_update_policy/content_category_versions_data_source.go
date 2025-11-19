package contentupdatepolicy

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/content_update_policies"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &contentCategoryVersionsDataSource{}
	_ datasource.DataSourceWithConfigure = &contentCategoryVersionsDataSource{}
)

// NewContentCategoryVersionsDataSource is a helper function to simplify the provider implementation.
func NewContentCategoryVersionsDataSource() datasource.DataSource {
	return &contentCategoryVersionsDataSource{}
}

// contentCategoryVersionsDataSourceModel maps the data source schema data.
type contentCategoryVersionsDataSourceModel struct {
	SensorOperations        []types.String `tfsdk:"sensor_operations"`
	SystemCritical          []types.String `tfsdk:"system_critical"`
	VulnerabilityManagement []types.String `tfsdk:"vulnerability_management"`
	RapidResponse           []types.String `tfsdk:"rapid_response"`
}

// contentCategoryVersionsDataSource is the data source implementation.
type contentCategoryVersionsDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

// Metadata returns the data source type name.
func (d *contentCategoryVersionsDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_content_category_versions"
}

// Schema defines the schema for the data source.
func (d *contentCategoryVersionsDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf(
			"Content Update Policy --- This data source provides information about available content category versions for pinning in content update policies.\n\n%s",
			scopes.GenerateScopeDescription(
				[]scopes.Scope{
					{
						Name:  "Content update policy",
						Read:  true,
						Write: false,
					},
				},
			),
		),
		Attributes: map[string]schema.Attribute{
			"sensor_operations": schema.ListAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Available versions for the Sensor Operations content category.",
			},
			"system_critical": schema.ListAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Available versions for the System Critical content category.",
			},
			"vulnerability_management": schema.ListAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Available versions for the Vulnerability Management content category.",
			},
			"rapid_response": schema.ListAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Available versions for the Rapid Response content category.",
			},
		},
	}
}

// Read refreshes the Terraform state with the latest data.
func (d *contentCategoryVersionsDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var state contentCategoryVersionsDataSourceModel

	// Categories mapping API name to field name
	categories := map[string]string{
		"sensor_operations":            "sensor_operations",
		"system_critical":              "system_critical",
		"vulnerability_management":     "vulnerability_management",
		"rapid_response_al_bl_listing": "rapid_response",
	}

	versions := make(map[string][]string)

	// Query each content category for available versions
	for apiCategory := range categories {
		categoryVersions, err := d.client.ContentUpdatePolicies.QueryPinnableContentVersions(
			&content_update_policies.QueryPinnableContentVersionsParams{
				Context:  ctx,
				Category: apiCategory,
			},
		)
		if err != nil {
			resp.Diagnostics.AddError(
				fmt.Sprintf("Unable to read content versions for category %s", apiCategory),
				err.Error(),
			)
			return
		}

		if categoryVersions.Payload.Resources != nil {
			versions[apiCategory] = categoryVersions.Payload.Resources
		} else {
			versions[apiCategory] = []string{}
		}
	}

	// Convert to types.String slices
	var sensorOpsVersions []types.String
	var systemCriticalVersions []types.String
	var vulnMgmtVersions []types.String
	var rapidResponseVersions []types.String

	for _, version := range versions["sensor_operations"] {
		sensorOpsVersions = append(sensorOpsVersions, types.StringValue(version))
	}

	for _, version := range versions["system_critical"] {
		systemCriticalVersions = append(systemCriticalVersions, types.StringValue(version))
	}

	for _, version := range versions["vulnerability_management"] {
		vulnMgmtVersions = append(vulnMgmtVersions, types.StringValue(version))
	}

	for _, version := range versions["rapid_response_al_bl_listing"] {
		rapidResponseVersions = append(rapidResponseVersions, types.StringValue(version))
	}

	state.SensorOperations = sensorOpsVersions
	state.SystemCritical = systemCriticalVersions
	state.VulnerabilityManagement = vulnMgmtVersions
	state.RapidResponse = rapidResponseVersions

	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Configure adds the provider configured client to the data source.
func (d *contentCategoryVersionsDataSource) Configure(
	_ context.Context,
	req datasource.ConfigureRequest,
	resp *datasource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*client.CrowdStrikeAPISpecification)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf(
				"Expected *client.CrowdStrikeAPISpecification, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)
		return
	}

	d.client = client
}
