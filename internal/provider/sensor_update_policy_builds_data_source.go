package provider

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_update_policies"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &sensorUpdatePolicyBuildsDataSource{}
	_ datasource.DataSourceWithConfigure = &sensorUpdatePolicyBuildsDataSource{}
)

// NewSensorUpdateBuildsDataSource is a helper function to simplify the provider implementation.
func NewSensorUpdateBuildsDataSource() datasource.DataSource {
	return &sensorUpdatePolicyBuildsDataSource{}
}

// sensorUpdatePolicyBuildsDataSourceModel maps the data source schema data.
type sensorUpdatePolicyBuildsDataSourceModel struct {
	ID     types.String                    `tfsdk:"id"`
	Builds []sensorUpdatePolicyBuildsModel `tfsdk:"sensor_update_policy_builds"`
}

// sensorUpdatePolicyBuildsModel maps coffees schema data.
type sensorUpdatePolicyBuildsModel struct {
	Build         types.String `tfsdk:"build"`
	Stage         types.String `tfsdk:"stage"`
	Platform      types.String `tfsdk:"platform"`
	SensorVersion types.String `tfsdk:"sensor_version"`
}

// sensorUpdatePolicyBuildsDataSource is the data source implementation.
type sensorUpdatePolicyBuildsDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

// Metadata returns the data source type name.
func (d *sensorUpdatePolicyBuildsDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_sensor_update_policy_builds"
}

// Schema defines the schema for the data source.
func (d *sensorUpdatePolicyBuildsDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
			},
			"sensor_update_policy_builds": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"build": schema.StringAttribute{
							Computed: true,
						},
						"stage": schema.StringAttribute{
							Computed: true,
						},
						"platform": schema.StringAttribute{
							Computed: true,
						},
						"sensor_version": schema.StringAttribute{
							Computed: true,
						},
					},
				},
			},
		},
	}
}

// Read refreshes the Terraform state with the latest data.
func (d *sensorUpdatePolicyBuildsDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var state sensorUpdatePolicyBuildsDataSourceModel

	builds, err := d.client.SensorUpdatePolicies.QueryCombinedSensorUpdateBuilds(
		&sensor_update_policies.QueryCombinedSensorUpdateBuildsParams{
			Context: ctx,
		},
	)

	if err != nil {
		resp.Diagnostics.AddError("Unable to read sensor update policy builds", err.Error())
		return
	}

	for _, build := range builds.Payload.Resources {
		buildState := sensorUpdatePolicyBuildsModel{
			Build:         types.StringValue(*build.Build),
			Stage:         types.StringValue(*build.Stage),
			Platform:      types.StringValue(*build.Platform),
			SensorVersion: types.StringValue(*build.SensorVersion),
		}

		state.Builds = append(state.Builds, buildState)
	}

	state.ID = types.StringValue("all")

	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Configure adds the provider configured client to the data source.
func (d *sensorUpdatePolicyBuildsDataSource) Configure(
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
