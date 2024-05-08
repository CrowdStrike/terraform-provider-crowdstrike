package provider

import (
	"context"
	"fmt"
	"strings"

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

var buildSchema = map[string]schema.Attribute{
	"build": schema.StringAttribute{
		Computed:    true,
		Description: "The build number for a specific sensor version.",
	},
	"stage": schema.StringAttribute{
		Computed:    true,
		Description: "The stage for the build.",
	},
	"platform": schema.StringAttribute{
		Computed:    true,
		Description: "The target platform for a the build.",
	},
	"sensor_version": schema.StringAttribute{
		Computed:    true,
		Description: "CrowdStrike Falcon Sensor version.",
	},
}

var platformSchema = map[string]schema.Attribute{
	"latest": schema.SingleNestedAttribute{
		Computed:    true,
		Description: "The latest sensor build.",
		Attributes:  buildSchema,
	},
	"n1": schema.SingleNestedAttribute{
		Computed:    true,
		Description: "The n-1 sensor build.",
		Attributes:  buildSchema,
	},
	"n2": schema.SingleNestedAttribute{
		Computed:    true,
		Description: "The n-2 sensor build.",
		Attributes:  buildSchema,
	},
	"all": schema.ListNestedAttribute{
		Computed:    true,
		Description: "All sensor builds for the specific platform.",
		NestedObject: schema.NestedAttributeObject{
			Attributes: buildSchema,
		},
	},
}

// NewSensorUpdateBuildsDataSource is a helper function to simplify the provider implementation.
func NewSensorUpdateBuildsDataSource() datasource.DataSource {
	return &sensorUpdatePolicyBuildsDataSource{}
}

// sensorUpdatePolicyBuildsDataSourceModel maps the data source schema data.
type sensorUpdatePolicyBuildsDataSourceModel struct {
	ID         types.String   `tfsdk:"id"`
	Windows    platformBuilds `tfsdk:"windows"`
	Linux      platformBuilds `tfsdk:"linux"`
	LinuxArm64 platformBuilds `tfsdk:"linux_arm64"`
	Mac        platformBuilds `tfsdk:"mac"`
}

// sensorUpdatePolicyPlatformModel contains the build information for each platform.
type platformBuilds struct {
	Latest sensorBuild   `tfsdk:"latest"`
	N1     sensorBuild   `tfsdk:"n1"`
	N2     sensorBuild   `tfsdk:"n2"`
	All    []sensorBuild `tfsdk:"all"`
}

// sensorBuild maps sensor update policy builds schema data.
type sensorBuild struct {
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
				Computed:    true,
				Description: "Placehodler identifier.",
			},
			"windows": schema.SingleNestedAttribute{
				Computed:    true,
				Description: "Builds for the Windows platform.",
				Attributes:  platformSchema,
			},
			"linux": schema.SingleNestedAttribute{
				Computed:    true,
				Description: "Builds for the Linux platform.",
				Attributes:  platformSchema,
			},
			"linux_arm64": schema.SingleNestedAttribute{
				Computed:    true,
				Description: "Builds for the Linux platform (arm64).",
				Attributes:  platformSchema,
			},
			"mac": schema.SingleNestedAttribute{
				Computed:    true,
				Description: "Builds for the Mac platform.",
				Attributes:  platformSchema,
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

	var windowsPlatformBuilds platformBuilds
	var linuxPlatformBuilds platformBuilds
	var linuxArm64PlatformBuilds platformBuilds
	var macPlatformBuilds platformBuilds
	var windowsBuilds []sensorBuild
	var linuxBuilds []sensorBuild
	var linuxArm64Builds []sensorBuild
	var macBuilds []sensorBuild

	for _, b := range builds.Payload.Resources {
		bCopy := b

		build := sensorBuild{
			Build:         types.StringValue(*b.Build),
			Platform:      types.StringValue(*b.Platform),
			SensorVersion: types.StringValue(*b.Platform),
			Stage:         types.StringValue(*b.Stage),
		}

		switch strings.ToLower(*bCopy.Platform) {
		case "windows":
			mapBuild(&windowsPlatformBuilds, build)
			windowsBuilds = append(windowsBuilds, build)
		case "mac":
			mapBuild(&macPlatformBuilds, build)
			macBuilds = append(macBuilds, build)
		case "linux":
			mapBuild(&linuxPlatformBuilds, build)
			linuxBuilds = append(linuxBuilds, build)
		default:
			mapBuild(&linuxArm64PlatformBuilds, build)
			linuxArm64Builds = append(linuxArm64Builds, build)
		}
	}

	windowsPlatformBuilds.All = windowsBuilds
	linuxPlatformBuilds.All = linuxBuilds
	linuxArm64PlatformBuilds.All = linuxArm64Builds
	macPlatformBuilds.All = macBuilds

	state.ID = types.StringValue("all")
	state.Windows = windowsPlatformBuilds
	state.Linux = linuxPlatformBuilds
	state.LinuxArm64 = linuxArm64PlatformBuilds
	state.Mac = macPlatformBuilds

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

// mapBuild checks if a build is latest, n-1, or n-2 and adds the build to the appropiate attribute.
func mapBuild(platformBuilds *platformBuilds, build sensorBuild) {
	if strings.Contains(build.Build.ValueString(), "|n|") {
		platformBuilds.Latest = build
	}
	if strings.Contains(build.Build.ValueString(), "|n-1|") {
		platformBuilds.N1 = build
	}
	if strings.Contains(build.Build.ValueString(), "|n-2|") {
		platformBuilds.N2 = build
	}
}
