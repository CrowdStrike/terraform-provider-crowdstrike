package containerregistry

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/falcon_container_image"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &containerRegistriesDataSource{}
	_ datasource.DataSourceWithConfigure = &containerRegistriesDataSource{}
)

// containerRegistriesDataSource defines the data source implementation.
type containerRegistriesDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

// containerRegistriesDataSourceModel describes the data source model.
type containerRegistriesDataSourceModel struct {
	ID         types.String                 `tfsdk:"id"`
	IDs        []types.String               `tfsdk:"ids"`
	Registries []containerRegistryDataModel `tfsdk:"registries"`
}

// containerRegistryDataModel describes a single registry in the data source.
type containerRegistryDataModel struct {
	ID                  types.String `tfsdk:"id"`
	Type                types.String `tfsdk:"type"`
	URL                 types.String `tfsdk:"url"`
	URLUniqueAlias      types.String `tfsdk:"url_unique_alias"`
	UserDefinedAlias    types.String `tfsdk:"user_defined_alias"`
	RefreshInterval     types.Int64  `tfsdk:"refresh_interval"`
	LastRefreshedAt     types.String `tfsdk:"last_refreshed_at"`
	NextRefreshAt       types.String `tfsdk:"next_refresh_at"`
	State               types.String `tfsdk:"state"`
	StateChangedAt      types.String `tfsdk:"state_changed_at"`
	CreatedAt           types.String `tfsdk:"created_at"`
	UpdatedAt           types.String `tfsdk:"updated_at"`
	CredentialUsername  types.String `tfsdk:"credential_username"`
	CredentialExpired   types.Bool   `tfsdk:"credential_expired"`
	CredentialExpiredAt types.String `tfsdk:"credential_expired_at"`
	CredentialCreatedAt types.String `tfsdk:"credential_created_at"`
	CredentialUpdatedAt types.String `tfsdk:"credential_updated_at"`
}

// containerRegistriesScopes defines the required API scopes for container registries data source.
var containerRegistriesScopes = []scopes.Scope{
	{
		Name: "Falcon Container Image",
		Read: true,
	},
}

// NewContainerRegistriesDataSource is a helper function to simplify the provider implementation.
func NewContainerRegistriesDataSource() datasource.DataSource {
	return &containerRegistriesDataSource{}
}

// Metadata returns the data source type name.
func (d *containerRegistriesDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_container_registries"
}

// Schema defines the schema for the data source.
func (d *containerRegistriesDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf(
			"Container Registries --- Use this data source to retrieve information about container registry connections.\n\n%s",
			scopes.GenerateScopeDescription(containerRegistriesScopes),
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for this data source",
			},
			"ids": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Optional list of registry UUIDs (RFC 4122) to filter by. If not provided, all registries are returned.",
			},
			"registries": schema.ListNestedAttribute{
				Computed:    true,
				Description: "List of container registry connections",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "The unique identifier of the registry connection",
						},
						"type": schema.StringAttribute{
							Computed:    true,
							Description: "The type of registry",
						},
						"url": schema.StringAttribute{
							Computed:    true,
							Description: "The URL used to log in to the registry",
						},
						"url_unique_alias": schema.StringAttribute{
							Computed:    true,
							Description: "The registry URL alias",
						},
						"user_defined_alias": schema.StringAttribute{
							Computed:    true,
							Description: "A user-friendly name for the registry connection",
						},
						"refresh_interval": schema.Int64Attribute{
							Computed:    true,
							Description: "The registry assessment interval in seconds",
						},
						"last_refreshed_at": schema.StringAttribute{
							Computed:    true,
							Description: "The last time the registry was assessed",
						},
						"next_refresh_at": schema.StringAttribute{
							Computed:    true,
							Description: "The registry's next scheduled assessment time",
						},
						"state": schema.StringAttribute{
							Computed:    true,
							Description: "The current state of the registry connection",
						},
						"state_changed_at": schema.StringAttribute{
							Computed:    true,
							Description: "The date and time of the registry connection's last state change",
						},
						"created_at": schema.StringAttribute{
							Computed:    true,
							Description: "The date and time the registry connection was created",
						},
						"updated_at": schema.StringAttribute{
							Computed:    true,
							Description: "The date and time the registry connection was last updated",
						},
						"credential_username": schema.StringAttribute{
							Computed:    true,
							Description: "Username for registry authentication",
						},
						"credential_expired": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether the registry credentials have expired",
						},
						"credential_expired_at": schema.StringAttribute{
							Computed:    true,
							Description: "The date and time the registry credentials expired",
						},
						"credential_created_at": schema.StringAttribute{
							Computed:    true,
							Description: "The date and time the registry connection credential was created",
						},
						"credential_updated_at": schema.StringAttribute{
							Computed:    true,
							Description: "The date and time the registry connection credential was last updated",
						},
					},
				},
			},
		},
	}
}

// Read refreshes the Terraform state with the latest data.
func (d *containerRegistriesDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data containerRegistriesDataSourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	data.ID = types.StringValue("container-registries")

	var registryIDs []string

	// Check if specific IDs are provided for filtering
	if len(data.IDs) > 0 {
		// Use provided IDs for filtering
		registryIDs = make([]string, len(data.IDs))
		for i, id := range data.IDs {
			registryIDs[i] = id.ValueString()
		}
		tflog.Info(ctx, fmt.Sprintf("Reading specific container registry connections: %v", registryIDs))
	} else {
		// Get all registry connections
		readParams := falcon_container_image.NewReadRegistryEntitiesParams()
		limit := int64(5000)
		readParams.SetLimit(&limit) // Set high limit to get all registries

		tflog.Info(ctx, "Reading all container registry connections")
		readResult, err := d.client.FalconContainerImage.ReadRegistryEntities(readParams)
		if err != nil {
			resp.Diagnostics.AddError(
				"Failed to read container registry connections",
				fmt.Sprintf("Error reading registry connections: %s", err.Error()),
			)
			return
		}

		if readResult.Payload == nil || len(readResult.Payload.Resources) == 0 {
			// No registries found, return empty list
			data.Registries = []containerRegistryDataModel{}
			resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
			return
		}

		registryIDs = make([]string, len(readResult.Payload.Resources))
		copy(registryIDs, readResult.Payload.Resources)
	}

	// Get detailed information for the registry IDs (either filtered or all)
	if len(registryIDs) > 0 {
		// Join IDs with commas for batch API call
		batchIDs := ""
		for i, id := range registryIDs {
			if i > 0 {
				batchIDs += ","
			}
			batchIDs += id
		}

		detailParams := falcon_container_image.NewReadRegistryEntitiesByUUIDParams().WithIds(batchIDs)
		detailResult, err := d.client.FalconContainerImage.ReadRegistryEntitiesByUUID(detailParams)
		if err != nil {
			resp.Diagnostics.AddError(
				"Failed to read registry details",
				fmt.Sprintf("Error reading registry details: %s", err.Error()),
			)
			return
		}

		if detailResult.Payload == nil || len(detailResult.Payload.Resources) == 0 {
			// No registry details found, return empty list
			data.Registries = []containerRegistryDataModel{}
		} else {
			// Process all registries from the batch response
			data.Registries = make([]containerRegistryDataModel, len(detailResult.Payload.Resources))
			for i, registry := range detailResult.Payload.Resources {
				registryModel := containerRegistryDataModel{}
				d.updateDataModelFromRegistry(&registryModel, registry)
				data.Registries[i] = registryModel
			}
		}
	} else {
		data.Registries = []containerRegistryDataModel{}
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Configure adds the provider configured client to the data source.
func (d *containerRegistriesDataSource) Configure(
	ctx context.Context,
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

// updateDataModelFromRegistry updates the data source model with data from the API response.
func (d *containerRegistriesDataSource) updateDataModelFromRegistry(
	model *containerRegistryDataModel,
	registry *models.DomainExternalAPIRegistry,
) {
	// Use the common mapping function for shared fields
	common := mapCommonRegistryFields(registry)

	model.ID = common.ID
	model.Type = common.Type
	model.URL = common.URL
	model.UserDefinedAlias = common.UserDefinedAlias
	model.RefreshInterval = common.RefreshInterval
	model.LastRefreshedAt = common.LastRefreshedAt
	model.NextRefreshAt = common.NextRefreshAt
	model.State = common.State
	model.StateChangedAt = common.StateChangedAt
	model.CreatedAt = common.CreatedAt
	model.UpdatedAt = common.UpdatedAt
	model.CredentialExpired = common.CredentialExpired
	model.CredentialExpiredAt = common.CredentialExpiredAt
	model.CredentialCreatedAt = common.CredentialCreatedAt
	model.CredentialUpdatedAt = common.CredentialUpdatedAt

	// Data source specific: username is not exposed by the API for security reasons
	model.CredentialUsername = types.StringNull()
}
