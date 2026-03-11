package hostgroups

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/host_group"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	dataSourceDocumentationSection = "Host Group"
	dataSourceMarkdownDescription  = "This data source provides information about a single host group in Falcon. Use this to look up a host group by name or ID and reference its attributes in other resources."
)

var dataSourceApiScopes = []scopes.Scope{
	{
		Name:  "Host groups",
		Read:  true,
		Write: false,
	},
}

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &hostGroupDataSource{}
	_ datasource.DataSourceWithConfigure = &hostGroupDataSource{}
)

// hostGroupDataSource is the data source implementation.
type hostGroupDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

// HostGroupDataSourceModel represents the data source model.
type HostGroupDataSourceModel struct {
	ID                types.String `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	Description       types.String `tfsdk:"description"`
	GroupType         types.String `tfsdk:"group_type"`
	AssignmentRule    types.String `tfsdk:"assignment_rule"`
	CreatedBy         types.String `tfsdk:"created_by"`
	CreatedTimestamp  types.String `tfsdk:"created_timestamp"`
	ModifiedBy        types.String `tfsdk:"modified_by"`
	ModifiedTimestamp types.String `tfsdk:"modified_timestamp"`
}

// NewHostGroupDataSource is a helper function to simplify the provider implementation.
func NewHostGroupDataSource() datasource.DataSource {
	return &hostGroupDataSource{}
}

// Configure adds the provider configured client to the data source.
func (d *hostGroupDataSource) Configure(
	_ context.Context,
	req datasource.ConfigureRequest,
	resp *datasource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	config, ok := req.ProviderData.(config.ProviderConfig)
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

	d.client = config.Client
}

// Metadata returns the data source type name.
func (d *hostGroupDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_host_group"
}

// Schema defines the schema for the data source.
func (d *hostGroupDataSource) Schema(
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
			"id": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The host group ID. Exactly one of 'id' or 'name' must be provided.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(32, 32),
					stringvalidator.ExactlyOneOf(path.MatchRoot("name")),
				},
			},
			"name": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The host group name. Exactly one of 'id' or 'name' must be provided.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"description": schema.StringAttribute{
				Computed:    true,
				Description: "The host group description",
			},
			"group_type": schema.StringAttribute{
				Computed:    true,
				Description: "The host group type (dynamic, static, staticByID)",
			},
			"assignment_rule": schema.StringAttribute{
				Computed:    true,
				Description: "The assignment rule for the host group",
			},
			"created_by": schema.StringAttribute{
				Computed:    true,
				Description: "User who created the host group",
			},
			"created_timestamp": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when the host group was created",
			},
			"modified_by": schema.StringAttribute{
				Computed:    true,
				Description: "User who last modified the host group",
			},
			"modified_timestamp": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when the host group was last modified",
			},
		},
	}
}

// Read refreshes the Terraform state with the latest data.
func (d *hostGroupDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data HostGroupDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if utils.IsKnown(data.ID) {
		// Look up by ID using GetHostGroups.
		tflog.Debug(ctx, "[datasource] Looking up host group by ID", map[string]any{
			"id": data.ID.ValueString(),
		})

		res, err := d.client.HostGroup.GetHostGroups(
			&host_group.GetHostGroupsParams{
				Context: ctx,
				Ids:     []string{data.ID.ValueString()},
			},
		)
		if err != nil {
			resp.Diagnostics.AddError(
				"Failed to get host group",
				fmt.Sprintf("Failed to get host group with ID %q: %s", data.ID.ValueString(), err.Error()),
			)
			return
		}

		if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
			resp.Diagnostics.AddError(
				"Host group not found",
				fmt.Sprintf("No host group found with ID %q.", data.ID.ValueString()),
			)
			return
		}

		group := res.Payload.Resources[0]
		data.ID = types.StringPointerValue(group.ID)
		data.Name = types.StringPointerValue(group.Name)
		data.Description = types.StringPointerValue(group.Description)
		data.GroupType = types.StringValue(group.GroupType)
		data.AssignmentRule = types.StringValue(group.AssignmentRule)
		data.CreatedBy = types.StringPointerValue(group.CreatedBy)
		data.CreatedTimestamp = types.StringValue(group.CreatedTimestamp.String())
		data.ModifiedBy = types.StringPointerValue(group.ModifiedBy)
		data.ModifiedTimestamp = types.StringValue(group.ModifiedTimestamp.String())
	} else {
		// Look up by name using QueryCombinedHostGroups with FQL filter.
		name := data.Name.ValueString()

		tflog.Debug(ctx, "[datasource] Looking up host group by name", map[string]any{
			"name": name,
		})

		filter := fmt.Sprintf("name:'%s'", name)
		params := &host_group.QueryCombinedHostGroupsParams{
			Context: ctx,
			Filter:  &filter,
		}

		res, err := d.client.HostGroup.QueryCombinedHostGroups(params)
		if err != nil {
			resp.Diagnostics.AddError(
				"Failed to query host groups",
				fmt.Sprintf("Failed to query host groups with name %q: %s", name, err.Error()),
			)
			return
		}

		if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
			resp.Diagnostics.AddError(
				"Host group not found",
				fmt.Sprintf("No host group found with name %q.", name),
			)
			return
		}

		// The FQL name filter may return partial matches, so filter
		// client-side for an exact (case-insensitive) name match.
		var matched []*models.HostGroupsHostGroupV1
		for _, g := range res.Payload.Resources {
			if g != nil && g.Name != nil && strings.EqualFold(*g.Name, name) {
				matched = append(matched, g)
			}
		}

		if len(matched) == 0 {
			resp.Diagnostics.AddError(
				"Host group not found",
				fmt.Sprintf("No host group found with exact name %q.", name),
			)
			return
		}

		if len(matched) > 1 {
			resp.Diagnostics.AddError(
				"Multiple host groups found",
				fmt.Sprintf("Found %d host groups with name %q. Host group names are expected to be unique.", len(matched), name),
			)
			return
		}

		group := matched[0]
		data.ID = types.StringPointerValue(group.ID)
		data.Name = types.StringPointerValue(group.Name)
		data.Description = types.StringPointerValue(group.Description)
		data.GroupType = types.StringValue(group.GroupType)
		data.AssignmentRule = types.StringValue(group.AssignmentRule)
		data.CreatedBy = types.StringPointerValue(group.CreatedBy)
		data.CreatedTimestamp = types.StringValue(group.CreatedTimestamp.String())
		data.ModifiedBy = types.StringPointerValue(group.ModifiedBy)
		data.ModifiedTimestamp = types.StringValue(group.ModifiedTimestamp.String())
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
