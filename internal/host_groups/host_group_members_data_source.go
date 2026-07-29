package hostgroups

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/host_group"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	membersDataSourceMarkdownDescription = "This data source provides the live membership of a host group in Falcon. Use this to see which hosts are currently attached to a host group, regardless of whether membership comes from a dynamic assignment rule or a static list. Membership is resolved by Falcon at query time, so for static groups the result reflects the hosts Falcon currently considers members rather than the hostnames or IDs declared on the `crowdstrike_host_group` resource. All pages of members are retrieved automatically."

	// membersPageSize is the maximum number of records the queryGroupMembers
	// endpoint returns per request.
	membersPageSize = 5000
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &hostGroupMembersDataSource{}
	_ datasource.DataSourceWithConfigure = &hostGroupMembersDataSource{}
)

// hostGroupMembersDataSource is the data source implementation.
type hostGroupMembersDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

// HostGroupMembersDataSourceModel represents the data source model.
type HostGroupMembersDataSourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Filter      types.String `tfsdk:"filter"`
	HostIDs     types.Set    `tfsdk:"host_ids"`
	MemberCount types.Int64  `tfsdk:"member_count"`
}

// NewHostGroupMembersDataSource is a helper function to simplify the provider implementation.
func NewHostGroupMembersDataSource() datasource.DataSource {
	return &hostGroupMembersDataSource{}
}

// Configure adds the provider configured client to the data source.
func (d *hostGroupMembersDataSource) Configure(
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

// Metadata returns the data source type name.
func (d *hostGroupMembersDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_host_group_members"
}

// Schema defines the schema for the data source.
func (d *hostGroupMembersDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			dataSourceDocumentationSection,
			membersDataSourceMarkdownDescription,
			dataSourceApiScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The host group ID. Exactly one of 'id' or 'name' must be provided.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(32, 32),
					stringvalidator.ExactlyOneOf(path.MatchRoot("name"), path.MatchRoot("id")),
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
			"filter": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "FQL filter applied to the group members query. When set, only members matching the filter are returned. Example: `platform_name:'Windows'`",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"host_ids": schema.SetAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "The agent IDs of the hosts currently in the host group. Empty when the group has no members or when no member matches `filter`.",
			},
			"member_count": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "The number of hosts in `host_ids`.",
			},
		},
	}
}

// Read refreshes the Terraform state with the latest data.
func (d *hostGroupMembersDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data HostGroupMembersDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	group, diags := lookupHostGroup(ctx, d.client, data.ID.ValueString(), data.Name.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	data.ID = flex.StringPointerToFramework(group.ID)
	data.Name = flex.StringPointerToFramework(group.Name)

	memberIDs, diags := d.getMembers(ctx, data.ID.ValueString(), data.Filter.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// host_ids is never user-configurable, so an empty group is reported as an
	// empty set instead of the null value flex would produce. This keeps
	// length() and for_each usable when a group has no members.
	hostIDs, diags := types.SetValueFrom(ctx, types.StringType, memberIDs)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	data.HostIDs = hostIDs
	data.MemberCount = types.Int64Value(int64(len(memberIDs)))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// getMembers returns the agent IDs of every host in the group, paging through
// all results. The returned slice is never nil.
func (d *hostGroupMembersDataSource) getMembers(
	ctx context.Context,
	groupID string,
	filter string,
) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics

	memberIDs := []string{}
	seen := make(map[string]struct{})

	limit := int64(membersPageSize)
	offset := int64(0)

	for {
		params := &host_group.QueryGroupMembersParams{
			Context: ctx,
			ID:      &groupID,
			Limit:   &limit,
			Offset:  &offset,
		}

		if filter != "" {
			params.Filter = &filter
		}

		res, err := d.client.HostGroup.QueryGroupMembers(params)
		if err != nil {
			diags.Append(tferrors.NewDiagnosticFromAPIError(
				tferrors.Read,
				err,
				dataSourceApiScopes,
				tferrors.WithNotFoundDetail(fmt.Sprintf("No host group found with ID %q.", groupID)),
			))
			return memberIDs, diags
		}

		if res == nil || res.Payload == nil {
			diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
			return memberIDs, diags
		}

		if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diag != nil {
			diags.Append(diag)
			return memberIDs, diags
		}

		page := res.Payload.Resources
		if len(page) == 0 {
			break
		}

		// Membership of a dynamic group can change between pages, so the same
		// agent ID can appear twice. Terraform rejects duplicate set elements.
		for _, id := range page {
			if id == "" {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			memberIDs = append(memberIDs, id)
		}

		offset += int64(len(page))

		tflog.Debug(ctx, "[datasource] Retrieved page of host group members", map[string]any{
			"page_count":  len(page),
			"total_count": len(memberIDs),
			"offset":      offset,
		})

		meta := res.Payload.Meta
		if meta != nil && meta.Pagination != nil && meta.Pagination.Total != nil {
			if offset >= *meta.Pagination.Total {
				break
			}
			continue
		}

		if int64(len(page)) < limit {
			break
		}
	}

	tflog.Debug(ctx, "[datasource] Retrieved host group members", map[string]any{
		"count": len(memberIDs),
	})

	return memberIDs, diags
}
