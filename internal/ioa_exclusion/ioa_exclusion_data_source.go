package ioaexclusion

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ioa_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"

	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &ioaExclusionDataSource{}
	_ datasource.DataSourceWithConfigure = &ioaExclusionDataSource{}
)

var ioaExclusionDataSourceScopes = []scopes.Scope{{Name: "IOA Exclusions", Read: true}}

type ioaExclusionDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

func NewIOAExclusionDataSource() datasource.DataSource { return &ioaExclusionDataSource{} }

func (d *ioaExclusionDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ioa_exclusion"
}

func (d *ioaExclusionDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	providerConfig, ok := req.ProviderData.(config.ProviderConfig)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Data Source Configure Type", fmt.Sprintf("Expected config.ProviderConfig, got: %T. Please report this issue to the provider developers.", req.ProviderData))
		return
	}
	d.client = providerConfig.Client
}

func (d *ioaExclusionDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription("Endpoint Security", "Looks up a single IOA exclusion by ID or exact name. The lookup fails if no object or multiple objects match. Use an ID to disambiguate matches.", ioaExclusionDataSourceScopes),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Unique identifier. Specify exactly one of `id` or `name`.",
				Optional:            true,
				Validators:          []validator.String{fwvalidators.StringNotWhitespace(), stringvalidator.ExactlyOneOf(path.MatchRoot("id"), path.MatchRoot("name"))},
			},
			"last_updated": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Always null: the last Terraform update timestamp belongs to resource state and is not returned by Falcon.",
			},
			"name": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Exact, case-sensitive exclusion name. Specify exactly one of `id` or `name`.",
				Optional:            true,
				Validators:          []validator.String{fwvalidators.StringNotWhitespace()},
			},
			"description": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Description of the IOA exclusion.",
			},
			"pattern_id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Identifier of the IOA pattern to exclude.",
			},
			"pattern_name": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Name of the IOA pattern.",
			},
			"cl_regex": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Command-line regex pattern for exclusion matching. Maximum length is 256 characters.",
			},
			"ifn_regex": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Image filename regex pattern for exclusion matching. Maximum length is 256 characters.",
			},
			"parent_cl_regex": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Parent process command-line regex pattern for exclusion matching. Maximum length is 256 characters.",
			},
			"parent_ifn_regex": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Parent process image filename regex pattern for exclusion matching. Maximum length is 256 characters.",
			},
			"grandparent_cl_regex": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Grandparent process command-line regex pattern for exclusion matching. Maximum length is 256 characters.",
			},
			"grandparent_ifn_regex": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Grandparent process image filename regex pattern for exclusion matching. Maximum length is 256 characters.",
			},
			"host_groups": schema.SetAttribute{
				Computed:            true,
				MarkdownDescription: "Host group IDs that receive this exclusion. Contains `[\"all\"]` when applied globally.",
				ElementType:         types.StringType,
			},
			"comment": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Additional context stored when creating or updating the exclusion.",
			},
			"applied_globally": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether the exclusion is applied globally to all hosts.",
			},
			"created_by": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "User who created the exclusion.",
			},
			"created_on": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Timestamp when the exclusion was created.",
				CustomType:          timetypes.RFC3339Type{},
			},
			"modified_by": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "User who last modified the exclusion.",
			},
			"last_modified": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Timestamp when the exclusion was last modified.",
				CustomType:          timetypes.RFC3339Type{},
			},
		},
	}
}

func (d *ioaExclusionDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data IOAExclusionResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	result, diags := d.lookup(ctx, data.ID.ValueString(), data.Name.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(data.wrap(ctx, result)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (d *ioaExclusionDataSource) get(ctx context.Context, ids []string) ([]*models.DomainSsIoaExclusionsV2, diag.Diagnostics) {
	var diags diag.Diagnostics
	params := ioa_exclusions.NewSsIoaExclusionsGetV2ParamsWithContext(ctx).WithIds(ids)
	response, err := d.client.IoaExclusions.SsIoaExclusionsGetV2(params)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, ioaExclusionDataSourceScopes))
		return nil, diags
	}
	if response == nil || response.Payload == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return nil, diags
	}
	if diagnostic := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, response.Payload.Errors); diagnostic != nil {
		diags.Append(diagnostic)
		return nil, diags
	}
	return response.Payload.Resources, diags
}

func (d *ioaExclusionDataSource) lookup(ctx context.Context, id, name string) (*models.DomainSsIoaExclusionsV2, diag.Diagnostics) {
	var diags diag.Diagnostics
	if id != "" {
		results, readDiags := d.get(ctx, []string{id})
		diags.Append(readDiags...)
		if diags.HasError() {
			return nil, diags
		}
		for _, result := range results {
			if result != nil && result.ID != nil && *result.ID == id {
				return result, diags
			}
		}
		diags.Append(tferrors.NewNotFoundError(fmt.Sprintf("No IOA exclusion found with ID %q.", id)))
		return nil, diags
	}

	escaped := strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(name)
	filter := fmt.Sprintf("name:'%s'", escaped)
	const limit int64 = 100
	var offset int64
	var match *models.DomainSsIoaExclusionsV2
	seen := map[string]bool{}
	for {
		params := ioa_exclusions.NewSsIoaExclusionsSearchV2ParamsWithContext(ctx).WithFilter(&filter).WithLimit(utils.Addr(limit)).WithOffset(&offset)
		response, err := d.client.IoaExclusions.SsIoaExclusionsSearchV2(params)
		if err != nil {
			diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, ioaExclusionDataSourceScopes))
			return nil, diags
		}
		if response == nil || response.Payload == nil {
			diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
			return nil, diags
		}
		payload := response.Payload
		if diagnostic := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, payload.Errors); diagnostic != nil {
			diags.Append(diagnostic)
			return nil, diags
		}
		ids := []string{}
		for _, candidateID := range payload.Resources {
			if candidateID != "" && !seen[candidateID] {
				seen[candidateID] = true
				ids = append(ids, candidateID)
			}
		}
		if len(ids) > 0 {
			results, readDiags := d.get(ctx, ids)
			diags.Append(readDiags...)
			if diags.HasError() {
				return nil, diags
			}
			returned := map[string]bool{}
			for _, result := range results {
				if result == nil || result.ID == nil {
					continue
				}
				returned[*result.ID] = true
				if result.Name == nil || *result.Name != name {
					continue
				}
				if match != nil && *match.ID != *result.ID {
					diags.AddError("Ambiguous IOA exclusion lookup", "More than one IOA exclusion matches the exact name. Specify an ID instead.")
					return nil, diags
				}
				match = result
			}
			for _, candidateID := range ids {
				if !returned[candidateID] {
					diags.AddError("Incomplete IOA exclusion lookup", "An exclusion returned by the query could not be retrieved. Retry the lookup.")
					return nil, diags
				}
			}
		}
		offset += int64(len(payload.Resources))
		if payload.Meta != nil && payload.Meta.Pagination != nil && payload.Meta.Pagination.Total != nil {
			if offset >= *payload.Meta.Pagination.Total {
				break
			}
		} else if int64(len(payload.Resources)) < limit {
			break
		}
		if len(ids) == 0 {
			diags.AddError("Incomplete IOA exclusion lookup", "The API pagination did not advance. Retry the lookup.")
			return nil, diags
		}
	}
	if match == nil {
		diags.Append(tferrors.NewNotFoundError(fmt.Sprintf("No IOA exclusion found with exact name %q.", name)))
	}
	return match, diags
}
