package sensorvisibilityexclusion

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_visibility_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	hostgroups "github.com/crowdstrike/terraform-provider-crowdstrike/internal/host_groups"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	dataSourceDocumentationSection = "Sensor Visibility Exclusion"
	dataSourceMarkdownDescription  = "This data source provides information about sensor visibility exclusions in Falcon."
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource                   = &sensorVisibilityExclusionsDataSource{}
	_ datasource.DataSourceWithConfigure      = &sensorVisibilityExclusionsDataSource{}
	_ datasource.DataSourceWithValidateConfig = &sensorVisibilityExclusionsDataSource{}
)

// Configure adds the provider configured client to the data source.
func (d *sensorVisibilityExclusionsDataSource) Configure(
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

// sensorVisibilityExclusionsDataSource is the data source implementation.
type sensorVisibilityExclusionsDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type exclusionDataModel struct {
	ID                         types.String `tfsdk:"id"`
	Value                      types.String `tfsdk:"value"`
	RegexpValue                types.String `tfsdk:"regexp_value"`
	ValueHash                  types.String `tfsdk:"value_hash"`
	AppliedGlobally            types.Bool   `tfsdk:"applied_globally"`
	ApplyToDescendantProcesses types.Bool   `tfsdk:"apply_to_descendant_processes"`
	HostGroups                 types.List   `tfsdk:"host_groups"`
	LastModified               types.String `tfsdk:"last_modified"`
	ModifiedBy                 types.String `tfsdk:"modified_by"`
	CreatedOn                  types.String `tfsdk:"created_on"`
	CreatedBy                  types.String `tfsdk:"created_by"`
}

func (m exclusionDataModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":                            types.StringType,
		"value":                         types.StringType,
		"regexp_value":                  types.StringType,
		"value_hash":                    types.StringType,
		"applied_globally":              types.BoolType,
		"apply_to_descendant_processes": types.BoolType,
		"host_groups":                   types.ListType{ElemType: types.StringType},
		"last_modified":                 types.StringType,
		"modified_by":                   types.StringType,
		"created_on":                    types.StringType,
		"created_by":                    types.StringType,
	}
}

// SensorVisibilityExclusionsDataSourceModel represents the data source model.
type SensorVisibilityExclusionsDataSourceModel struct {
	Filter          types.String `tfsdk:"filter"`
	IDs             types.List   `tfsdk:"ids"`
	Sort            types.String `tfsdk:"sort"`
	AppliedGlobally types.Bool   `tfsdk:"applied_globally"`
	CreatedBy       types.String `tfsdk:"created_by"`
	ModifiedBy      types.String `tfsdk:"modified_by"`
	Value           types.String `tfsdk:"value"`
	Exclusions      types.List   `tfsdk:"exclusions"`
}

func (m *SensorVisibilityExclusionsDataSourceModel) wrap(ctx context.Context, exclusions []*models.SvExclusionsSVExclusionV1) diag.Diagnostics {
	var diags diag.Diagnostics
	exclusionModels := make([]exclusionDataModel, 0, len(exclusions))

	for _, exclusion := range exclusions {
		if exclusion == nil {
			continue
		}

		exclusionModel := exclusionDataModel{}

		exclusionModel.ID = flex.StringPointerToFramework(exclusion.ID)
		exclusionModel.Value = flex.StringPointerToFramework(exclusion.Value)
		exclusionModel.RegexpValue = flex.StringPointerToFramework(exclusion.RegexpValue)
		exclusionModel.ValueHash = flex.StringPointerToFramework(exclusion.ValueHash)
		exclusionModel.AppliedGlobally = types.BoolPointerValue(exclusion.AppliedGlobally)
		exclusionModel.ApplyToDescendantProcesses = types.BoolValue(exclusion.IsDescendantProcess)
		exclusionModel.LastModified = flex.StringValueToFramework(exclusion.LastModified.String())
		exclusionModel.ModifiedBy = flex.StringPointerToFramework(exclusion.ModifiedBy)
		exclusionModel.CreatedOn = flex.StringValueToFramework(exclusion.CreatedOn.String())
		exclusionModel.CreatedBy = flex.StringPointerToFramework(exclusion.CreatedBy)

		hostGroups, hostGroupDiags := hostgroups.ConvertHostGroupsToList(ctx, exclusion.Groups)
		diags.Append(hostGroupDiags...)
		if diags.HasError() {
			return diags
		}
		exclusionModel.HostGroups = hostGroups

		exclusionModels = append(exclusionModels, exclusionModel)
	}

	m.Exclusions = utils.SliceToListTypeObject(ctx, exclusionModels, exclusionDataModel{}.AttributeTypes(), &diags)
	return diags
}

// hasIndividualFilters checks if any of the individual filter attributes are set.
func (m *SensorVisibilityExclusionsDataSourceModel) hasIndividualFilters() bool {
	return utils.IsKnown(m.AppliedGlobally) ||
		utils.IsKnown(m.CreatedBy) ||
		utils.IsKnown(m.ModifiedBy) ||
		utils.IsKnown(m.Value)
}

// NewSensorVisibilityExclusionsDataSource is a helper function to simplify the provider implementation.
func NewSensorVisibilityExclusionsDataSource() datasource.DataSource {
	return &sensorVisibilityExclusionsDataSource{}
}

// Metadata returns the data source type name.
func (d *sensorVisibilityExclusionsDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_sensor_visibility_exclusions"
}

// Schema defines the schema for the data source.
func (d *sensorVisibilityExclusionsDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			dataSourceDocumentationSection,
			dataSourceMarkdownDescription,
			apiScopes,
		),
		Attributes: map[string]schema.Attribute{
			"filter": schema.StringAttribute{
				Optional:    true,
				Description: "FQL filter to apply to the sensor visibility exclusions query. When specified, only exclusions matching the filter will be returned. Cannot be used together with 'ids' or other filter attributes. Example: `applied_globally:true`",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"ids": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "List of sensor visibility exclusion IDs to retrieve. When specified, only exclusions with matching IDs will be returned. Cannot be used together with 'filter' or other filter attributes.",
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.LengthBetween(32, 32),
					),
					listvalidator.SizeAtLeast(1),
					listvalidator.UniqueValues(),
				},
			},
			"sort": schema.StringAttribute{
				Optional:    true,
				Description: "Sort order for the results. Valid values include field names with optional '.asc' or '.desc' suffix. Example: 'value.asc', 'created_on.desc'",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"applied_globally": schema.BoolAttribute{
				Optional:    true,
				Description: "Filter exclusions by whether they are applied globally. All provided filter attributes must match for an exclusion to be returned (omitted attributes are ignored). Cannot be used together with 'filter' or 'ids'.",
			},
			"created_by": schema.StringAttribute{
				Optional:    true,
				Description: "Filter exclusions by the user who created them. All provided filter attributes must match for an exclusion to be returned (omitted attributes are ignored). Supports wildcard matching with '*' where '*' matches any sequence of characters until the end of the string or until the next literal character in the pattern is found. Multiple wildcards can be used in a single pattern. Matching is case insensitive. Cannot be used together with 'filter' or 'ids'.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"modified_by": schema.StringAttribute{
				Optional:    true,
				Description: "Filter exclusions by the user who last modified them. All provided filter attributes must match for an exclusion to be returned (omitted attributes are ignored). Supports wildcard matching with '*' where '*' matches any sequence of characters until the end of the string or until the next literal character in the pattern is found. Multiple wildcards can be used in a single pattern. Matching is case insensitive. Cannot be used together with 'filter' or 'ids'.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"value": schema.StringAttribute{
				Optional:    true,
				Description: "Filter exclusions by the exclusion value/path. All provided filter attributes must match for an exclusion to be returned (omitted attributes are ignored). Supports wildcard matching with '*' where '*' matches any sequence of characters until the end of the string or until the next literal character in the pattern is found. Multiple wildcards can be used in a single pattern. Matching is case insensitive. Cannot be used together with 'filter' or 'ids'.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"exclusions": schema.ListNestedAttribute{
				Computed:    true,
				Description: "The list of sensor visibility exclusions",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "The sensor visibility exclusion ID",
						},
						"value": schema.StringAttribute{
							Computed:    true,
							Description: "The exclusion value/path",
						},
						"regexp_value": schema.StringAttribute{
							Computed:    true,
							Description: "The regular expression representation of the exclusion value",
						},
						"value_hash": schema.StringAttribute{
							Computed:    true,
							Description: "The hash of the exclusion value",
						},
						"applied_globally": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether the exclusion is applied globally to all host groups",
						},
						"apply_to_descendant_processes": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether the exclusion applies to descendant processes",
						},
						"host_groups": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "List of host group IDs assigned to the exclusion",
						},
						"last_modified": schema.StringAttribute{
							Computed:    true,
							Description: "Timestamp when the exclusion was last modified",
						},
						"modified_by": schema.StringAttribute{
							Computed:    true,
							Description: "User who last modified the exclusion",
						},
						"created_on": schema.StringAttribute{
							Computed:    true,
							Description: "Timestamp when the exclusion was created",
						},
						"created_by": schema.StringAttribute{
							Computed:    true,
							Description: "User who created the exclusion",
						},
					},
				},
			},
		},
	}
}

func (d *sensorVisibilityExclusionsDataSource) ValidateConfig(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var data SensorVisibilityExclusionsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	hasFilter := utils.IsKnown(data.Filter) && data.Filter.ValueString() != ""
	hasIDs := utils.IsKnown(data.IDs) && len(data.IDs.Elements()) > 0

	filterCount := 0
	if hasFilter {
		filterCount++
	}
	if hasIDs {
		filterCount++
	}
	if data.hasIndividualFilters() {
		filterCount++
	}

	if filterCount > 1 {
		resp.Diagnostics.AddError(
			"Invalid Attribute Combination",
			"Cannot specify 'filter', 'ids', and individual filter attributes (applied_globally, created_by, modified_by, value) together. Please use only one filtering method: either 'filter' for FQL queries, 'ids' for specific IDs, or individual filter attributes.",
		)
	}
}

// querySensorVisibilityExclusions returns all sensor visibility exclusions matching filter.
func (d *sensorVisibilityExclusionsDataSource) querySensorVisibilityExclusions(
	ctx context.Context,
	filter string,
	sort string,
) ([]*models.SvExclusionsSVExclusionV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	var allExclusions []*models.SvExclusionsSVExclusionV1

	tflog.Debug(
		ctx,
		"[datasource] Getting all sensor visibility exclusions",
	)

	limit := int64(5000)
	offset := int64(0)

	for {
		params := &sensor_visibility_exclusions.QuerySensorVisibilityExclusionsV1Params{
			Context: ctx,
			Limit:   &limit,
			Offset:  &offset,
		}

		if filter != "" {
			params.Filter = &filter
		}

		if sort != "" {
			params.Sort = &sort
		}

		res, err := d.client.SensorVisibilityExclusions.QuerySensorVisibilityExclusionsV1(params)
		if err != nil {
			diag := tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, apiScopes)
			if diag.Summary() == tferrors.NotFoundErrorSummary {
				tflog.Debug(ctx, "[datasource] No sensor visibility exclusions found (404), returning empty list")
				return allExclusions, diags
			}
			diags.Append(diag)
			return allExclusions, diags
		}

		if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
			tflog.Debug(ctx, "[datasource] No more sensor visibility exclusions to retrieve",
				map[string]interface{}{
					"total_retrieved": len(allExclusions),
				})
			break
		}

		// Get detailed exclusion information for the IDs returned by the query
		exclusions, exclusionDiags := d.getSensorVisibilityExclusions(ctx, res.Payload.Resources)
		diags.Append(exclusionDiags...)
		if diags.HasError() {
			return allExclusions, diags
		}

		allExclusions = append(allExclusions, exclusions...)
		tflog.Debug(ctx, "[datasource] Retrieved page of sensor visibility exclusions",
			map[string]interface{}{
				"page_count":  len(exclusions),
				"total_count": len(allExclusions),
				"offset":      offset,
			})

		if res.Payload.Meta == nil || res.Payload.Meta.Pagination == nil ||
			res.Payload.Meta.Pagination.Offset == nil || res.Payload.Meta.Pagination.Total == nil {
			tflog.Warn(ctx, "Missing pagination metadata in API response, using offset+limit for next page",
				map[string]interface{}{
					"meta": res.Payload.Meta,
				})
			offset += limit
			continue
		}

		offset = int64(*res.Payload.Meta.Pagination.Offset)
		if offset >= *res.Payload.Meta.Pagination.Total {
			tflog.Info(ctx, "[datasource] Pagination complete",
				map[string]interface{}{
					"total_retrieved": len(allExclusions),
					"total_available": *res.Payload.Meta.Pagination.Total,
				})
			break
		}
	}

	return allExclusions, diags
}

// getSensorVisibilityExclusions returns sensor visibility exclusions matching the provided IDs.
func (d *sensorVisibilityExclusionsDataSource) getSensorVisibilityExclusions(
	ctx context.Context,
	ids []string,
) ([]*models.SvExclusionsSVExclusionV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	tflog.Debug(
		ctx,
		"[datasource] Getting sensor visibility exclusions",
		map[string]any{
			"ids_count": len(ids),
			"ids":       ids,
		},
	)

	params := sensor_visibility_exclusions.NewGetSensorVisibilityExclusionsV1ParamsWithContext(ctx)
	if len(ids) > 0 {
		params.SetIds(ids)
	}

	res, err := d.client.SensorVisibilityExclusions.GetSensorVisibilityExclusionsV1(params)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, apiScopes)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			tflog.Debug(ctx, "[datasource] Sensor visibility exclusions not found (404), returning empty list",
				map[string]any{
					"ids": ids,
				})
			return []*models.SvExclusionsSVExclusionV1{}, diags
		}
		diags.Append(diag)
		return nil, diags
	}

	if res == nil || res.Payload == nil {
		tflog.Debug(ctx, "[datasource] No sensor visibility exclusions response",
			map[string]any{
				"response_nil": res == nil,
				"payload_nil":  res != nil && res.Payload == nil,
			})
		return []*models.SvExclusionsSVExclusionV1{}, diags
	}

	exclusions := res.Payload.Resources
	tflog.Debug(ctx, "[datasource] Retrieved sensor visibility exclusions",
		map[string]any{
			"count": len(exclusions),
		})

	return exclusions, diags
}

// Read refreshes the Terraform state with the latest data.
func (d *sensorVisibilityExclusionsDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data SensorVisibilityExclusionsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var exclusions []*models.SvExclusionsSVExclusionV1
	var diags diag.Diagnostics

	// If specific IDs are requested, get them directly
	if utils.IsKnown(data.IDs) {
		requestedIDs := utils.ListTypeAs[string](ctx, data.IDs, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}

		exclusions, diags = d.getSensorVisibilityExclusions(ctx, requestedIDs)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
	} else {
		// Otherwise, query all exclusions and filter as needed
		exclusions, diags = d.querySensorVisibilityExclusions(ctx, data.Filter.ValueString(), data.Sort.ValueString())
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		if data.hasIndividualFilters() {
			exclusions = filterExclusionsByAttributes(exclusions, &data)
		}
	}

	resp.Diagnostics.Append(data.wrap(ctx, exclusions)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// filterExclusionsByAttributes filters exclusions by individual attributes.
func filterExclusionsByAttributes(exclusions []*models.SvExclusionsSVExclusionV1, filters *SensorVisibilityExclusionsDataSourceModel) []*models.SvExclusionsSVExclusionV1 {
	filtered := make([]*models.SvExclusionsSVExclusionV1, 0, len(exclusions))
	for _, exclusion := range exclusions {
		if exclusion == nil {
			continue
		}

		if !filters.AppliedGlobally.IsNull() {
			if exclusion.AppliedGlobally == nil || *exclusion.AppliedGlobally != filters.AppliedGlobally.ValueBool() {
				continue
			}
		}

		if !filters.CreatedBy.IsNull() {
			if exclusion.CreatedBy == nil || !utils.MatchesWildcard(*exclusion.CreatedBy, filters.CreatedBy.ValueString()) {
				continue
			}
		}

		if !filters.ModifiedBy.IsNull() {
			if exclusion.ModifiedBy == nil || !utils.MatchesWildcard(*exclusion.ModifiedBy, filters.ModifiedBy.ValueString()) {
				continue
			}
		}

		if !filters.Value.IsNull() {
			if exclusion.Value == nil || !utils.MatchesWildcard(*exclusion.Value, filters.Value.ValueString()) {
				continue
			}
		}

		filtered = append(filtered, exclusion)
	}
	return filtered
}
