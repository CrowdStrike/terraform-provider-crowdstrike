package contentupdatepolicy

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/content_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	hostgroups "github.com/crowdstrike/terraform-provider-crowdstrike/internal/host_groups"
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
	dataSourceDocumentationSection = "Content Update Policies"
	dataSourceMarkdownDescription  = "This data source provides information about content update policies in Falcon."
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource                   = &contentUpdatePoliciesDataSource{}
	_ datasource.DataSourceWithConfigure      = &contentUpdatePoliciesDataSource{}
	_ datasource.DataSourceWithValidateConfig = &contentUpdatePoliciesDataSource{}
)

// Configure adds the provider configured client to the data source.
func (d *contentUpdatePoliciesDataSource) Configure(
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

// contentUpdatePoliciesDataSource is the data source implementation.
type contentUpdatePoliciesDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type policyDataModel struct {
	ID                      types.String `tfsdk:"id"`
	Name                    types.String `tfsdk:"name"`
	Description             types.String `tfsdk:"description"`
	Enabled                 types.Bool   `tfsdk:"enabled"`
	CreatedBy               types.String `tfsdk:"created_by"`
	CreatedTimestamp        types.String `tfsdk:"created_timestamp"`
	ModifiedBy              types.String `tfsdk:"modified_by"`
	ModifiedTimestamp       types.String `tfsdk:"modified_timestamp"`
	HostGroups              types.List   `tfsdk:"host_groups"`
	SensorOperations        types.Object `tfsdk:"sensor_operations"`
	SystemCritical          types.Object `tfsdk:"system_critical"`
	VulnerabilityManagement types.Object `tfsdk:"vulnerability_management"`
	RapidResponse           types.Object `tfsdk:"rapid_response"`
}

func (m policyDataModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":                       types.StringType,
		"name":                     types.StringType,
		"description":              types.StringType,
		"enabled":                  types.BoolType,
		"created_by":               types.StringType,
		"created_timestamp":        types.StringType,
		"modified_by":              types.StringType,
		"modified_timestamp":       types.StringType,
		"host_groups":              types.ListType{ElemType: types.StringType},
		"sensor_operations":        types.ObjectType{AttrTypes: ringAssignmentModel{}.AttributeTypes()},
		"system_critical":          types.ObjectType{AttrTypes: ringAssignmentModel{}.AttributeTypes()},
		"vulnerability_management": types.ObjectType{AttrTypes: ringAssignmentModel{}.AttributeTypes()},
		"rapid_response":           types.ObjectType{AttrTypes: ringAssignmentModel{}.AttributeTypes()},
	}
}

type ContentUpdatePoliciesDataSourceModel struct {
	Filter      types.String `tfsdk:"filter"`
	IDs         types.List   `tfsdk:"ids"`
	Sort        types.String `tfsdk:"sort"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	CreatedBy   types.String `tfsdk:"created_by"`
	ModifiedBy  types.String `tfsdk:"modified_by"`
	Policies    types.List   `tfsdk:"policies"`
}

func (m *ContentUpdatePoliciesDataSourceModel) wrap(ctx context.Context, policies []*models.ContentUpdatePolicyV1) diag.Diagnostics {
	var diags diag.Diagnostics
	policyModels := make([]policyDataModel, 0, len(policies))
	for _, policy := range policies {
		if policy == nil {
			continue
		}

		policyModel := policyDataModel{}

		policyModel.ID = types.StringPointerValue(policy.ID)
		policyModel.Name = types.StringPointerValue(policy.Name)
		policyModel.Description = types.StringPointerValue(policy.Description)
		policyModel.Enabled = types.BoolPointerValue(policy.Enabled)
		policyModel.CreatedBy = types.StringPointerValue(policy.CreatedBy)
		policyModel.CreatedTimestamp = types.StringValue(policy.CreatedTimestamp.String())
		policyModel.ModifiedBy = types.StringPointerValue(policy.ModifiedBy)
		policyModel.ModifiedTimestamp = types.StringValue(policy.ModifiedTimestamp.String())

		hostGroups, hostGroupDiags := hostgroups.ConvertHostGroupsToList(ctx, policy.Groups)
		diags.Append(hostGroupDiags...)
		if diags.HasError() {
			return diags
		}
		policyModel.HostGroups = hostGroups

		if policy.Settings != nil && policy.Settings.RingAssignmentSettings != nil {
			var sensorOperations ringAssignmentModel
			var systemCritical ringAssignmentModel
			var vulnerabilityManagement ringAssignmentModel
			var rapidResponse ringAssignmentModel

			for _, setting := range policy.Settings.RingAssignmentSettings {
				if setting == nil || setting.ID == nil {
					continue
				}
				switch *setting.ID {
				case "sensor_operations":
					sensorOperations.wrap(setting)
				case "system_critical":
					systemCritical.wrap(setting)
				case "vulnerability_management":
					vulnerabilityManagement.wrap(setting)
				case "rapid_response_al_bl_listing":
					rapidResponse.wrap(setting)
				}
			}

			sensorOperationsObj, sensorOpsDiags := utils.ConvertModelToTerraformObject(ctx, &sensorOperations)
			diags.Append(sensorOpsDiags...)
			policyModel.SensorOperations = sensorOperationsObj

			systemCriticalObj, systemCritDiags := utils.ConvertModelToTerraformObject(ctx, &systemCritical)
			diags.Append(systemCritDiags...)
			policyModel.SystemCritical = systemCriticalObj

			vulnMgmtObj, vulnMgmtDiags := utils.ConvertModelToTerraformObject(ctx, &vulnerabilityManagement)
			diags.Append(vulnMgmtDiags...)
			policyModel.VulnerabilityManagement = vulnMgmtObj

			rapidResponseObj, rapidRespDiags := utils.ConvertModelToTerraformObject(ctx, &rapidResponse)
			diags.Append(rapidRespDiags...)
			policyModel.RapidResponse = rapidResponseObj
		}

		policyModels = append(policyModels, policyModel)
	}

	m.Policies = utils.SliceToListTypeObject(ctx, policyModels, policyDataModel{}.AttributeTypes(), &diags)
	return diags
}

// hasIndividualFilters checks if any of the individual filter attributes are set.
func (m ContentUpdatePoliciesDataSourceModel) hasIndividualFilters() bool {
	return utils.IsKnown(m.Name) ||
		utils.IsKnown(m.Description) ||
		utils.IsKnown(m.Enabled) ||
		utils.IsKnown(m.CreatedBy) ||
		utils.IsKnown(m.ModifiedBy)
}

// NewContentUpdatePoliciesDataSource is a helper function to simplify the provider implementation.
func NewContentUpdatePoliciesDataSource() datasource.DataSource {
	return &contentUpdatePoliciesDataSource{}
}

// Metadata returns the data source type name.
func (d *contentUpdatePoliciesDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_content_update_policies"
}

// Schema defines the schema for the data source.
func (d *contentUpdatePoliciesDataSource) Schema(
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
			"filter": schema.StringAttribute{
				Optional:    true,
				Description: "FQL filter to apply to the content update policies query. When specified, only policies matching the filter will be returned. Cannot be used together with 'ids' or other filter attributes. Example: `name:'*prod*'`",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"ids": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "List of content update policy IDs to retrieve. When specified, only policies with matching IDs will be returned. Cannot be used together with 'filter' or other filter attributes.",
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
				Description: "Sort order for the results. Valid values include field names with optional '.asc' or '.desc' suffix. Example: 'name.asc', 'precedence.desc'",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"name": schema.StringAttribute{
				Optional:    true,
				Description: "Filter policies by name. All provided filter attributes must match for a policy to be returned (omitted attributes are ignored). Supports wildcard matching with '*' where '*' matches any sequence of characters until the end of the string or until the next literal character in the pattern is found. Multiple wildcards can be used in a single pattern. Matching is case insensitive. Cannot be used together with 'filter' or 'ids'.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Filter policies by description. All provided filter attributes must match for a policy to be returned (omitted attributes are ignored). Supports wildcard matching with '*' where '*' matches any sequence of characters until the end of the string or until the next literal character in the pattern is found. Multiple wildcards can be used in a single pattern. Matching is case insensitive. Cannot be used together with 'filter' or 'ids'.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Description: "Filter policies by enabled status. All provided filter attributes must match for a policy to be returned (omitted attributes are ignored). Cannot be used together with 'filter' or 'ids'.",
			},
			"created_by": schema.StringAttribute{
				Optional:    true,
				Description: "Filter policies by the user who created them. All provided filter attributes must match for a policy to be returned (omitted attributes are ignored). Supports wildcard matching with '*' where '*' matches any sequence of characters until the end of the string or until the next literal character in the pattern is found. Multiple wildcards can be used in a single pattern. Matching is case insensitive. Cannot be used together with 'filter' or 'ids'.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"modified_by": schema.StringAttribute{
				Optional:    true,
				Description: "Filter policies by the user who last modified them. All provided filter attributes must match for a policy to be returned (omitted attributes are ignored). Supports wildcard matching with '*' where '*' matches any sequence of characters until the end of the string or until the next literal character in the pattern is found. Multiple wildcards can be used in a single pattern. Matching is case insensitive. Cannot be used together with 'filter' or 'ids'.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"policies": schema.ListNestedAttribute{
				Computed:    true,
				Description: "The list of content update policies",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "The content update policy ID",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "The content update policy name",
						},
						"description": schema.StringAttribute{
							Computed:    true,
							Description: "The content update policy description",
						},
						"enabled": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether the content update policy is enabled",
						},
						"created_by": schema.StringAttribute{
							Computed:    true,
							Description: "User who created the policy",
						},
						"created_timestamp": schema.StringAttribute{
							Computed:    true,
							Description: "Timestamp when the policy was created",
						},
						"modified_by": schema.StringAttribute{
							Computed:    true,
							Description: "User who last modified the policy",
						},
						"modified_timestamp": schema.StringAttribute{
							Computed:    true,
							Description: "Timestamp when the policy was last modified",
						},
						"host_groups": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "List of host group IDs assigned to the policy",
						},
						"sensor_operations": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "Ring assignment settings for sensor operations content category",
							Attributes: map[string]schema.Attribute{
								"ring_assignment": schema.StringAttribute{
									Computed:    true,
									Description: "Ring assignment for the content category (ga, ea, pause)",
								},
								"delay_hours": schema.Int64Attribute{
									Computed:    true,
									Description: "Delay in hours when using 'ga' ring assignment",
								},
								"pinned_content_version": schema.StringAttribute{
									Computed:    true,
									Description: "Pinned content version for the content category",
								},
							},
						},
						"system_critical": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "Ring assignment settings for system critical content category",
							Attributes: map[string]schema.Attribute{
								"ring_assignment": schema.StringAttribute{
									Computed:    true,
									Description: "Ring assignment for the content category (ga, ea)",
								},
								"delay_hours": schema.Int64Attribute{
									Computed:    true,
									Description: "Delay in hours when using 'ga' ring assignment",
								},
								"pinned_content_version": schema.StringAttribute{
									Computed:    true,
									Description: "Pinned content version for the content category",
								},
							},
						},
						"vulnerability_management": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "Ring assignment settings for vulnerability management content category",
							Attributes: map[string]schema.Attribute{
								"ring_assignment": schema.StringAttribute{
									Computed:    true,
									Description: "Ring assignment for the content category (ga, ea, pause)",
								},
								"delay_hours": schema.Int64Attribute{
									Computed:    true,
									Description: "Delay in hours when using 'ga' ring assignment",
								},
								"pinned_content_version": schema.StringAttribute{
									Computed:    true,
									Description: "Pinned content version for the content category",
								},
							},
						},
						"rapid_response": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "Ring assignment settings for rapid response allow/block listing content category",
							Attributes: map[string]schema.Attribute{
								"ring_assignment": schema.StringAttribute{
									Computed:    true,
									Description: "Ring assignment for the content category (ga, ea, pause)",
								},
								"delay_hours": schema.Int64Attribute{
									Computed:    true,
									Description: "Delay in hours when using 'ga' ring assignment",
								},
								"pinned_content_version": schema.StringAttribute{
									Computed:    true,
									Description: "Pinned content version for the content category",
								},
							},
						},
					},
				},
			},
		},
	}
}

func (d *contentUpdatePoliciesDataSource) ValidateConfig(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var data ContentUpdatePoliciesDataSourceModel
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
			"Cannot specify 'filter', 'ids', and individual filter attributes (name, description, enabled, created_by, modified_by) together. Please use only one filtering method: either 'filter' for FQL queries, 'ids' for specific IDs, or individual filter attributes.",
		)
	}
}

// getContentUpdatePolicies returns all content update policies matching filter.
func (d *contentUpdatePoliciesDataSource) getContentUpdatePolicies(
	ctx context.Context,
	filter string,
	sort string,
) ([]*models.ContentUpdatePolicyV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	var allPolicies []*models.ContentUpdatePolicyV1

	tflog.Debug(
		ctx,
		"[datasource] Getting all content update policies",
	)

	limit := int64(5000)
	offset := int64(0)

	for {
		params := &content_update_policies.QueryCombinedContentUpdatePoliciesParams{
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

		res, err := d.client.ContentUpdatePolicies.QueryCombinedContentUpdatePolicies(params)
		if err != nil {
			diags.AddError(
				"Failed to query content update policies",
				fmt.Sprintf("Failed to query content update policies: %s", err.Error()),
			)
			return allPolicies, diags
		}

		if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
			tflog.Debug(ctx, "[datasource] No more content update policies to retrieve",
				map[string]interface{}{
					"total_retrieved": len(allPolicies),
				})
			break
		}

		allPolicies = append(allPolicies, res.Payload.Resources...)
		tflog.Debug(ctx, "[datasource] Retrieved page of content update policies",
			map[string]interface{}{
				"page_count":  len(res.Payload.Resources),
				"total_count": len(allPolicies),
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
					"total_retrieved": len(allPolicies),
					"total_available": *res.Payload.Meta.Pagination.Total,
				})
			break
		}
	}

	return allPolicies, diags
}

// Read refreshes the Terraform state with the latest data.
func (d *contentUpdatePoliciesDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data ContentUpdatePoliciesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policies, diags := d.getContentUpdatePolicies(ctx, data.Filter.ValueString(), data.Sort.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if utils.IsKnown(data.IDs) {
		requestedIDs := utils.ListTypeAs[string](ctx, data.IDs, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}

		policies = FilterPoliciesByIDs(policies, requestedIDs)
	}

	if data.hasIndividualFilters() {
		policies = FilterPoliciesByAttributes(policies, &data)
	}

	resp.Diagnostics.Append(data.wrap(ctx, policies)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func FilterPoliciesByIDs(policies []*models.ContentUpdatePolicyV1, requestedIDs []string) []*models.ContentUpdatePolicyV1 {
	idMap := make(map[string]bool, len(requestedIDs))
	for _, id := range requestedIDs {
		idMap[id] = true
	}

	filtered := make([]*models.ContentUpdatePolicyV1, 0, len(requestedIDs))
	for _, policy := range policies {
		if policy != nil && policy.ID != nil && idMap[*policy.ID] {
			filtered = append(filtered, policy)
			if len(filtered) == len(requestedIDs) {
				break
			}
		}
	}
	return filtered
}

func FilterPoliciesByAttributes(policies []*models.ContentUpdatePolicyV1, filters *ContentUpdatePoliciesDataSourceModel) []*models.ContentUpdatePolicyV1 {
	filtered := make([]*models.ContentUpdatePolicyV1, 0, len(policies))
	for _, policy := range policies {
		if policy == nil {
			continue
		}

		if !filters.Name.IsNull() {
			if policy.Name == nil || !utils.MatchesWildcard(*policy.Name, filters.Name.ValueString()) {
				continue
			}
		}

		if !filters.Description.IsNull() {
			if policy.Description == nil || !utils.MatchesWildcard(*policy.Description, filters.Description.ValueString()) {
				continue
			}
		}

		if !filters.CreatedBy.IsNull() {
			if policy.CreatedBy == nil || !utils.MatchesWildcard(*policy.CreatedBy, filters.CreatedBy.ValueString()) {
				continue
			}
		}

		if !filters.ModifiedBy.IsNull() {
			if policy.ModifiedBy == nil || !utils.MatchesWildcard(*policy.ModifiedBy, filters.ModifiedBy.ValueString()) {
				continue
			}
		}

		if !filters.Enabled.IsNull() {
			if policy.Enabled == nil || *policy.Enabled != filters.Enabled.ValueBool() {
				continue
			}
		}

		filtered = append(filtered, policy)
	}
	return filtered
}
