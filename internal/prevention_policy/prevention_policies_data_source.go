package preventionpolicy

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/prevention_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
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
	dataSourceDocumentationSection = "Prevention Policies"
	dataSourceMarkdownDescription  = "This data source provides information about prevention policies in Falcon."
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &preventionPoliciesDataSource{}
	_ datasource.DataSourceWithConfigure = &preventionPoliciesDataSource{}
)

// preventionPoliciesDataSource is the data source implementation.
type preventionPoliciesDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type preventionPolicyDataModel struct {
	ID                types.String `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	Description       types.String `tfsdk:"description"`
	PlatformName      types.String `tfsdk:"platform_name"`
	Enabled           types.Bool   `tfsdk:"enabled"`
	CreatedBy         types.String `tfsdk:"created_by"`
	CreatedTimestamp  types.String `tfsdk:"created_timestamp"`
	ModifiedBy        types.String `tfsdk:"modified_by"`
	ModifiedTimestamp types.String `tfsdk:"modified_timestamp"`
	HostGroups        types.List   `tfsdk:"host_groups"`
	IoaRuleGroups     types.List   `tfsdk:"ioa_rule_groups"`
}

type preventionPoliciesDataSourceModel struct {
	Filter      types.String `tfsdk:"filter"`
	IDs         types.List   `tfsdk:"ids"`
	Sort        types.String `tfsdk:"sort"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	Platform    types.String `tfsdk:"platform"`
	Policies    types.List   `tfsdk:"policies"`
}

// buildResult holds the results from building an FQL filter with client-side filtering info.
type buildResult struct {
	filter           string
	nameClientFilter func(string) bool
	descClientFilter func(string) bool
	needsNameFilter  bool
	needsDescFilter  bool
}

// NewPreventionPoliciesDataSource is a helper function to simplify the provider implementation.
func NewPreventionPoliciesDataSource() datasource.DataSource {
	return &preventionPoliciesDataSource{}
}

// Metadata returns the data source type name.
func (d *preventionPoliciesDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_prevention_policies"
}

// Schema defines the schema for the data source.
func (d *preventionPoliciesDataSource) Schema(
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
				Optional: true,
				Description: "FQL filter to apply to the prevention policies query. " +
					"When specified, only policies matching the filter will be returned. " +
					"Cannot be used together with 'ids' or other filter attributes. " +
					"Example: `platform_name:'Windows'`",
			},
			"ids": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "List of prevention policy IDs to retrieve. " +
					"When specified, only policies with matching IDs will be returned. " +
					"Cannot be used together with 'filter' or other filter attributes.",
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.LengthBetween(32, 32),
					),
				},
			},
			"sort": schema.StringAttribute{
				Optional: true,
				Description: "Sort order for the results. " +
					"Valid values include field names with optional '.asc' or '.desc' suffix. " +
					"Example: 'name.asc', 'precedence.desc'",
			},
			"name": schema.StringAttribute{
				Optional: true,
				Description: "Filter policies by name. Supports exact matching and wildcard patterns. " +
					"Without wildcard (*): Returns policies with names that exactly match the specified value (e.g., 'production server' matches only 'production server'). " +
					"With wildcard (*): Returns policies whose names contain the specified pattern (e.g., 'production*' matches 'production server', 'production lab', etc.). " +
					"Cannot be used together with 'filter' or 'ids'.",
			},
			"description": schema.StringAttribute{
				Optional: true,
				Description: "Filter policies by description. Supports exact matching and wildcard patterns. " +
					"Without wildcard (*): Returns policies with descriptions that exactly match the specified value (e.g., 'malware protection' matches only 'malware protection'). " +
					"With wildcard (*): Returns policies whose descriptions contain the specified pattern (e.g., 'malware*' matches 'malware protection', 'malware detection', etc.). " +
					"Cannot be used together with 'filter' or 'ids'.",
			},
			"enabled": schema.BoolAttribute{
				Optional: true,
				Description: "Filter policies by enabled status. " +
					"Cannot be used together with 'filter' or 'ids'.",
			},
			"platform": schema.StringAttribute{
				Optional: true,
				Description: "Filter policies by platform (Windows, Linux, Mac). " +
					"Cannot be used together with 'filter' or 'ids'.",
			},
			"policies": schema.ListNestedAttribute{
				Computed:    true,
				Description: "The list of prevention policies",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "The prevention policy ID",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "The prevention policy name",
						},
						"description": schema.StringAttribute{
							Computed:    true,
							Description: "The prevention policy description",
						},
						"platform_name": schema.StringAttribute{
							Computed:    true,
							Description: "The platform name (Windows, Linux, Mac)",
						},
						"enabled": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether the prevention policy is enabled",
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
						"ioa_rule_groups": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "List of IOA rule group IDs associated with the policy",
						},
					},
				},
			},
		},
	}
}

// getPreventionPoliciesWithFilter retrieves prevention policies using a filter.
func (d *preventionPoliciesDataSource) getPreventionPoliciesWithFilter(
	ctx context.Context,
	filter string,
	sort string,
) ([]*models.PreventionPolicyV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	var allPolicies []*models.PreventionPolicyV1

	tflog.Info(
		ctx,
		"[datasource] Getting prevention policies with filter",
		map[string]interface{}{"filter": filter, "sort": sort},
	)

	limit := int64(5000)
	offset := int64(0)

	for {
		params := &prevention_policies.QueryCombinedPreventionPoliciesParams{
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

		res, err := d.client.PreventionPolicies.QueryCombinedPreventionPolicies(params)
		if err != nil {
			diags.AddError(
				"Failed to query prevention policies",
				fmt.Sprintf("Failed to query prevention policies: %s", err.Error()),
			)
			return allPolicies, diags
		}

		if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
			tflog.Debug(ctx, "[datasource] No more prevention policies to retrieve",
				map[string]interface{}{
					"total_retrieved": len(allPolicies),
				})
			break
		}

		allPolicies = append(allPolicies, res.Payload.Resources...)
		tflog.Debug(ctx, "[datasource] Retrieved page of prevention policies",
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

// getPreventionPoliciesByIDs retrieves prevention policies by their IDs.
func (d *preventionPoliciesDataSource) getPreventionPoliciesByIDs(
	ctx context.Context,
	ids []string,
) ([]*models.PreventionPolicyV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	tflog.Info(
		ctx,
		"[datasource] Getting prevention policies by IDs",
		map[string]interface{}{"ids": ids},
	)

	res, err := d.client.PreventionPolicies.GetPreventionPolicies(
		&prevention_policies.GetPreventionPoliciesParams{
			Context: ctx,
			Ids:     ids,
		},
	)

	if err != nil {
		if notFound, ok := err.(*prevention_policies.GetPreventionPoliciesNotFound); ok {
			if notFound == nil || notFound.Payload == nil {
				return []*models.PreventionPolicyV1{}, diags
			}
			return notFound.Payload.Resources, diags
		}
		diags.AddError(
			"Failed to get prevention policies",
			fmt.Sprintf("Failed to get prevention policies by IDs: %s", err.Error()),
		)
		return nil, diags
	}

	if res == nil || res.Payload == nil {
		return []*models.PreventionPolicyV1{}, diags
	}

	return res.Payload.Resources, diags
}

// convertToDataModel converts a prevention policy API model to the data source model.
func convertToDataModel(policy *models.PreventionPolicyV1) *preventionPolicyDataModel {
	if policy == nil {
		return nil
	}

	// Convert host groups
	groups := make([]attr.Value, 0, len(policy.Groups))
	for _, group := range policy.Groups {
		if group != nil && group.ID != nil {
			groups = append(groups, types.StringPointerValue(group.ID))
		}
	}

	// Convert IOA rule groups
	ioaRuleGroups := make([]attr.Value, 0, len(policy.IoaRuleGroups))
	for _, group := range policy.IoaRuleGroups {
		if group.ID != nil {
			ioaRuleGroups = append(ioaRuleGroups, types.StringValue(*group.ID))
		}
	}

	model := &preventionPolicyDataModel{
		HostGroups:    types.ListValueMust(types.StringType, groups),
		IoaRuleGroups: types.ListValueMust(types.StringType, ioaRuleGroups),
	}

	// Set string fields with null checks
	if policy.ID != nil {
		model.ID = types.StringValue(*policy.ID)
	} else {
		model.ID = types.StringNull()
	}

	if policy.Name != nil {
		model.Name = types.StringValue(*policy.Name)
	} else {
		model.Name = types.StringNull()
	}

	if policy.Description != nil {
		model.Description = types.StringValue(*policy.Description)
	} else {
		model.Description = types.StringNull()
	}

	if policy.PlatformName != nil {
		model.PlatformName = types.StringValue(*policy.PlatformName)
	} else {
		model.PlatformName = types.StringNull()
	}

	if policy.CreatedBy != nil {
		model.CreatedBy = types.StringValue(*policy.CreatedBy)
	} else {
		model.CreatedBy = types.StringNull()
	}

	if policy.CreatedTimestamp != nil {
		model.CreatedTimestamp = types.StringValue(policy.CreatedTimestamp.String())
	} else {
		model.CreatedTimestamp = types.StringNull()
	}

	if policy.ModifiedBy != nil {
		model.ModifiedBy = types.StringValue(*policy.ModifiedBy)
	} else {
		model.ModifiedBy = types.StringNull()
	}

	if policy.ModifiedTimestamp != nil {
		model.ModifiedTimestamp = types.StringValue(policy.ModifiedTimestamp.String())
	} else {
		model.ModifiedTimestamp = types.StringNull()
	}

	// Set boolean field
	if policy.Enabled != nil {
		model.Enabled = types.BoolValue(*policy.Enabled)
	} else {
		model.Enabled = types.BoolNull()
	}

	return model
}

// hasIndividualFilters checks if any of the individual filter attributes are set.
func (d *preventionPoliciesDataSource) hasIndividualFilters(data *preventionPoliciesDataSourceModel) bool {
	return (!data.Name.IsNull() && !data.Name.IsUnknown()) ||
		(!data.Description.IsNull() && !data.Description.IsUnknown()) ||
		(!data.Enabled.IsNull() && !data.Enabled.IsUnknown()) ||
		(!data.Platform.IsNull() && !data.Platform.IsUnknown())
}

// buildFQLFromAttributesWithClientFiltering constructs an FQL filter from individual filter attributes
// and returns the necessary client-side filtering functions.
func (d *preventionPoliciesDataSource) buildFQLFromAttributesWithClientFiltering(ctx context.Context, data *preventionPoliciesDataSourceModel) buildResult {
	var filters []string
	result := buildResult{
		nameClientFilter: func(string) bool { return true },
		descClientFilter: func(string) bool { return true },
		needsNameFilter:  false,
		needsDescFilter:  false,
	}

	// name filter
	if !data.Name.IsNull() && !data.Name.IsUnknown() {
		value := data.Name.ValueString()
		if value != "" {
			nameQuery := utils.ProcessNameSearchPattern(value)
			if nameQuery.APIQuery != "" {
				filters = append(filters, nameQuery.APIQuery)
			}
			if nameQuery.NeedsClientFilter {
				result.nameClientFilter = nameQuery.ClientFilter
				result.needsNameFilter = true
			}
		}
	}

	// description filter
	if !data.Description.IsNull() && !data.Description.IsUnknown() {
		value := data.Description.ValueString()
		if value != "" {
			descQuery := utils.ProcessDescriptionSearchPattern(value)
			if descQuery.APIQuery != "" {
				filters = append(filters, descQuery.APIQuery)
			}
			if descQuery.NeedsClientFilter {
				result.descClientFilter = descQuery.ClientFilter
				result.needsDescFilter = true
			}
		}
	}

	// enabled filter
	if !data.Enabled.IsNull() && !data.Enabled.IsUnknown() {
		enabled := data.Enabled.ValueBool()
		filters = append(filters, fmt.Sprintf("enabled:%t", enabled))
	}

	// platform filter (map to platform_name)
	if !data.Platform.IsNull() && !data.Platform.IsUnknown() {
		value := data.Platform.ValueString()
		if value != "" {
			filters = append(filters, fmt.Sprintf("platform_name:'%s'", value))
		}
	}

	// Join all filters with AND (+)
	if len(filters) == 0 {
		result.filter = ""
	} else {
		result.filter = strings.Join(filters, "+")
	}

	// Add debug logging to see what filter is generated
	tflog.Info(
		ctx,
		"[datasource] Generated FQL filter from individual attributes with client filtering",
		map[string]interface{}{
			"filter":            result.filter,
			"filter_count":      len(filters),
			"needs_name_filter": result.needsNameFilter,
			"needs_desc_filter": result.needsDescFilter,
		},
	)

	return result
}

// applyClientSideFiltering applies client-side filtering to the policies based on name and description patterns.
func (d *preventionPoliciesDataSource) applyClientSideFiltering(
	ctx context.Context,
	policies []*models.PreventionPolicyV1,
	buildRes buildResult,
) []*models.PreventionPolicyV1 {
	if !buildRes.needsNameFilter && !buildRes.needsDescFilter {
		// No client-side filtering needed
		return policies
	}

	var filtered []*models.PreventionPolicyV1
	filteredCount := 0

	for _, policy := range policies {
		include := true

		// Apply name filtering if needed
		if buildRes.needsNameFilter && policy.Name != nil {
			if !buildRes.nameClientFilter(*policy.Name) {
				include = false
			}
		}

		// Apply description filtering if needed
		if include && buildRes.needsDescFilter && policy.Description != nil {
			if !buildRes.descClientFilter(*policy.Description) {
				include = false
			}
		}

		if include {
			filtered = append(filtered, policy)
			filteredCount++
		}
	}

	tflog.Info(
		ctx,
		"[datasource] Applied client-side filtering",
		map[string]interface{}{
			"original_count": len(policies),
			"filtered_count": filteredCount,
		},
	)

	return filtered
}

// Read refreshes the Terraform state with the latest data.
func (d *preventionPoliciesDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data preventionPoliciesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check what filtering methods are being used
	hasFilter := !data.Filter.IsNull() && !data.Filter.IsUnknown() && data.Filter.ValueString() != ""
	hasIDs := !data.IDs.IsNull() && !data.IDs.IsUnknown() && len(data.IDs.Elements()) > 0
	hasIndividualFilters := d.hasIndividualFilters(&data)

	// Validate mutual exclusivity
	filterCount := 0
	if hasFilter {
		filterCount++
	}
	if hasIDs {
		filterCount++
	}
	if hasIndividualFilters {
		filterCount++
	}

	if filterCount > 1 {
		resp.Diagnostics.AddError(
			"Invalid Attribute Combination",
			"Cannot specify 'filter', 'ids', and individual filter attributes (name, description, enabled, platform) together. "+
				"Please use only one filtering method: either 'filter' for FQL queries, 'ids' for specific IDs, "+
				"or individual filter attributes.",
		)
		return
	}

	var policies []*models.PreventionPolicyV1
	var diags diag.Diagnostics
	var buildRes buildResult

	if hasIDs {
		// Get policies by IDs
		var ids []string
		resp.Diagnostics.Append(data.IDs.ElementsAs(ctx, &ids, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		policies, diags = d.getPreventionPoliciesByIDs(ctx, ids)
	} else {
		// Get policies with filter (or all if no filter)
		filter := ""

		if hasFilter {
			filter = data.Filter.ValueString()
			// No client-side filtering needed for direct filters
			buildRes = buildResult{
				filter:           filter,
				nameClientFilter: func(string) bool { return true },
				descClientFilter: func(string) bool { return true },
				needsNameFilter:  false,
				needsDescFilter:  false,
			}
		} else if hasIndividualFilters {
			// Build FQL filter from individual attributes with client filtering
			buildRes = d.buildFQLFromAttributesWithClientFiltering(ctx, &data)
			filter = buildRes.filter
		}

		sort := ""
		if !data.Sort.IsNull() && !data.Sort.IsUnknown() {
			sort = data.Sort.ValueString()
		}

		policies, diags = d.getPreventionPoliciesWithFilter(ctx, filter, sort)
	}

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply client-side filtering if needed
	if hasIndividualFilters {
		policies = d.applyClientSideFiltering(ctx, policies, buildRes)
	}

	// Convert API models to data models
	policyModels := make([]*preventionPolicyDataModel, 0, len(policies))
	for _, policy := range policies {
		if convertedPolicy := convertToDataModel(policy); convertedPolicy != nil {
			policyModels = append(policyModels, convertedPolicy)
		}
	}

	// Convert to types.List
	policyValues := make([]attr.Value, 0, len(policyModels))
	for _, policy := range policyModels {
		policyValue, policiesDiag := types.ObjectValueFrom(ctx, map[string]attr.Type{
			"id":                 types.StringType,
			"name":               types.StringType,
			"description":        types.StringType,
			"platform_name":      types.StringType,
			"enabled":            types.BoolType,
			"created_by":         types.StringType,
			"created_timestamp":  types.StringType,
			"modified_by":        types.StringType,
			"modified_timestamp": types.StringType,
			"host_groups":        types.ListType{ElemType: types.StringType},
			"ioa_rule_groups":    types.ListType{ElemType: types.StringType},
		}, policy)
		resp.Diagnostics.Append(policiesDiag...)
		if resp.Diagnostics.HasError() {
			return
		}
		policyValues = append(policyValues, policyValue)
	}

	policiesList, policiesListDiag := types.ListValue(types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"id":                 types.StringType,
			"name":               types.StringType,
			"description":        types.StringType,
			"platform_name":      types.StringType,
			"enabled":            types.BoolType,
			"created_by":         types.StringType,
			"created_timestamp":  types.StringType,
			"modified_by":        types.StringType,
			"modified_timestamp": types.StringType,
			"host_groups":        types.ListType{ElemType: types.StringType},
			"ioa_rule_groups":    types.ListType{ElemType: types.StringType},
		},
	}, policyValues)
	resp.Diagnostics.Append(policiesListDiag...)
	if resp.Diagnostics.HasError() {
		return
	}

	data.Policies = policiesList

	// Set state
	diags = resp.State.Set(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Configure adds the provider configured client to the data source.
func (d *preventionPoliciesDataSource) Configure(
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
