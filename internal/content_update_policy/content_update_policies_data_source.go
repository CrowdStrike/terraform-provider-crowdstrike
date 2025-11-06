package contentupdatepolicy

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/content_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &contentUpdatePoliciesDataSource{}
	_ datasource.DataSourceWithConfigure = &contentUpdatePoliciesDataSource{}
)

// contentUpdatePoliciesDataSource is the data source implementation.
type contentUpdatePoliciesDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type contentUpdatePolicyDataModel struct {
	ID                types.String `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	Description       types.String `tfsdk:"description"`
	Enabled           types.Bool   `tfsdk:"enabled"`
	CreatedBy         types.String `tfsdk:"created_by"`
	CreatedTimestamp  types.String `tfsdk:"created_timestamp"`
	ModifiedBy        types.String `tfsdk:"modified_by"`
	ModifiedTimestamp types.String `tfsdk:"modified_timestamp"`
	Groups            types.List   `tfsdk:"groups"`
}

type contentUpdatePoliciesDataSourceModel struct {
	ID       types.String `tfsdk:"id"`
	Filter   types.String `tfsdk:"filter"`
	IDs      types.List   `tfsdk:"ids"`
	Sort     types.String `tfsdk:"sort"`
	Enabled  types.Bool   `tfsdk:"enabled"`
	Platform types.String `tfsdk:"platform"`
	Policies types.List   `tfsdk:"policies"`
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
		MarkdownDescription: fmt.Sprintf(
			"Content Update Policies --- This data source provides information about content update policies in Falcon.\n\n%s",
			scopes.GenerateScopeDescription([]scopes.Scope{
				{
					Name:  "Content update policies",
					Read:  true,
					Write: false,
				},
			}),
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for this data source",
			},
			"filter": schema.StringAttribute{
				Optional: true,
				Description: "FQL filter to apply to the content update policies query. " +
					"When specified, only policies matching the filter will be returned. " +
					"Cannot be used together with 'ids' or other filter attributes. " +
					"Example: `enabled:true`",
			},
			"ids": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "List of content update policy IDs to retrieve. " +
					"When specified, only policies with matching IDs will be returned. " +
					"Cannot be used together with 'filter' or other filter attributes.",
			},
			"sort": schema.StringAttribute{
				Optional: true,
				Description: "Sort order for the results. " +
					"Valid values include field names with optional '.asc' or '.desc' suffix. " +
					"Example: 'name.asc', 'created_timestamp.desc'",
			},
			"enabled": schema.BoolAttribute{
				Optional: true,
				Description: "Filter policies by enabled status. " +
					"Cannot be used together with 'filter' or 'ids'.",
			},
			"platform": schema.StringAttribute{
				Optional: true,
				Description: "Filter policies by platform. " +
					"Valid values include 'windows', 'mac', 'linux'. " +
					"Cannot be used together with 'filter' or 'ids'.",
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
						"groups": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "List of host group IDs assigned to the policy",
						},
					},
				},
			},
		},
	}
}

// getContentUpdatePoliciesWithFilter retrieves content update policies using a filter.
func (d *contentUpdatePoliciesDataSource) getContentUpdatePoliciesWithFilter(
	ctx context.Context,
	filter string,
	sort string,
) ([]*models.ContentUpdatePolicyV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	tflog.Info(
		ctx,
		"[datasource] Getting content update policies with filter",
		map[string]interface{}{"filter": filter, "sort": sort},
	)

	params := &content_update_policies.QueryCombinedContentUpdatePoliciesParams{
		Context: ctx,
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
		return nil, diags
	}

	if res == nil || res.Payload == nil {
		diags.AddError(
			"Failed to query content update policies",
			"Received empty response from content update policies query",
		)
		return nil, diags
	}

	return res.Payload.Resources, diags
}

// getContentUpdatePoliciesByIDs retrieves content update policies by their IDs.
func (d *contentUpdatePoliciesDataSource) getContentUpdatePoliciesByIDs(
	ctx context.Context,
	ids []string,
) ([]*models.ContentUpdatePolicyV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	tflog.Info(
		ctx,
		"[datasource] Getting content update policies by IDs",
		map[string]interface{}{"ids": ids},
	)

	res, err := d.client.ContentUpdatePolicies.GetContentUpdatePolicies(
		&content_update_policies.GetContentUpdatePoliciesParams{
			Context: ctx,
			Ids:     ids,
		},
	)

	if err != nil {
		diags.AddError(
			"Failed to get content update policies",
			fmt.Sprintf("Failed to get content update policies by IDs: %s", err.Error()),
		)
		return nil, diags
	}

	if res == nil || res.Payload == nil {
		diags.AddError(
			"Failed to get content update policies",
			"Received empty response from content update policies get request",
		)
		return nil, diags
	}

	return res.Payload.Resources, diags
}

// convertToDataModel converts a content update policy API model to the data source model.
func convertToDataModel(policy *models.ContentUpdatePolicyV1) *contentUpdatePolicyDataModel {
	if policy == nil {
		return nil
	}

	// Convert host groups
	groups := make([]attr.Value, 0, len(policy.Groups))
	for _, group := range policy.Groups {
		if group.ID != nil {
			groups = append(groups, types.StringValue(*group.ID))
		}
	}

	model := &contentUpdatePolicyDataModel{
		Groups: types.ListValueMust(types.StringType, groups),
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
func (d *contentUpdatePoliciesDataSource) hasIndividualFilters(data *contentUpdatePoliciesDataSourceModel) bool {
	return (!data.Enabled.IsNull() && !data.Enabled.IsUnknown()) ||
		(!data.Platform.IsNull() && !data.Platform.IsUnknown())
}

// buildFQLFromAttributes constructs an FQL filter from individual filter attributes.
func (d *contentUpdatePoliciesDataSource) buildFQLFromAttributes(ctx context.Context, data *contentUpdatePoliciesDataSourceModel) string {
	var filters []string

	// enabled filter
	if !data.Enabled.IsNull() && !data.Enabled.IsUnknown() {
		enabled := data.Enabled.ValueBool()
		filters = append(filters, fmt.Sprintf("enabled:%t", enabled))
	}

	// platform filter
	if !data.Platform.IsNull() && !data.Platform.IsUnknown() {
		value := data.Platform.ValueString()
		if value != "" {
			filters = append(filters, fmt.Sprintf("platform_name:'%s'", value))
		}
	}

	// Join all filters with AND (+)
	if len(filters) == 0 {
		return ""
	}

	fqlFilter := strings.Join(filters, "+")

	// Add debug logging to see what filter is generated
	tflog.Info(
		ctx,
		"[datasource] Generated FQL filter from individual attributes",
		map[string]interface{}{"filter": fqlFilter, "filter_count": len(filters)},
	)

	return fqlFilter
}

// Read refreshes the Terraform state with the latest data.
func (d *contentUpdatePoliciesDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data contentUpdatePoliciesDataSourceModel
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
			"Cannot specify 'filter', 'ids', and individual filter attributes (enabled, platform) together. "+
				"Please use only one filtering method: either 'filter' for FQL queries, 'ids' for specific IDs, "+
				"or individual filter attributes.",
		)
		return
	}

	var policies []*models.ContentUpdatePolicyV1
	var diags diag.Diagnostics
	var dataSourceID string

	if hasIDs {
		// Get policies by IDs
		var ids []string
		resp.Diagnostics.Append(data.IDs.ElementsAs(ctx, &ids, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		policies, diags = d.getContentUpdatePoliciesByIDs(ctx, ids)
		dataSourceID = "ids"
	} else {
		// Get policies with filter (or all if no filter)
		filter := ""

		if hasFilter {
			filter = data.Filter.ValueString()
		} else if hasIndividualFilters {
			// Build FQL filter from individual attributes
			filter = d.buildFQLFromAttributes(ctx, &data)
		}

		sort := ""
		if !data.Sort.IsNull() && !data.Sort.IsUnknown() {
			sort = data.Sort.ValueString()
		}

		policies, diags = d.getContentUpdatePoliciesWithFilter(ctx, filter, sort)

		// Set appropriate data source ID
		if hasFilter || hasIndividualFilters {
			dataSourceID = "filtered"
		} else {
			dataSourceID = "all"
		}
	}

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert API models to data models
	policyModels := make([]*contentUpdatePolicyDataModel, 0, len(policies))
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
			"enabled":            types.BoolType,
			"created_by":         types.StringType,
			"created_timestamp":  types.StringType,
			"modified_by":        types.StringType,
			"modified_timestamp": types.StringType,
			"groups":             types.ListType{ElemType: types.StringType},
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
			"enabled":            types.BoolType,
			"created_by":         types.StringType,
			"created_timestamp":  types.StringType,
			"modified_by":        types.StringType,
			"modified_timestamp": types.StringType,
			"groups":             types.ListType{ElemType: types.StringType},
		},
	}, policyValues)
	resp.Diagnostics.Append(policiesListDiag...)
	if resp.Diagnostics.HasError() {
		return
	}

	data.Policies = policiesList

	// Set ID based on filtering method used
	data.ID = types.StringValue(dataSourceID)

	// Set state
	diags = resp.State.Set(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

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
