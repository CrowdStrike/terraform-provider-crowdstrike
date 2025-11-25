package fim

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/filevantage"
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
	dataSourceDocumentationSection = "Filevantage"
	dataSourceMarkdownDescription  = "This data source provides information about file vantage policies in Falcon."
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource                   = &filevantagePoliciesDataSource{}
	_ datasource.DataSourceWithConfigure      = &filevantagePoliciesDataSource{}
	_ datasource.DataSourceWithValidateConfig = &filevantagePoliciesDataSource{}
)

// Configure adds the provider configured client to the data source.
func (d *filevantagePoliciesDataSource) Configure(
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

// filevantagePoliciesDataSource is the data source implementation.
type filevantagePoliciesDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type policyDataModel struct {
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

func (m policyDataModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
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
	}
}

type filevantagePoliciesDataSourceModel struct {
	Type     types.String `tfsdk:"type"`
	IDs      types.List   `tfsdk:"ids"`
	Sort     types.String `tfsdk:"sort"`
	Policies types.List   `tfsdk:"policies"`
}

func (m *filevantagePoliciesDataSourceModel) wrap(ctx context.Context, policies []*models.PoliciesPolicy) diag.Diagnostics {
	var diags diag.Diagnostics
	policyModels := make([]policyDataModel, 0, len(policies))
	for _, policy := range policies {
		if policy == nil {
			continue
		}

		policyModel := policyDataModel{}

		policyModel.ID = types.StringValue(*policy.ID)
		policyModel.Name = types.StringValue(policy.Name)
		policyModel.Description = types.StringValue(policy.Description)
		policyModel.PlatformName = types.StringValue(policy.Platform)
		policyModel.Enabled = types.BoolValue(*policy.Enabled)

		// These fields are not available on models.PoliciesPolicy
		policyModel.CreatedBy = types.StringValue("")
		policyModel.CreatedTimestamp = types.StringValue("")
		policyModel.ModifiedBy = types.StringValue("")
		policyModel.ModifiedTimestamp = types.StringValue("")

		// Convert host groups
		var hostGroupIDs []string
		for _, hostGroup := range policy.HostGroups {
			if hostGroup.ID != nil {
				hostGroupIDs = append(hostGroupIDs, *hostGroup.ID)
			}
		}
		hostGroupList, diag := types.ListValueFrom(ctx, types.StringType, hostGroupIDs)
		if diag.HasError() {
			diags.Append(diag...)
			return diags
		}
		policyModel.HostGroups = hostGroupList

		// Convert rule groups
		var ruleGroupIDs []string
		for _, ruleGroup := range policy.RuleGroups {
			if ruleGroup.ID != nil {
				ruleGroupIDs = append(ruleGroupIDs, *ruleGroup.ID)
			}
		}
		ruleGroupList, diag := types.ListValueFrom(ctx, types.StringType, ruleGroupIDs)
		if diag.HasError() {
			diags.Append(diag...)
			return diags
		}
		policyModel.IoaRuleGroups = ruleGroupList

		policyModels = append(policyModels, policyModel)
	}

	m.Policies = utils.SliceToListTypeObject(ctx, policyModels, policyDataModel{}.AttributeTypes(), &diags)
	return diags
}

// NewFilevantagePoliciesDataSource is a helper function to simplify the provider implementation.
func NewFilevantagePoliciesDataSource() datasource.DataSource {
	return &filevantagePoliciesDataSource{}
}

// Metadata returns the data source type name.
func (d *filevantagePoliciesDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_filevantage_policies"
}

// Schema defines the schema for the data source.
func (d *filevantagePoliciesDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			dataSourceDocumentationSection,
			dataSourceMarkdownDescription,
			apiScopesRead,
		),
		Attributes: map[string]schema.Attribute{
			"type": schema.StringAttribute{
				Optional:    true,
				Description: "Filter policies by platform type (Windows, Linux, Mac). Uses the /filevantage/queries/policies/v1 endpoint. Cannot be used together with 'ids'.",
				Validators: []validator.String{
					stringvalidator.OneOf("Windows", "Linux", "Mac"),
				},
			},
			"ids": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "List of file vantage policy IDs to retrieve. Uses the /filevantage/entities/policies/v1 endpoint. Cannot be used together with 'type'.",
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
				Description: "Sort order for the results. Can be used with 'type'. Valid values include field names with optional '.asc' or '.desc' suffix. Example: 'name.asc', 'precedence.desc'",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"policies": schema.ListNestedAttribute{
				Computed:    true,
				Description: "The list of file vantage policies",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "The file vantage policy ID",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "The file vantage policy name",
						},
						"description": schema.StringAttribute{
							Computed:    true,
							Description: "The file vantage policy description",
						},
						"platform_name": schema.StringAttribute{
							Computed:    true,
							Description: "The platform name (Windows, Linux, Mac)",
						},
						"enabled": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether the file vantage policy is enabled",
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

func (d *filevantagePoliciesDataSource) ValidateConfig(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var data filevantagePoliciesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	hasType := utils.IsKnown(data.Type) && data.Type.ValueString() != ""
	hasIDs := utils.IsKnown(data.IDs) && len(data.IDs.Elements()) > 0

	if hasType && hasIDs {
		resp.Diagnostics.AddError(
			"Invalid Attribute Combination",
			"Cannot specify both 'type' and 'ids' together. Please use only one: either 'type' for filtering by platform type, or 'ids' for retrieving specific policies by ID.",
		)
	}

	// Require at least one of type or ids
	if !hasType && !hasIDs {
		resp.Diagnostics.AddError(
			"Missing Required Attribute",
			"Either 'type' or 'ids' must be specified. Use 'type' to filter by platform type (Windows, Linux, Mac) or 'ids' to retrieve specific policies by ID.",
		)
	}
}

// getFilevantagePolicies returns all file vantage policies matching type using QueryPolicies + GetPolicies.
func (d *filevantagePoliciesDataSource) getFilevantagePolicies(
	ctx context.Context,
	platformType string,
	sort string,
) ([]*models.PoliciesPolicy, diag.Diagnostics) {
	var diags diag.Diagnostics

	tflog.Debug(
		ctx,
		"[datasource] Getting file vantage policies with type",
		map[string]interface{}{
			"type": platformType,
			"sort": sort,
		},
	)

	// Step 1: Query policy IDs with filtering and sorting
	var allPolicyIDs []string
	limit := int64(500) // API maximum is 500
	offset := int64(0)

	for {
		queryParams := &filevantage.QueryPoliciesParams{
			Context: ctx,
			Limit:   &limit,
			Offset:  &offset,
		}

		if platformType != "" {
			queryParams.Type = platformType
		}

		if sort != "" {
			queryParams.Sort = &sort
		}

		queryRes, err := d.client.Filevantage.QueryPolicies(queryParams)
		if err != nil {
			diags.AddError(
				"Failed to query file vantage policy IDs",
				fmt.Sprintf("Failed to query file vantage policy IDs: %s", err.Error()),
			)
			return nil, diags
		}

		if queryRes == nil || queryRes.Payload == nil || len(queryRes.Payload.Resources) == 0 {
			tflog.Debug(ctx, "[datasource] No more file vantage policy IDs to retrieve",
				map[string]interface{}{
					"total_retrieved": len(allPolicyIDs),
				})
			break
		}

		allPolicyIDs = append(allPolicyIDs, queryRes.Payload.Resources...)
		tflog.Debug(ctx, "[datasource] Retrieved page of file vantage policy IDs",
			map[string]interface{}{
				"page_count":  len(queryRes.Payload.Resources),
				"total_count": len(allPolicyIDs),
			})

		// Check if there are more pages
		if queryRes.Payload.Meta == nil || queryRes.Payload.Meta.Pagination == nil ||
			queryRes.Payload.Meta.Pagination.Offset == nil || queryRes.Payload.Meta.Pagination.Total == nil {
			tflog.Warn(ctx, "Missing pagination metadata in API response, using offset+limit for next page",
				map[string]interface{}{
					"meta": queryRes.Payload.Meta,
				})
			offset += limit
			continue
		}

		offset = int64(*queryRes.Payload.Meta.Pagination.Offset) + int64(*queryRes.Payload.Meta.Pagination.Limit)
		if offset >= *queryRes.Payload.Meta.Pagination.Total {
			break
		}
	}

	if len(allPolicyIDs) == 0 {
		tflog.Debug(ctx, "[datasource] No file vantage policies found matching filter")
		return []*models.PoliciesPolicy{}, diags
	}

	// Step 2: Get full policy details for all IDs
	return d.getFilevantagePoliciesByIDs(ctx, allPolicyIDs)
}

// getFilevantagePoliciesByIDs returns file vantage policies by their IDs using the entities endpoint.
func (d *filevantagePoliciesDataSource) getFilevantagePoliciesByIDs(
	ctx context.Context,
	ids []string,
) ([]*models.PoliciesPolicy, diag.Diagnostics) {
	var diags diag.Diagnostics

	tflog.Debug(
		ctx,
		"[datasource] Getting file vantage policies by IDs",
		map[string]interface{}{
			"ids": ids,
		},
	)

	params := &filevantage.GetPoliciesParams{
		Context: ctx,
		Ids:     ids,
	}

	res, err := d.client.Filevantage.GetPolicies(params)
	if err != nil {
		diags.AddError(
			"Failed to get file vantage policies by IDs",
			fmt.Sprintf("Failed to get file vantage policies by IDs: %s", err.Error()),
		)
		return nil, diags
	}

	if res == nil || res.Payload == nil {
		diags.AddError(
			"Empty response",
			"Received empty response when getting file vantage policies by IDs",
		)
		return nil, diags
	}

	tflog.Debug(ctx, "[datasource] Retrieved file vantage policies by IDs",
		map[string]interface{}{
			"requested_count": len(ids),
			"returned_count":  len(res.Payload.Resources),
		})

	return res.Payload.Resources, diags
}

// Read refreshes the Terraform state with the latest data.
func (d *filevantagePoliciesDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data filevantagePoliciesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var policies []*models.PoliciesPolicy
	var diags diag.Diagnostics

	// Route to appropriate endpoint based on input
	if utils.IsKnown(data.IDs) && len(data.IDs.Elements()) > 0 {
		// Use entities endpoint for specific IDs
		requestedIDs := utils.ListTypeAs[string](ctx, data.IDs, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}

		policies, diags = d.getFilevantagePoliciesByIDs(ctx, requestedIDs)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

	} else if utils.IsKnown(data.Type) && data.Type.ValueString() != "" {
		// Use queries endpoint with type filter
		sort := ""
		if utils.IsKnown(data.Sort) {
			sort = data.Sort.ValueString()
		}

		policies, diags = d.getFilevantagePolicies(ctx, data.Type.ValueString(), sort)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	resp.Diagnostics.Append(data.wrap(ctx, policies)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
