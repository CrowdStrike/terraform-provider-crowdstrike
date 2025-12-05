package fim

import (
	"context"
	"fmt"
	"regexp"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/filevantage"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/boolvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const (
	dataSourceDocumentationSection = "FileVantage"
	dataSourceMarkdownDescription  = "This data source provides information about FileVantage policies in Falcon."
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &filevantagePoliciesDataSource{}
	_ datasource.DataSourceWithConfigure = &filevantagePoliciesDataSource{}
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
	Precedence        types.Int64  `tfsdk:"precedence"`
	CreatedBy         types.String `tfsdk:"created_by"`
	CreatedTimestamp  types.String `tfsdk:"created_timestamp"`
	ModifiedBy        types.String `tfsdk:"modified_by"`
	ModifiedTimestamp types.String `tfsdk:"modified_timestamp"`
	HostGroups        types.List   `tfsdk:"host_groups"`
	RuleGroups        types.List   `tfsdk:"rule_groups"`
}

func (m policyDataModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":                 types.StringType,
		"name":               types.StringType,
		"description":        types.StringType,
		"platform_name":      types.StringType,
		"enabled":            types.BoolType,
		"precedence":         types.Int64Type,
		"created_by":         types.StringType,
		"created_timestamp":  types.StringType,
		"modified_by":        types.StringType,
		"modified_timestamp": types.StringType,
		"host_groups":        types.ListType{ElemType: types.StringType},
		"rule_groups":        types.ListType{ElemType: types.StringType},
	}
}

type filevantagePoliciesDataSourceModel struct {
	PlatformNames types.Set    `tfsdk:"platform_names"`
	IDs           types.List   `tfsdk:"ids"`
	Sort          types.String `tfsdk:"sort"`
	Name          types.String `tfsdk:"name"`
	Description   types.String `tfsdk:"description"`
	Enabled       types.Bool   `tfsdk:"enabled"`
	CreatedBy     types.String `tfsdk:"created_by"`
	ModifiedBy    types.String `tfsdk:"modified_by"`
	Policies      types.List   `tfsdk:"policies"`
}

// hasIndividualFilters checks if any of the individual filter attributes are set.
func (m *filevantagePoliciesDataSourceModel) hasIndividualFilters() bool {
	return utils.IsKnown(m.Name) ||
		utils.IsKnown(m.Description) ||
		utils.IsKnown(m.Enabled) ||
		utils.IsKnown(m.CreatedBy) ||
		utils.IsKnown(m.ModifiedBy)
}

func (m *filevantagePoliciesDataSourceModel) wrap(ctx context.Context, policies []*models.PoliciesPolicy) diag.Diagnostics {
	var diags diag.Diagnostics
	policyModels := make([]policyDataModel, 0, len(policies))
	for _, policy := range policies {
		if policy == nil {
			continue
		}

		policyModel := policyDataModel{}

		policyModel.ID = flex.StringPointerToFramework(policy.ID)
		policyModel.Name = flex.StringValueToFramework(policy.Name)
		policyModel.Description = flex.StringValueToFramework(policy.Description)
		policyModel.PlatformName = flex.StringValueToFramework(policy.Platform)
		policyModel.Enabled = types.BoolPointerValue(policy.Enabled)
		policyModel.Precedence = types.Int64Value(int64(policy.Precedence))
		policyModel.CreatedBy = flex.StringValueToFramework(policy.CreatedBy)
		policyModel.CreatedTimestamp = flex.StringPointerToFramework(policy.CreatedTimestamp)
		policyModel.ModifiedBy = flex.StringPointerToFramework(policy.ModifiedBy)
		policyModel.ModifiedTimestamp = flex.StringPointerToFramework(policy.ModifiedTimestamp)

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
			if ruleGroup != nil && ruleGroup.ID != nil {
				ruleGroupIDs = append(ruleGroupIDs, *ruleGroup.ID)
			}
		}
		ruleGroupList, diag := types.ListValueFrom(ctx, types.StringType, ruleGroupIDs)
		if diag.HasError() {
			diags.Append(diag...)
			return diags
		}
		policyModel.RuleGroups = ruleGroupList

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
			"ids": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "List of FileVantage policy IDs to retrieve. Cannot be used together with 'platform_names' or other filter attributes.",
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.LengthBetween(32, 32),
					),
					listvalidator.SizeAtLeast(1),
					listvalidator.UniqueValues(),
					listvalidator.ConflictsWith(
						path.MatchRoot("platform_names"),
						path.MatchRoot("sort"),
						path.MatchRoot("name"),
						path.MatchRoot("description"),
						path.MatchRoot("enabled"),
						path.MatchRoot("created_by"),
						path.MatchRoot("modified_by"),
					),
				},
			},
			"platform_names": schema.SetAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "Filter policies by platform names. Valid values: Windows, Linux, Mac. Defaults to all. Cannot be used together with 'ids'.",
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(
						stringvalidator.OneOf("Windows", "Linux", "Mac"),
					),
					setvalidator.ConflictsWith(path.MatchRoot("ids")),
				},
			},
			"sort": schema.StringAttribute{
				Optional:    true,
				Description: "Sort order for the results. Can be used with 'platform_names'. Valid values: 'precedence', 'created_timestamp', 'modified_timestamp', optionally followed by '.asc' or '.desc' (e.g., 'precedence.desc'). By default, '.asc' is used if no direction is specified. Cannot be used together with 'ids'.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^(precedence|created_timestamp|modified_timestamp)(\.asc|\.desc)?$`),
						"must be one of: precedence, created_timestamp, modified_timestamp, optionally followed by .asc or .desc",
					),
					stringvalidator.ConflictsWith(path.MatchRoot("ids")),
				},
			},
			"name": schema.StringAttribute{
				Optional:    true,
				Description: "Filter policies by name. All provided filter attributes must match for a policy to be returned (omitted attributes are ignored). Supports wildcard matching with '*' where '*' matches any sequence of characters until the end of the string or until the next literal character in the pattern is found. Multiple wildcards can be used in a single pattern. Matching is case insensitive. Cannot be used together with 'ids'.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
					stringvalidator.ConflictsWith(path.MatchRoot("ids")),
				},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Filter policies by description. All provided filter attributes must match for a policy to be returned (omitted attributes are ignored). Supports wildcard matching with '*' where '*' matches any sequence of characters until the end of the string or until the next literal character in the pattern is found. Multiple wildcards can be used in a single pattern. Matching is case insensitive. Cannot be used together with 'ids'.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
					stringvalidator.ConflictsWith(path.MatchRoot("ids")),
				},
			},
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Description: "Filter policies by enabled status. All provided filter attributes must match for a policy to be returned (omitted attributes are ignored). Cannot be used together with 'ids'.",
				Validators: []validator.Bool{
					boolvalidator.ConflictsWith(path.MatchRoot("ids")),
				},
			},
			"created_by": schema.StringAttribute{
				Optional:    true,
				Description: "Filter policies by the user who created them. All provided filter attributes must match for a policy to be returned (omitted attributes are ignored). Supports wildcard matching with '*' where '*' matches any sequence of characters until the end of the string or until the next literal character in the pattern is found. Multiple wildcards can be used in a single pattern. Matching is case insensitive. Cannot be used together with 'ids'.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
					stringvalidator.ConflictsWith(path.MatchRoot("ids")),
				},
			},
			"modified_by": schema.StringAttribute{
				Optional:    true,
				Description: "Filter policies by the user who last modified them. All provided filter attributes must match for a policy to be returned (omitted attributes are ignored). Supports wildcard matching with '*' where '*' matches any sequence of characters until the end of the string or until the next literal character in the pattern is found. Multiple wildcards can be used in a single pattern. Matching is case insensitive. Cannot be used together with 'ids'.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
					stringvalidator.ConflictsWith(path.MatchRoot("ids")),
				},
			},
			"policies": schema.ListNestedAttribute{
				Computed:    true,
				Description: "The list of FileVantage policies",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "The FileVantage policy ID",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "The FileVantage policy name",
						},
						"description": schema.StringAttribute{
							Computed:    true,
							Description: "The FileVantage policy description",
						},
						"platform_name": schema.StringAttribute{
							Computed:    true,
							Description: "The platform name (Windows, Linux, Mac)",
						},
						"enabled": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether the FileVantage policy is enabled",
						},
						"precedence": schema.Int64Attribute{
							Computed:    true,
							Description: "Policy precedence/priority",
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
						"rule_groups": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "List of rule group IDs associated with the policy",
						},
					},
				},
			},
		},
	}
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

	var policyIDs []string

	if utils.IsKnown(data.IDs) && len(data.IDs.Elements()) > 0 {
		policyIDs = utils.ListTypeAs[string](ctx, data.IDs, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	} else {
		platformNames := []string{"Windows", "Linux", "Mac"}
		if utils.IsKnown(data.PlatformNames) && len(data.PlatformNames.Elements()) > 0 {
			resp.Diagnostics.Append(data.PlatformNames.ElementsAs(ctx, &platformNames, false)...)
			if resp.Diagnostics.HasError() {
				return
			}
		}

		sort := data.Sort.ValueString()
		var diags diag.Diagnostics
		policyIDs, diags = d.getFilevantagePolicyIDs(ctx, platformNames, sort)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	var policies []*models.PoliciesPolicy
	if len(policyIDs) > 0 {
		var diags diag.Diagnostics
		policies, diags = d.getFilevantagePoliciesByIDs(ctx, policyIDs)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	if data.hasIndividualFilters() {
		policies = filterPoliciesByAttributes(policies, &data)
	}

	resp.Diagnostics.Append(data.wrap(ctx, policies)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// getFilevantagePolicyIDs returns all FileVantage policy IDs matching platform names.
func (d *filevantagePoliciesDataSource) getFilevantagePolicyIDs(
	ctx context.Context,
	platformNames []string,
	sort string,
) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics
	var allPolicyIDs []string

	for _, platformName := range platformNames {
		var platformPolicyIDs []string
		limit := int64(500)
		offset := int64(0)

		for {
			queryParams := &filevantage.QueryPoliciesParams{
				Context: ctx,
				Limit:   &limit,
				Offset:  &offset,
				Type:    platformName,
			}

			if sort != "" {
				queryParams.Sort = &sort
			}

			queryRes, err := d.client.Filevantage.QueryPolicies(queryParams)
			if err != nil {
				diags.Append(tferrors.NewOperationError(tferrors.Read, err))
				return nil, diags
			}

			if queryRes == nil || queryRes.Payload == nil || len(queryRes.Payload.Resources) == 0 {
				break
			}

			platformPolicyIDs = append(platformPolicyIDs, queryRes.Payload.Resources...)

			if queryRes.Payload.Meta == nil || queryRes.Payload.Meta.Pagination == nil ||
				queryRes.Payload.Meta.Pagination.Offset == nil || queryRes.Payload.Meta.Pagination.Total == nil {
				offset += limit
				continue
			}

			offset = int64(*queryRes.Payload.Meta.Pagination.Offset) + limit
			if offset >= *queryRes.Payload.Meta.Pagination.Total {
				break
			}
		}

		allPolicyIDs = append(allPolicyIDs, platformPolicyIDs...)
	}

	return allPolicyIDs, diags
}

// getFilevantagePoliciesByIDs returns FileVantage policies by their IDs.
func (d *filevantagePoliciesDataSource) getFilevantagePoliciesByIDs(
	ctx context.Context,
	ids []string,
) ([]*models.PoliciesPolicy, diag.Diagnostics) {
	var diags diag.Diagnostics
	var allPolicies []*models.PoliciesPolicy

	batchSize := 500
	for i := 0; i < len(ids); i += batchSize {
		end := min(i+batchSize, len(ids))
		batchIDs := ids[i:end]

		params := &filevantage.GetPoliciesParams{
			Context: ctx,
			Ids:     batchIDs,
		}

		res, err := d.client.Filevantage.GetPolicies(params)
		if err != nil {
			diags.Append(tferrors.NewOperationError(tferrors.Read, err))
			return nil, diags
		}

		if res != nil && res.Payload != nil && len(res.Payload.Resources) > 0 {
			allPolicies = append(allPolicies, res.Payload.Resources...)
		}
	}

	return allPolicies, diags
}

// filterPoliciesByAttributes filters policies by individual attributes.
func filterPoliciesByAttributes(policies []*models.PoliciesPolicy, filters *filevantagePoliciesDataSourceModel) []*models.PoliciesPolicy {
	filtered := make([]*models.PoliciesPolicy, 0, len(policies))
	for _, policy := range policies {
		if policy == nil {
			continue
		}

		if !filters.Name.IsNull() {
			if !utils.MatchesWildcard(policy.Name, filters.Name.ValueString()) {
				continue
			}
		}

		if !filters.Description.IsNull() {
			if !utils.MatchesWildcard(policy.Description, filters.Description.ValueString()) {
				continue
			}
		}

		if !filters.CreatedBy.IsNull() {
			if !utils.MatchesWildcard(policy.CreatedBy, filters.CreatedBy.ValueString()) {
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
