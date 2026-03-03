package cloudsecurity

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwtypes "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/types"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &cloudSecuritySuppressionRulesDataSource{}
	_ datasource.DataSourceWithConfigure = &cloudSecuritySuppressionRulesDataSource{}
)

var (
	suppressionRulesDataSourceDocumentationSection string = "Falcon Cloud Security"
	suppressionRulesDataSourceMarkdownDescription  string = "This data source retrieves detailed information about cloud security suppression rules. " +
		"Suppression rules define criteria for automatically suppressing findings, such as IOMs, across your environment. " +
		"Text-based fields (`name`, `description`) accept wildcards `*`. All fields query Falcon using logical AND. If FQL is defined, all other fields will be ignored. " +
		"For advanced queries to further narrow your search, please use a Falcon Query Language (FQL) filter."
)

func NewCloudSecuritySuppressionRulesDataSource() datasource.DataSource {
	return &cloudSecuritySuppressionRulesDataSource{}
}

type cloudSecuritySuppressionRulesDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type cloudSecuritySuppressionRulesDataSourceModel struct {
	Type        types.String `tfsdk:"type"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Reason      types.String `tfsdk:"reason"`
	Disabled    types.Bool   `tfsdk:"disabled"`
	FQL         types.String `tfsdk:"fql"`
	Rules       types.Set    `tfsdk:"rules"`
}

type cloudSecuritySuppressionRulesDataSourceRuleModel struct {
	ID                  types.String      `tfsdk:"id"`
	Type                types.String      `tfsdk:"type"`
	Description         types.String      `tfsdk:"description"`
	Name                types.String      `tfsdk:"name"`
	RuleSelectionFilter types.Object      `tfsdk:"rule_selection_filter"`
	AssetFilter         types.Object      `tfsdk:"asset_filter"`
	Comment             types.String      `tfsdk:"comment"`
	ExpirationDate      timetypes.RFC3339 `tfsdk:"expiration_date"`
	Reason              types.String      `tfsdk:"reason"`
}

type suppressionRulesFqlFilters struct {
	property string
	value    string
}

func (m cloudSecuritySuppressionRulesDataSourceRuleModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":          types.StringType,
		"type":        types.StringType,
		"description": types.StringType,
		"name":        types.StringType,
		"rule_selection_filter": types.ObjectType{
			AttrTypes: ruleSelectionFilterModel{}.AttributeTypes(),
		},
		"asset_filter": types.ObjectType{
			AttrTypes: scopeAssetFilterModel{}.AttributeTypes(),
		},
		"comment":         types.StringType,
		"expiration_date": timetypes.RFC3339Type{},
		"reason":          types.StringType,
	}
}

func (r *cloudSecuritySuppressionRulesDataSource) Configure(
	ctx context.Context,
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

	r.client = config.Client
}

func (r *cloudSecuritySuppressionRulesDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_security_suppression_rules"
}

func (r *cloudSecuritySuppressionRulesDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			suppressionRulesDataSourceDocumentationSection,
			suppressionRulesDataSourceMarkdownDescription,
			cloudSecurityRuleScopes,
		),
		Attributes: map[string]schema.Attribute{
			"type": schema.StringAttribute{
				Optional:    true,
				Description: "Type of suppression rule to filter by. This corresponds to the subdomain field in the API. One of: IOM.",
				Validators: []validator.String{
					stringvalidator.ConflictsWith(path.MatchRoot("fql")),
					stringvalidator.OneOf(suppressionRuleSubdomainDefault),
				},
			},
			"name": schema.StringAttribute{
				Optional:    true,
				Description: "Name of the suppression rule to search for. Wildcards are accepted (e.g., *suppression rule*).",
				Validators: []validator.String{
					stringvalidator.ConflictsWith(path.MatchRoot("fql")),
				},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description of the suppression rule to search for. Wildcards are accepted (e.g., *suppression rule*).",
				Validators: []validator.String{
					stringvalidator.ConflictsWith(path.MatchRoot("fql")),
				},
			},
			"reason": schema.StringAttribute{
				Optional:    true,
				Description: "Suppression reason to filter by. One of: accept-risk, compensating-control, false-positive.",
				Validators: []validator.String{
					stringvalidator.ConflictsWith(path.MatchRoot("fql")),
					stringvalidator.OneOf(suppressionRuleReasonValues...),
				},
			},
			"disabled": schema.BoolAttribute{
				Optional:    true,
				Description: "Filter suppression rules by disabled status. When false, shows only active rules (non-expired). When true, shows all rules including expired ones. If not specified, shows all rules.",
			},
			"fql": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Falcon Query Language (FQL) filter for advanced suppression rule searches. FQL filter, allowed props: `name`, `description`, `subdomain`, `suppression_reason`, `disabled`",
			},
			"rules": schema.SetNestedAttribute{
				Computed:    true,
				Description: "List of cloud security suppression rules",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "Unique identifier of the suppression rule.",
							Validators: []validator.String{
								stringvalidator.RegexMatches(
									regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
									"must be a valid ID in the format of 7c86a274-c04b-4292-9f03-dafae42bde97",
								),
							},
						},
						"type": schema.StringAttribute{
							Computed:    true,
							Description: "Type of suppression rule. One of: IOM.",
						},
						"description": schema.StringAttribute{
							Computed:    true,
							Description: "Description of the suppression rule.",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the suppression rule.",
						},
						"comment": schema.StringAttribute{
							Computed:    true,
							Description: "Comment for suppression. This will be attached to the findings suppressed by this rule.",
						},
						"expiration_date": schema.StringAttribute{
							CustomType:  timetypes.RFC3339Type{},
							Computed:    true,
							Description: "Expiration date for suppression in RFC3339 format.",
						},
						"reason": schema.StringAttribute{
							Computed:    true,
							Description: "Reason for suppression. One of: accept-risk, compensating-control, false-positive.",
						},
						"rule_selection_filter": schema.SingleNestedAttribute{
							Computed:            true,
							MarkdownDescription: "Filter criteria for rule selection. Within each attribute, rules match if they contain ANY of the specified values (OR logic). Between different attributes, rules must match ALL specified attributes (AND logic).",
							Attributes: map[string]schema.Attribute{
								"ids": schema.SetAttribute{
									Computed:    true,
									Description: "Set of rule IDs. A rule will match if its ID is included in this set.",
									ElementType: types.StringType,
								},
								"names": schema.SetAttribute{
									Computed:    true,
									Description: "Set of rule names. A rule will match if its name is included in this set.",
									ElementType: types.StringType,
								},
								"origins": schema.SetAttribute{
									Computed:            true,
									MarkdownDescription: "Set of rule origins. One of: `Custom`, `Default`. A rule will match if its origin is included in this set.",
									ElementType:         types.StringType,
								},
								"providers": schema.SetAttribute{
									Computed:            true,
									MarkdownDescription: "Set of rule cloud providers. Examples: `AWS`, `Azure`, `GCP`, `OCI`. A rule will match if its cloud provider is included in this set.",
									ElementType:         types.StringType,
								},
								"services": schema.SetAttribute{
									Computed:            true,
									MarkdownDescription: "Set of cloud services. Examples: `Azure Cosmos DB`, `CloudFront`, `Compute Engine`, `EC2`, `Elasticache`, `Virtual Network`. A rule will match if its cloud service is included in this set.",
									ElementType:         types.StringType,
								},
								"severities": schema.SetAttribute{
									Computed:            true,
									MarkdownDescription: "Set of rule severities. One of: `critical`, `high`, `medium`, `informational`. A rule will match if its severity is included in this set.",
									ElementType:         types.StringType,
								},
							},
						},
						"asset_filter": schema.SingleNestedAttribute{
							Computed:            true,
							MarkdownDescription: "Filter criteria for scope assets. Within each attribute, assets match if they contain ANY of the specified values (OR logic). Between different attributes, assets must match ALL specified attributes (AND logic).",
							Attributes: map[string]schema.Attribute{
								"account_ids": schema.SetAttribute{
									Computed:    true,
									Description: "Set of cloud account IDs. An Asset will match if it belongs to an account included in this set.",
									ElementType: types.StringType,
								},
								"cloud_group_ids": schema.SetAttribute{
									Computed:    true,
									Description: "Set of cloud group IDs. An Asset will match if it belongs to a Cloud Group whose ID is included in this set.",
									ElementType: types.StringType,
								},
								"cloud_providers": schema.SetAttribute{
									Computed:            true,
									MarkdownDescription: "Set of cloud providers. Examples: `aws`, `azure`, `gcp`. An Asset will match if it belongs to a cloud provider included in this set.",
									ElementType:         types.StringType,
								},
								"regions": schema.SetAttribute{
									Computed:            true,
									MarkdownDescription: "Set of regions. Examples: `eu-central-1`, `eastus`, `us-west-1`. An Asset will match if it is located in a region included in this set.",
									ElementType:         types.StringType,
								},
								"resource_ids": schema.SetAttribute{
									Computed:    true,
									Description: "Set of resource IDs. An Asset will match if its resource ID is included in this set.",
									ElementType: types.StringType,
								},
								"resource_names": schema.SetAttribute{
									Computed:    true,
									Description: "Set of resource names. An Asset will match if its resource name is included in this set.",
									ElementType: types.StringType,
								},
								"resource_types": schema.SetAttribute{
									Computed:            true,
									MarkdownDescription: "Set of resource types. Examples: `AWS::S3::Bucket`, `compute.googleapis.com/Instance`, `Microsoft.ContainerService/managedClusters`. An Asset will match if its resource type is included in this set.",
									ElementType:         types.StringType,
								},
								"service_categories": schema.SetAttribute{
									Computed:            true,
									MarkdownDescription: "Set of service categories. Examples: `Compute`, `Identity`, `Networking`. An Asset will match if its cloud service category is included in this set.",
									ElementType:         types.StringType,
								},
								"tags": schema.MapAttribute{
									Computed:    true,
									Description: "Map of tags. These must match the k=v format. An Asset will match if any of its tag key-value pairs match those specified in this map.",
									ElementType: types.StringType,
								},
							},
						},
					},
				},
			},
		},
	}
}

func (r *cloudSecuritySuppressionRulesDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data cloudSecuritySuppressionRulesDataSourceModel
	var diags diag.Diagnostics

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	fqlFilters := []suppressionRulesFqlFilters{
		{
			property: "subdomain",
			value:    data.Type.ValueString(),
		},
		{
			property: "name",
			value:    data.Name.ValueString(),
		},
		{
			property: "description",
			value:    data.Description.ValueString(),
		},
		{
			property: "suppression_reason",
			value:    data.Reason.ValueString(),
		},
		{
			property: "disabled",
			value: func() string {
				if data.Disabled.IsNull() {
					return ""
				}
				if data.Disabled.ValueBool() {
					return "true"
				}
				return "false"
			}(),
		},
	}

	data.Rules, diags = r.getSuppressionRules(
		ctx,
		data.FQL.ValueString(),
		fqlFilters,
	)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	diags = resp.State.Set(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func buildRuleSelectionFilterObject(ctx context.Context, filter *models.ApimodelsRuleSelectionFilter) (types.Object, diag.Diagnostics) {
	var diags diag.Diagnostics

	if filter == nil {
		return types.ObjectNull(ruleSelectionFilterModel{}.AttributeTypes()), diags
	}

	ruleSelectionFilter := make(map[string]attr.Value)

	// Convert rule severities using the stringToSeverity map
	convertedRuleSeverities := make([]string, 0, len(filter.RuleSeverities))
	for _, severity := range filter.RuleSeverities {
		if converted, ok := stringToSeverity[severity]; ok {
			convertedRuleSeverities = append(convertedRuleSeverities, converted)
		} else {
			convertedRuleSeverities = append(convertedRuleSeverities, severity)
		}
	}

	ruleSelectionFilter["ids"], diags = fwtypes.OptionalStringSet(ctx, filter.RuleIds)
	if diags.HasError() {
		return types.ObjectNull(ruleSelectionFilterModel{}.AttributeTypes()), diags
	}

	ruleSelectionFilter["names"], diags = fwtypes.OptionalStringSet(ctx, filter.RuleNames)
	if diags.HasError() {
		return types.ObjectNull(ruleSelectionFilterModel{}.AttributeTypes()), diags
	}

	ruleSelectionFilter["origins"], diags = fwtypes.OptionalStringSet(ctx, filter.RuleOrigins)
	if diags.HasError() {
		return types.ObjectNull(ruleSelectionFilterModel{}.AttributeTypes()), diags
	}

	ruleSelectionFilter["providers"], diags = fwtypes.OptionalStringSet(ctx, filter.RuleProviders)
	if diags.HasError() {
		return types.ObjectNull(ruleSelectionFilterModel{}.AttributeTypes()), diags
	}

	ruleSelectionFilter["services"], diags = fwtypes.OptionalStringSet(ctx, filter.RuleServices)
	if diags.HasError() {
		return types.ObjectNull(ruleSelectionFilterModel{}.AttributeTypes()), diags
	}

	ruleSelectionFilter["severities"], diags = fwtypes.OptionalStringSet(ctx, convertedRuleSeverities)
	if diags.HasError() {
		return types.ObjectNull(ruleSelectionFilterModel{}.AttributeTypes()), diags
	}

	return types.ObjectValueMust(
		ruleSelectionFilterModel{}.AttributeTypes(),
		ruleSelectionFilter,
	), diags
}

func buildScopeAssetFilterObject(ctx context.Context, filter *models.ApimodelsAssetFilter) (types.Object, diag.Diagnostics) {
	var diags diag.Diagnostics

	if filter == nil {
		return types.ObjectNull(scopeAssetFilterModel{}.AttributeTypes()), diags
	}

	// Extract cloud group IDs
	cloudGroupIDs := make([]string, 0)
	for _, cloudGroup := range filter.CloudGroups {
		if cloudGroup != nil && cloudGroup.ID != nil {
			cloudGroupIDs = append(cloudGroupIDs, *cloudGroup.ID)
		}
	}

	scopeAssetFilter := make(map[string]attr.Value)

	scopeAssetFilter["account_ids"], diags = fwtypes.OptionalStringSet(ctx, filter.AccountIds)
	if diags.HasError() {
		return types.ObjectNull(scopeAssetFilterModel{}.AttributeTypes()), diags
	}

	scopeAssetFilter["cloud_group_ids"], diags = fwtypes.OptionalStringSet(ctx, cloudGroupIDs)
	if diags.HasError() {
		return types.ObjectNull(scopeAssetFilterModel{}.AttributeTypes()), diags
	}

	scopeAssetFilter["cloud_providers"], diags = fwtypes.OptionalStringSet(ctx, filter.CloudProviders)
	if diags.HasError() {
		return types.ObjectNull(scopeAssetFilterModel{}.AttributeTypes()), diags
	}

	scopeAssetFilter["regions"], diags = fwtypes.OptionalStringSet(ctx, filter.Regions)
	if diags.HasError() {
		return types.ObjectNull(scopeAssetFilterModel{}.AttributeTypes()), diags
	}

	scopeAssetFilter["resource_ids"], diags = fwtypes.OptionalStringSet(ctx, filter.ResourceIds)
	if diags.HasError() {
		return types.ObjectNull(scopeAssetFilterModel{}.AttributeTypes()), diags
	}

	scopeAssetFilter["resource_names"], diags = fwtypes.OptionalStringSet(ctx, filter.ResourceNames)
	if diags.HasError() {
		return types.ObjectNull(scopeAssetFilterModel{}.AttributeTypes()), diags
	}

	scopeAssetFilter["resource_types"], diags = fwtypes.OptionalStringSet(ctx, filter.ResourceTypes)
	if diags.HasError() {
		return types.ObjectNull(scopeAssetFilterModel{}.AttributeTypes()), diags
	}

	scopeAssetFilter["service_categories"], diags = fwtypes.OptionalStringSet(ctx, filter.ServiceCategories)
	if diags.HasError() {
		return types.ObjectNull(scopeAssetFilterModel{}.AttributeTypes()), diags
	}

	// Parse tags from "key=value" format into a map
	tagsMap := make(map[string]attr.Value)
	for _, tag := range filter.Tags {
		if parts := strings.SplitN(tag, "=", 2); len(parts) == 2 {
			tagsMap[parts[0]] = types.StringValue(parts[1])
		}
	}

	if len(tagsMap) == 0 {
		scopeAssetFilter["tags"] = types.MapNull(types.StringType)
	} else {
		scopeAssetFilter["tags"] = types.MapValueMust(types.StringType, tagsMap)
	}

	return types.ObjectValueMust(
		scopeAssetFilterModel{}.AttributeTypes(),
		scopeAssetFilter,
	), diags
}

func (r *cloudSecuritySuppressionRulesDataSource) getSuppressionRules(
	ctx context.Context,
	fql string,
	fqlFilters []suppressionRulesFqlFilters,
) (types.Set, diag.Diagnostics) {
	var rules []cloudSecuritySuppressionRulesDataSourceRuleModel
	var diags diag.Diagnostics
	var filter string
	limit := int64(50)
	offset := int64(0)
	defaultResponse := types.SetValueMust(types.ObjectType{AttrTypes: cloudSecuritySuppressionRulesDataSourceRuleModel{}.AttributeTypes()}, []attr.Value{})

	queryParams := cloud_policies.QuerySuppressionRulesParams{
		Context: ctx,
		Limit:   &limit,
		Offset:  &offset,
	}

	if fql == "" {
		var filters []string
		exactMatchFields := []string{"subdomain", "suppression_reason", "disabled"}

		for _, f := range fqlFilters {
			if f.value != "" {
				value := strings.ReplaceAll(f.value, "\\", "\\\\\\\\")
				if slices.Contains(exactMatchFields, f.property) {
					filters = append(filters, fmt.Sprintf("%s:'%s'", f.property, value))
				} else {
					filters = append(filters, fmt.Sprintf("%s:*'%s'", f.property, value))
				}
			}
		}

		if len(filters) > 0 {
			filter = strings.Join(filters, "+")
		}

		if filter != "" {
			queryParams.Filter = &filter
		}
	} else {
		queryParams.Filter = &fql
	}

	for {
		queryResp, err := r.client.CloudPolicies.QuerySuppressionRules(&queryParams)
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, cloudSecurityRuleScopes)
		if diag != nil {
			diags.Append(diag)
			return defaultResponse, diags
		}

		if queryResp == nil || queryResp.Payload == nil || len(queryResp.Payload.Resources) == 0 {
			break
		}

		queryPayload := queryResp.GetPayload()

		if err = falcon.AssertNoError(queryPayload.Errors); err != nil {
			diags.Append(tferrors.NewOperationError(tferrors.Read, err))
			return defaultResponse, diags
		}

		if len(queryPayload.Resources) == 0 {
			return defaultResponse, diags
		}

		ruleParams := cloud_policies.GetSuppressionRulesParams{
			Context: ctx,
			Ids:     queryPayload.Resources,
		}

		getSuppressionRulesResp, err := r.client.CloudPolicies.GetSuppressionRules(&ruleParams)
		diag = tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, cloudSecurityRuleScopes)
		if diag != nil {
			diags.Append(diag)
			return defaultResponse, diags
		}

		if getSuppressionRulesResp == nil || getSuppressionRulesResp.Payload == nil || len(getSuppressionRulesResp.Payload.Resources) == 0 {
			diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
			return defaultResponse, diags
		}

		getSuppressionRulesPayload := getSuppressionRulesResp.GetPayload()

		if err = falcon.AssertNoError(getSuppressionRulesPayload.Errors); err != nil {
			diags.Append(tferrors.NewOperationError(tferrors.Read, err))
			return defaultResponse, diags
		}

		for _, resource := range getSuppressionRulesPayload.Resources {
			rule := cloudSecuritySuppressionRulesDataSourceRuleModel{
				ID:          flex.StringPointerToFramework(resource.ID),
				Description: flex.StringValueToFramework(resource.Description),
				Name:        flex.StringPointerToFramework(resource.Name),
				Comment:     flex.StringValueToFramework(resource.SuppressionComment),
				Reason:      flex.StringPointerToFramework(resource.SuppressionReason),
				Type:        flex.StringPointerToFramework(resource.Subdomain),
			}

			rule.ExpirationDate, diags = flex.RFC3339ValueToFramework(resource.SuppressionExpirationDate)
			if diags.HasError() {
				return defaultResponse, diags
			}

			rule.RuleSelectionFilter, diags = buildRuleSelectionFilterObject(ctx, resource.RuleSelectionFilter)
			if diags.HasError() {
				return defaultResponse, diags
			}

			rule.AssetFilter, diags = buildScopeAssetFilterObject(ctx, resource.ScopeAssetFilter)
			if diags.HasError() {
				return defaultResponse, diags
			}

			rules = append(rules, rule)
		}

		if queryPayload.Meta != nil && queryPayload.Meta.Pagination != nil {
			pagination := queryPayload.Meta.Pagination
			if pagination.Offset != nil && pagination.Total != nil && int64(*pagination.Offset) >= *pagination.Total {
				tflog.Info(ctx, "Pagination complete", map[string]any{"meta": queryPayload.Meta})
				break
			}
		}

		offset += limit
		queryParams.Offset = &offset
	}

	rulesSet, diags := types.SetValueFrom(
		ctx,
		types.ObjectType{AttrTypes: cloudSecuritySuppressionRulesDataSourceRuleModel{}.AttributeTypes()},
		rules,
	)
	if diags.HasError() {
		return defaultResponse, diags
	}

	return rulesSet, diags
}
