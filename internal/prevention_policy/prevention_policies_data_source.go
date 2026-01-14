package preventionpolicy

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/prevention_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	hostgroups "github.com/crowdstrike/terraform-provider-crowdstrike/internal/host_groups"
	ioarulegroup "github.com/crowdstrike/terraform-provider-crowdstrike/internal/ioa_rule_group"
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
	dataSourceDocumentationSection = "Prevention Policy"
	dataSourceMarkdownDescription  = "This data source provides information about prevention policies in Falcon."
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource                   = &preventionPoliciesDataSource{}
	_ datasource.DataSourceWithConfigure      = &preventionPoliciesDataSource{}
	_ datasource.DataSourceWithValidateConfig = &preventionPoliciesDataSource{}
)

// Configure adds the provider configured client to the data source.
func (d *preventionPoliciesDataSource) Configure(
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

// preventionPoliciesDataSource is the data source implementation.
type preventionPoliciesDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type policyDataModel struct {
	ID                 types.String `tfsdk:"id"`
	Name               types.String `tfsdk:"name"`
	Description        types.String `tfsdk:"description"`
	PlatformName       types.String `tfsdk:"platform_name"`
	Enabled            types.Bool   `tfsdk:"enabled"`
	CreatedBy          types.String `tfsdk:"created_by"`
	CreatedTimestamp   types.String `tfsdk:"created_timestamp"`
	ModifiedBy         types.String `tfsdk:"modified_by"`
	ModifiedTimestamp  types.String `tfsdk:"modified_timestamp"`
	HostGroups         types.List   `tfsdk:"host_groups"`
	IoaRuleGroups      types.List   `tfsdk:"ioa_rule_groups"`
	PreventionSettings types.Object `tfsdk:"prevention_settings"`
}

type categorySettingsModel struct {
	Detection  types.String `tfsdk:"detection"`
	Prevention types.String `tfsdk:"prevention"`
}

func (c categorySettingsModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"detection":  types.StringType,
		"prevention": types.StringType,
	}
}

type preventionSettingsModel struct {
	AdwareAndPUA                   types.Object `tfsdk:"adware_and_pua"`
	CloudAntiMalware               types.Object `tfsdk:"cloud_anti_malware"`
	CloudMachineLearning           types.Object `tfsdk:"cloud_machine_learning"`
	CustomBlocking                 types.Object `tfsdk:"custom_blocking"`
	EndUserNotifications           types.Object `tfsdk:"end_user_notifications"`
	EnhancedExploitationVisibility types.Object `tfsdk:"enhanced_exploitation_visibility"`
	ExploitBlocking                types.Object `tfsdk:"exploit_blocking"`
	HashBlocking                   types.Object `tfsdk:"hash_blocking"`
	MalwareProtection              types.Object `tfsdk:"malware_protection"`
	MemoryScanning                 types.Object `tfsdk:"memory_scanning"`
	OnSensorML                     types.Object `tfsdk:"on_sensor_ml"`
	Quarantine                     types.Object `tfsdk:"quarantine"`
	RealTimeResponse               types.Object `tfsdk:"real_time_response"`
	ScriptBasedExecutionMonitoring types.Object `tfsdk:"script_based_execution_monitoring"`
	SensorAntiMalware              types.Object `tfsdk:"sensor_anti_malware"`
	UnknownDetectionRelated        types.Object `tfsdk:"unknown_detection_related"`
	UnknownExecutableDetection     types.Object `tfsdk:"unknown_executable_detection"`
}

func (p preventionSettingsModel) AttributeTypes() map[string]attr.Type {
	categoryType := types.ObjectType{AttrTypes: categorySettingsModel{}.AttributeTypes()}
	return map[string]attr.Type{
		"adware_and_pua":                    categoryType,
		"cloud_anti_malware":                categoryType,
		"cloud_machine_learning":            categoryType,
		"custom_blocking":                   categoryType,
		"end_user_notifications":            categoryType,
		"enhanced_exploitation_visibility":  categoryType,
		"exploit_blocking":                  categoryType,
		"hash_blocking":                     categoryType,
		"malware_protection":                categoryType,
		"memory_scanning":                   categoryType,
		"on_sensor_ml":                      categoryType,
		"quarantine":                        categoryType,
		"real_time_response":                categoryType,
		"script_based_execution_monitoring": categoryType,
		"sensor_anti_malware":               categoryType,
		"unknown_detection_related":         categoryType,
		"unknown_executable_detection":      categoryType,
	}
}

func (m policyDataModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":                  types.StringType,
		"name":                types.StringType,
		"description":         types.StringType,
		"platform_name":       types.StringType,
		"enabled":             types.BoolType,
		"created_by":          types.StringType,
		"created_timestamp":   types.StringType,
		"modified_by":         types.StringType,
		"modified_timestamp":  types.StringType,
		"host_groups":         types.ListType{ElemType: types.StringType},
		"ioa_rule_groups":     types.ListType{ElemType: types.StringType},
		"prevention_settings": types.ObjectType{AttrTypes: preventionSettingsModel{}.AttributeTypes()},
	}
}

type preventionPoliciesDataSourceModel struct {
	Filter       types.String `tfsdk:"filter"`
	IDs          types.List   `tfsdk:"ids"`
	Sort         types.String `tfsdk:"sort"`
	Name         types.String `tfsdk:"name"`
	Description  types.String `tfsdk:"description"`
	Enabled      types.Bool   `tfsdk:"enabled"`
	PlatformName types.String `tfsdk:"platform_name"`
	CreatedBy    types.String `tfsdk:"created_by"`
	ModifiedBy   types.String `tfsdk:"modified_by"`
	Policies     types.List   `tfsdk:"policies"`
}

func (m *preventionPoliciesDataSourceModel) wrap(ctx context.Context, policies []*models.PreventionPolicyV1) diag.Diagnostics {
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
		policyModel.PlatformName = types.StringPointerValue(policy.PlatformName)
		policyModel.Enabled = types.BoolPointerValue(policy.Enabled)
		policyModel.CreatedBy = types.StringPointerValue(policy.CreatedBy)
		policyModel.CreatedTimestamp = types.StringValue(policy.CreatedTimestamp.String())
		policyModel.ModifiedBy = types.StringPointerValue(policy.ModifiedBy)
		policyModel.ModifiedTimestamp = types.StringValue(policy.ModifiedTimestamp.String())

		hostGroups, diags := hostgroups.ConvertHostGroupsToList(ctx, policy.Groups)
		if diags.HasError() {
			return diags
		}
		policyModel.HostGroups = hostGroups

		ioaRuleGroups, diags := ioarulegroup.ConvertIOARuleGroupToList(ctx, policy.IoaRuleGroups)
		if diags.HasError() {
			return diags
		}
		policyModel.IoaRuleGroups = ioaRuleGroups

		// Prevention settings are not available in the API response for this data source
		policyModel.PreventionSettings = types.ObjectNull(preventionSettingsModel{}.AttributeTypes())

		policyModels = append(policyModels, policyModel)
	}

	m.Policies = utils.SliceToListTypeObject(ctx, policyModels, policyDataModel{}.AttributeTypes(), &diags)
	return diags
}

// hasIndividualFilters checks if any of the individual filter attributes are set.
func (m preventionPoliciesDataSourceModel) hasIndividualFilters() bool {
	return utils.IsKnown(m.Name) ||
		utils.IsKnown(m.Description) ||
		utils.IsKnown(m.Enabled) ||
		utils.IsKnown(m.PlatformName) ||
		utils.IsKnown(m.CreatedBy) ||
		utils.IsKnown(m.ModifiedBy)
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
				Optional:    true,
				Description: "FQL filter to apply to the prevention policies query. When specified, only policies matching the filter will be returned. Cannot be used together with 'ids' or other filter attributes. Example: `platform_name:'Windows'`",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"ids": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "List of prevention policy IDs to retrieve. When specified, only policies with matching IDs will be returned. Cannot be used together with 'filter' or other filter attributes.",
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
			"platform_name": schema.StringAttribute{
				Optional:    true,
				Description: "Filter policies by platform_name (Windows, Linux, Mac). All provided filter attributes must match for a policy to be returned (omitted attributes are ignored). Cannot be used together with 'filter' or 'ids'.",
				Validators: []validator.String{
					stringvalidator.OneOf("Windows", "Linux", "Mac"),
				},
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
						"prevention_settings": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "Prevention policy settings",
							Attributes: map[string]schema.Attribute{
								"adware_and_pua": schema.SingleNestedAttribute{
									Computed:    true,
									Description: "Adware and PUA protection settings",
									Attributes: map[string]schema.Attribute{
										"detection": schema.StringAttribute{
											Computed:    true,
											Description: "Detection setting",
										},
										"prevention": schema.StringAttribute{
											Computed:    true,
											Description: "Prevention setting",
										},
									},
								},
								"cloud_anti_malware": schema.SingleNestedAttribute{
									Computed:    true,
									Description: "Cloud anti-malware protection settings",
									Attributes: map[string]schema.Attribute{
										"detection": schema.StringAttribute{
											Computed:    true,
											Description: "Detection setting",
										},
										"prevention": schema.StringAttribute{
											Computed:    true,
											Description: "Prevention setting",
										},
									},
								},
								"cloud_machine_learning": schema.SingleNestedAttribute{
									Computed:    true,
									Description: "Cloud machine learning protection settings",
									Attributes: map[string]schema.Attribute{
										"detection": schema.StringAttribute{
											Computed:    true,
											Description: "Detection setting",
										},
										"prevention": schema.StringAttribute{
											Computed:    true,
											Description: "Prevention setting",
										},
									},
								},
								"custom_blocking": schema.SingleNestedAttribute{
									Computed:    true,
									Description: "Custom blocking protection settings",
									Attributes: map[string]schema.Attribute{
										"detection": schema.StringAttribute{
											Computed:    true,
											Description: "Detection setting",
										},
										"prevention": schema.StringAttribute{
											Computed:    true,
											Description: "Prevention setting",
										},
									},
								},
								"end_user_notifications": schema.SingleNestedAttribute{
									Computed:    true,
									Description: "End user notifications settings",
									Attributes: map[string]schema.Attribute{
										"detection": schema.StringAttribute{
											Computed:    true,
											Description: "Detection setting",
										},
										"prevention": schema.StringAttribute{
											Computed:    true,
											Description: "Prevention setting",
										},
									},
								},
								"enhanced_exploitation_visibility": schema.SingleNestedAttribute{
									Computed:    true,
									Description: "Enhanced exploitation visibility settings",
									Attributes: map[string]schema.Attribute{
										"detection": schema.StringAttribute{
											Computed:    true,
											Description: "Detection setting",
										},
										"prevention": schema.StringAttribute{
											Computed:    true,
											Description: "Prevention setting",
										},
									},
								},
								"exploit_blocking": schema.SingleNestedAttribute{
									Computed:    true,
									Description: "Exploit blocking protection settings",
									Attributes: map[string]schema.Attribute{
										"detection": schema.StringAttribute{
											Computed:    true,
											Description: "Detection setting",
										},
										"prevention": schema.StringAttribute{
											Computed:    true,
											Description: "Prevention setting",
										},
									},
								},
								"hash_blocking": schema.SingleNestedAttribute{
									Computed:    true,
									Description: "Hash blocking protection settings",
									Attributes: map[string]schema.Attribute{
										"detection": schema.StringAttribute{
											Computed:    true,
											Description: "Detection setting",
										},
										"prevention": schema.StringAttribute{
											Computed:    true,
											Description: "Prevention setting",
										},
									},
								},
								"malware_protection": schema.SingleNestedAttribute{
									Computed:    true,
									Description: "Malware protection settings",
									Attributes: map[string]schema.Attribute{
										"detection": schema.StringAttribute{
											Computed:    true,
											Description: "Detection setting",
										},
										"prevention": schema.StringAttribute{
											Computed:    true,
											Description: "Prevention setting",
										},
									},
								},
								"memory_scanning": schema.SingleNestedAttribute{
									Computed:    true,
									Description: "Memory scanning protection settings",
									Attributes: map[string]schema.Attribute{
										"detection": schema.StringAttribute{
											Computed:    true,
											Description: "Detection setting",
										},
										"prevention": schema.StringAttribute{
											Computed:    true,
											Description: "Prevention setting",
										},
									},
								},
								"on_sensor_ml": schema.SingleNestedAttribute{
									Computed:    true,
									Description: "On-sensor machine learning protection settings",
									Attributes: map[string]schema.Attribute{
										"detection": schema.StringAttribute{
											Computed:    true,
											Description: "Detection setting",
										},
										"prevention": schema.StringAttribute{
											Computed:    true,
											Description: "Prevention setting",
										},
									},
								},
								"quarantine": schema.SingleNestedAttribute{
									Computed:    true,
									Description: "Quarantine protection settings",
									Attributes: map[string]schema.Attribute{
										"detection": schema.StringAttribute{
											Computed:    true,
											Description: "Detection setting",
										},
										"prevention": schema.StringAttribute{
											Computed:    true,
											Description: "Prevention setting",
										},
									},
								},
								"real_time_response": schema.SingleNestedAttribute{
									Computed:    true,
									Description: "Real-time response protection settings",
									Attributes: map[string]schema.Attribute{
										"detection": schema.StringAttribute{
											Computed:    true,
											Description: "Detection setting",
										},
										"prevention": schema.StringAttribute{
											Computed:    true,
											Description: "Prevention setting",
										},
									},
								},
								"script_based_execution_monitoring": schema.SingleNestedAttribute{
									Computed:    true,
									Description: "Script-based execution monitoring settings",
									Attributes: map[string]schema.Attribute{
										"detection": schema.StringAttribute{
											Computed:    true,
											Description: "Detection setting",
										},
										"prevention": schema.StringAttribute{
											Computed:    true,
											Description: "Prevention setting",
										},
									},
								},
								"sensor_anti_malware": schema.SingleNestedAttribute{
									Computed:    true,
									Description: "Sensor anti-malware protection settings",
									Attributes: map[string]schema.Attribute{
										"detection": schema.StringAttribute{
											Computed:    true,
											Description: "Detection setting",
										},
										"prevention": schema.StringAttribute{
											Computed:    true,
											Description: "Prevention setting",
										},
									},
								},
								"unknown_detection_related": schema.SingleNestedAttribute{
									Computed:    true,
									Description: "Unknown detection related settings",
									Attributes: map[string]schema.Attribute{
										"detection": schema.StringAttribute{
											Computed:    true,
											Description: "Detection setting",
										},
										"prevention": schema.StringAttribute{
											Computed:    true,
											Description: "Prevention setting",
										},
									},
								},
								"unknown_executable_detection": schema.SingleNestedAttribute{
									Computed:    true,
									Description: "Unknown executable detection settings",
									Attributes: map[string]schema.Attribute{
										"detection": schema.StringAttribute{
											Computed:    true,
											Description: "Detection setting",
										},
										"prevention": schema.StringAttribute{
											Computed:    true,
											Description: "Prevention setting",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func (d *preventionPoliciesDataSource) ValidateConfig(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var data preventionPoliciesDataSourceModel
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
			"Cannot specify 'filter', 'ids', and individual filter attributes (name, description, enabled, platform_name, created_by, modified_by) together. Please use only one filtering method: either 'filter' for FQL queries, 'ids' for specific IDs, or individual filter attributes.",
		)
	}
}

// getPreventionPolicies returns all prevention policies matching filter.
func (d *preventionPoliciesDataSource) getPreventionPolicies(
	ctx context.Context,
	filter string,
	sort string,
) ([]*models.PreventionPolicyV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	var allPolicies []*models.PreventionPolicyV1

	tflog.Debug(
		ctx,
		"[datasource] Getting all prevention policies",
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

	policies, diags := d.getPreventionPolicies(ctx, data.Filter.ValueString(), data.Sort.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if utils.IsKnown(data.IDs) {
		requestedIDs := utils.ListTypeAs[string](ctx, data.IDs, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}

		policies = filterPoliciesByIDs(policies, requestedIDs)
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

func filterPoliciesByIDs(policies []*models.PreventionPolicyV1, requestedIDs []string) []*models.PreventionPolicyV1 {
	idMap := make(map[string]bool, len(requestedIDs))
	for _, id := range requestedIDs {
		idMap[id] = true
	}

	filtered := make([]*models.PreventionPolicyV1, 0, len(requestedIDs))
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

func filterPoliciesByAttributes(policies []*models.PreventionPolicyV1, filters *preventionPoliciesDataSourceModel) []*models.PreventionPolicyV1 {
	filtered := make([]*models.PreventionPolicyV1, 0, len(policies))
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

		if !filters.PlatformName.IsNull() {
			if policy.PlatformName == nil || !strings.EqualFold(*policy.PlatformName, filters.PlatformName.ValueString()) {
				continue
			}
		}

		filtered = append(filtered, policy)
	}
	return filtered
}
