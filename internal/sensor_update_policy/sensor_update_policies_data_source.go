package sensorupdatepolicy

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
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
	dataSourceDocumentationSection = "Sensor Update Policies"
	dataSourceMarkdownDescription  = "This data source provides information about sensor update policies in Falcon."
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource                   = &sensorUpdatePoliciesDataSource{}
	_ datasource.DataSourceWithConfigure      = &sensorUpdatePoliciesDataSource{}
	_ datasource.DataSourceWithValidateConfig = &sensorUpdatePoliciesDataSource{}
)

// Configure adds the provider configured client to the data source.
func (d *sensorUpdatePoliciesDataSource) Configure(
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

// sensorUpdatePoliciesDataSource is the data source implementation.
type sensorUpdatePoliciesDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type policyDataModel struct {
	ID                  types.String `tfsdk:"id"`
	Name                types.String `tfsdk:"name"`
	Description         types.String `tfsdk:"description"`
	Enabled             types.Bool   `tfsdk:"enabled"`
	PlatformName        types.String `tfsdk:"platform_name"`
	CreatedBy           types.String `tfsdk:"created_by"`
	CreatedTimestamp    types.String `tfsdk:"created_timestamp"`
	ModifiedBy          types.String `tfsdk:"modified_by"`
	ModifiedTimestamp   types.String `tfsdk:"modified_timestamp"`
	HostGroups          types.List   `tfsdk:"host_groups"`
	Build               types.String `tfsdk:"build"`
	BuildArm64          types.String `tfsdk:"build_arm64"`
	UninstallProtection types.Bool   `tfsdk:"uninstall_protection"`
	Schedule            types.Object `tfsdk:"schedule"`
}

func (m policyDataModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":                   types.StringType,
		"name":                 types.StringType,
		"description":          types.StringType,
		"enabled":              types.BoolType,
		"platform_name":        types.StringType,
		"created_by":           types.StringType,
		"created_timestamp":    types.StringType,
		"modified_by":          types.StringType,
		"modified_timestamp":   types.StringType,
		"host_groups":          types.ListType{ElemType: types.StringType},
		"build":                types.StringType,
		"build_arm64":          types.StringType,
		"uninstall_protection": types.BoolType,
		"schedule":             types.ObjectType{AttrTypes: policySchedule{}.AttributeTypes()},
	}
}

// sensorUpdatePoliciesDataSourceModel represents the data source model (exported for testing).
type sensorUpdatePoliciesDataSourceModel struct {
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

func (m *sensorUpdatePoliciesDataSourceModel) wrap(ctx context.Context, policies []*models.SensorUpdatePolicyV2) diag.Diagnostics {
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

		hostGroups, diagsHostGroups := hostgroups.ConvertHostGroupsToList(ctx, policy.Groups)
		diags.Append(diagsHostGroups...)
		if diags.HasError() {
			return diags
		}
		policyModel.HostGroups = hostGroups

		if policy.Settings != nil {
			if policy.Settings.Build != nil && *policy.Settings.Build != "" {
				policyModel.Build = types.StringValue(*policy.Settings.Build)
			} else {
				policyModel.Build = types.StringNull()
			}

			if policy.Settings.UninstallProtection != nil {
				if *policy.Settings.UninstallProtection == "ENABLED" {
					policyModel.UninstallProtection = types.BoolValue(true)
				} else {
					policyModel.UninstallProtection = types.BoolValue(false)
				}
			}

			if policy.PlatformName != nil && strings.ToLower(*policy.PlatformName) == "linux" && policy.Settings.Variants != nil {
				for _, v := range policy.Settings.Variants {
					if v != nil && v.Platform != nil && strings.EqualFold(*v.Platform, linuxArm64Varient) {
						if v.Build != nil && *v.Build != "" {
							policyModel.BuildArm64 = types.StringValue(*v.Build)
						} else {
							policyModel.BuildArm64 = types.StringNull()
						}
						break
					}
				}
			}

			policySchedule := policySchedule{}
			policySchedule.TimeBlocks = types.SetNull(types.ObjectType{AttrTypes: timeBlock{}.AttributeTypes()})

			if policy.Settings.Scheduler != nil {
				policySchedule.Enabled = types.BoolPointerValue(policy.Settings.Scheduler.Enabled)

				if policy.Settings.Scheduler.Enabled != nil && *policy.Settings.Scheduler.Enabled {
					if policy.Settings.Scheduler.Timezone != nil && *policy.Settings.Scheduler.Timezone != "" {
						policySchedule.Timezone = types.StringValue(*policy.Settings.Scheduler.Timezone)
					} else {
						policySchedule.Timezone = types.StringNull()
					}

					if len(policy.Settings.Scheduler.Schedules) > 0 {
						timeBlockObjects := []timeBlock{}

						for _, s := range policy.Settings.Scheduler.Schedules {
							daysStr := []string{}
							for _, d := range s.Days {
								daysStr = append(daysStr, int64ToDay[d])
							}

							days, diagsDay := types.SetValueFrom(ctx, types.StringType, daysStr)
							diags.Append(diagsDay...)
							if diags.HasError() {
								return diags
							}

							var startTime, endTime types.String
							if s.Start != nil && *s.Start != "" {
								startTime = types.StringValue(*s.Start)
							} else {
								startTime = types.StringNull()
							}
							if s.End != nil && *s.End != "" {
								endTime = types.StringValue(*s.End)
							} else {
								endTime = types.StringNull()
							}

							timeBlockObjects = append(timeBlockObjects, timeBlock{
								Days:      days,
								StartTime: startTime,
								EndTime:   endTime,
							})
						}

						timeBlocks, diagsTimeBlocks := types.SetValueFrom(
							ctx,
							types.ObjectType{AttrTypes: timeBlock{}.AttributeTypes()},
							timeBlockObjects,
						)
						diags.Append(diagsTimeBlocks...)
						if diags.HasError() {
							return diags
						}
						policySchedule.TimeBlocks = timeBlocks
					}
				}
			}

			scheduleObj, diagsSchedule := types.ObjectValueFrom(
				ctx,
				policySchedule.AttributeTypes(),
				policySchedule,
			)
			diags.Append(diagsSchedule...)
			if diags.HasError() {
				return diags
			}
			policyModel.Schedule = scheduleObj
		}

		policyModels = append(policyModels, policyModel)
	}

	m.Policies = utils.SliceToListTypeObject(ctx, policyModels, policyDataModel{}.AttributeTypes(), &diags)
	return diags
}

// hasIndividualFilters checks if any of the individual filter attributes are set.
func (m *sensorUpdatePoliciesDataSourceModel) hasIndividualFilters() bool {
	return utils.IsKnown(m.Name) ||
		utils.IsKnown(m.Description) ||
		utils.IsKnown(m.Enabled) ||
		utils.IsKnown(m.PlatformName) ||
		utils.IsKnown(m.CreatedBy) ||
		utils.IsKnown(m.ModifiedBy)
}

// NewSensorUpdatePoliciesDataSource is a helper function to simplify the provider implementation.
func NewSensorUpdatePoliciesDataSource() datasource.DataSource {
	return &sensorUpdatePoliciesDataSource{}
}

// Metadata returns the data source type name.
func (d *sensorUpdatePoliciesDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_sensor_update_policies"
}

// Schema defines the schema for the data source.
func (d *sensorUpdatePoliciesDataSource) Schema(
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
				Description: "FQL filter to apply to the sensor update policies query. When specified, only policies matching the filter will be returned. Cannot be used together with 'ids' or other filter attributes. Example: `platform_name:'Windows'`",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"ids": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "List of sensor update policy IDs to retrieve. When specified, only policies with matching IDs will be returned. Cannot be used together with 'filter' or other filter attributes.",
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
					fwvalidators.StringNotWhitespace(),
				},
			},
			"name": schema.StringAttribute{
				Optional:    true,
				Description: "Filter policies by name. All provided filter attributes must match for a policy to be returned (omitted attributes are ignored). Supports wildcard matching with '*' where '*' matches any sequence of characters until the end of the string or until the next literal character in the pattern is found. Multiple wildcards can be used in a single pattern. Matching is case insensitive. Cannot be used together with 'filter' or 'ids'.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Filter policies by description. All provided filter attributes must match for a policy to be returned (omitted attributes are ignored). Supports wildcard matching with '*' where '*' matches any sequence of characters until the end of the string or until the next literal character in the pattern is found. Multiple wildcards can be used in a single pattern. Matching is case insensitive. Cannot be used together with 'filter' or 'ids'.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
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
					fwvalidators.StringNotWhitespace(),
				},
			},
			"modified_by": schema.StringAttribute{
				Optional:    true,
				Description: "Filter policies by the user who last modified them. All provided filter attributes must match for a policy to be returned (omitted attributes are ignored). Supports wildcard matching with '*' where '*' matches any sequence of characters until the end of the string or until the next literal character in the pattern is found. Multiple wildcards can be used in a single pattern. Matching is case insensitive. Cannot be used together with 'filter' or 'ids'.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"policies": schema.ListNestedAttribute{
				Computed:    true,
				Description: "The list of sensor update policies",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "The sensor update policy ID",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "The sensor update policy name",
						},
						"description": schema.StringAttribute{
							Computed:    true,
							Description: "The sensor update policy description",
						},
						"platform_name": schema.StringAttribute{
							Computed:    true,
							Description: "The platform name (Windows, Linux, Mac)",
						},
						"enabled": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether the sensor update policy is enabled",
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
						"build": schema.StringAttribute{
							Computed:    true,
							Description: "The target build applied to devices in the policy",
						},
						"build_arm64": schema.StringAttribute{
							Computed:    true,
							Description: "The ARM64 build applied to Linux devices (only set for Linux policies)",
						},
						"uninstall_protection": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether uninstall protection is enabled",
						},
						"schedule": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "The schedule that controls when sensor updates are allowed",
							Attributes: map[string]schema.Attribute{
								"enabled": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether the update schedule is enabled",
								},
								"timezone": schema.StringAttribute{
									Computed:    true,
									Description: "The timezone used for the time blocks",
								},
								"time_blocks": schema.SetNestedAttribute{
									Computed:    true,
									Description: "Time blocks when sensor updates are prohibited",
									NestedObject: schema.NestedAttributeObject{
										Attributes: map[string]schema.Attribute{
											"days": schema.SetAttribute{
												Computed:    true,
												ElementType: types.StringType,
												Description: "Days of the week when this time block is active",
											},
											"start_time": schema.StringAttribute{
												Computed:    true,
												Description: "Start time in 24HR format",
											},
											"end_time": schema.StringAttribute{
												Computed:    true,
												Description: "End time in 24HR format",
											},
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

func (d *sensorUpdatePoliciesDataSource) ValidateConfig(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var data sensorUpdatePoliciesDataSourceModel
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

// getSensorUpdatePolicies returns all sensor update policies matching filter.
func (d *sensorUpdatePoliciesDataSource) getSensorUpdatePolicies(
	ctx context.Context,
	filter string,
	sort string,
) ([]*models.SensorUpdatePolicyV2, diag.Diagnostics) {
	var diags diag.Diagnostics
	var allPolicies []*models.SensorUpdatePolicyV2

	tflog.Debug(
		ctx,
		"[datasource] Getting all sensor update policies",
	)

	limit := int64(5000)
	offset := int64(0)

	for {
		params := &sensor_update_policies.QueryCombinedSensorUpdatePoliciesV2Params{
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

		res, err := d.client.SensorUpdatePolicies.QueryCombinedSensorUpdatePoliciesV2(params)
		if err != nil {
			diags.Append(tferrors.NewOperationError(tferrors.Read, err))
			return allPolicies, diags
		}

		if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
			tflog.Debug(ctx, "[datasource] No more sensor update policies to retrieve",
				map[string]interface{}{
					"total_retrieved": len(allPolicies),
				})
			break
		}

		allPolicies = append(allPolicies, res.Payload.Resources...)
		tflog.Debug(ctx, "[datasource] Retrieved page of sensor update policies",
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
func (d *sensorUpdatePoliciesDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data sensorUpdatePoliciesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policies, diags := d.getSensorUpdatePolicies(ctx, data.Filter.ValueString(), data.Sort.ValueString())
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

// filterPoliciesByIDs filters policies by their IDs.
func filterPoliciesByIDs(policies []*models.SensorUpdatePolicyV2, requestedIDs []string) []*models.SensorUpdatePolicyV2 {
	idMap := make(map[string]bool, len(requestedIDs))
	for _, id := range requestedIDs {
		idMap[id] = true
	}

	filtered := make([]*models.SensorUpdatePolicyV2, 0, len(requestedIDs))
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

// filterPoliciesByAttributes filters policies by individual attributes.
func filterPoliciesByAttributes(policies []*models.SensorUpdatePolicyV2, filters *sensorUpdatePoliciesDataSourceModel) []*models.SensorUpdatePolicyV2 {
	filtered := make([]*models.SensorUpdatePolicyV2, 0, len(policies))
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
