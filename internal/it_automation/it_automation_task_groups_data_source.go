package itautomation

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/it_automation"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
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

var (
	taskGroupsDataSourceDocumentationSection string         = "IT Automation"
	taskGroupsDataSourceMarkdownDescription  string         = "This data source provides information about IT Automation task groups in CrowdStrike Falcon. Task groups allow organizing tasks for RBAC and grouping purposes."
	taskGroupsDataSourceRequiredScopes       []scopes.Scope = []scopes.Scope{
		{
			Name: "IT Automation - Tasks",
			Read: true,
		},
	}
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource                   = &itAutomationTaskGroupsDataSource{}
	_ datasource.DataSourceWithConfigure      = &itAutomationTaskGroupsDataSource{}
	_ datasource.DataSourceWithValidateConfig = &itAutomationTaskGroupsDataSource{}
)

// NewItAutomationTaskGroupsDataSource is a helper function to simplify the provider implementation.
func NewItAutomationTaskGroupsDataSource() datasource.DataSource {
	return &itAutomationTaskGroupsDataSource{}
}

// itAutomationTaskGroupsDataSource is the data source implementation.
type itAutomationTaskGroupsDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type taskGroupDataModel struct {
	ID                   types.String `tfsdk:"id"`
	Name                 types.String `tfsdk:"name"`
	Description          types.String `tfsdk:"description"`
	AccessType           types.String `tfsdk:"access_type"`
	IsPreset             types.Bool   `tfsdk:"is_preset"`
	SupportedOs          types.List   `tfsdk:"supported_os"`
	TaskIds              types.List   `tfsdk:"task_ids"`
	AssignedUserIds      types.List   `tfsdk:"assigned_user_ids"`
	AssignedUserGroupIds types.List   `tfsdk:"assigned_user_group_ids"`
	CreatedBy            types.String `tfsdk:"created_by"`
	CreatedTime          types.String `tfsdk:"created_time"`
	ModifiedBy           types.String `tfsdk:"modified_by"`
	ModifiedTime         types.String `tfsdk:"modified_time"`
}

func (m taskGroupDataModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":                      types.StringType,
		"name":                    types.StringType,
		"description":             types.StringType,
		"access_type":             types.StringType,
		"is_preset":               types.BoolType,
		"supported_os":            types.ListType{ElemType: types.StringType},
		"task_ids":                types.ListType{ElemType: types.StringType},
		"assigned_user_ids":       types.ListType{ElemType: types.StringType},
		"assigned_user_group_ids": types.ListType{ElemType: types.StringType},
		"created_by":              types.StringType,
		"created_time":            types.StringType,
		"modified_by":             types.StringType,
		"modified_time":           types.StringType,
	}
}

type itAutomationTaskGroupsDataSourceModel struct {
	Filter     types.String `tfsdk:"filter"`
	IDs        types.List   `tfsdk:"ids"`
	Sort       types.String `tfsdk:"sort"`
	Name       types.String `tfsdk:"name"`
	AccessType types.String `tfsdk:"access_type"`
	TaskGroups types.List   `tfsdk:"task_groups"`
}

// hasIndividualFilters checks if any of the individual filter attributes are set.
func (m itAutomationTaskGroupsDataSourceModel) hasIndividualFilters() bool {
	return utils.IsKnown(m.Name) || utils.IsKnown(m.AccessType)
}

// toFQL converts individual filter attributes to an FQL filter expression.
func (m itAutomationTaskGroupsDataSourceModel) toFQL() string {
	parts := make([]string, 0, 2)
	if utils.IsKnown(m.Name) {
		parts = append(parts, fmt.Sprintf("name:'%s'", m.Name.ValueString()))
	}
	if utils.IsKnown(m.AccessType) {
		parts = append(parts, fmt.Sprintf("access_type:'%s'", m.AccessType.ValueString()))
	}
	return strings.Join(parts, "+")
}

func (m *itAutomationTaskGroupsDataSourceModel) wrap(ctx context.Context, groups []*models.ItautomationTaskGroup) diag.Diagnostics {
	var diags diag.Diagnostics

	groupModels := make([]taskGroupDataModel, 0, len(groups))
	for _, group := range groups {
		if group == nil {
			continue
		}

		groupModel := taskGroupDataModel{
			ID:           flex.StringPointerToFramework(group.ID),
			Name:         flex.StringPointerToFramework(group.Name),
			Description:  flex.StringPointerToFramework(group.Description),
			AccessType:   flex.StringPointerToFramework(group.AccessType),
			IsPreset:     types.BoolPointerValue(group.IsPreset),
			CreatedBy:    flex.StringPointerToFramework(group.CreatedBy),
			ModifiedBy:   flex.StringPointerToFramework(group.ModifiedBy),
			CreatedTime:  flex.StringValueToFramework(group.CreatedTime.String()),
			ModifiedTime: flex.StringValueToFramework(group.ModifiedTime.String()),
		}

		supportedOs, d := flex.FlattenStringValueList(ctx, group.SupportedOs)
		diags.Append(d...)
		groupModel.SupportedOs = supportedOs

		taskIDs, d := flex.FlattenStringValueList(ctx, group.TaskIds)
		diags.Append(d...)
		groupModel.TaskIds = taskIDs

		assignedUserIds, d := flex.FlattenStringValueList(ctx, group.AssignedUserIds)
		diags.Append(d...)
		groupModel.AssignedUserIds = assignedUserIds

		assignedUserGroupIds, d := flex.FlattenStringValueList(ctx, group.AssignedUserGroupIds)
		diags.Append(d...)
		groupModel.AssignedUserGroupIds = assignedUserGroupIds

		groupModels = append(groupModels, groupModel)
	}

	m.TaskGroups = utils.SliceToListTypeObject(ctx, groupModels, taskGroupDataModel{}.AttributeTypes(), &diags)
	return diags
}

// Configure adds the provider configured client to the data source.
func (d *itAutomationTaskGroupsDataSource) Configure(
	_ context.Context,
	req datasource.ConfigureRequest,
	resp *datasource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	providerConfig, ok := req.ProviderData.(config.ProviderConfig)
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

	d.client = providerConfig.Client
}

// Metadata returns the data source type name.
func (d *itAutomationTaskGroupsDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_it_automation_task_groups"
}

// Schema defines the schema for the data source.
func (d *itAutomationTaskGroupsDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			taskGroupsDataSourceDocumentationSection,
			taskGroupsDataSourceMarkdownDescription,
			taskGroupsDataSourceRequiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"filter": schema.StringAttribute{
				Optional:    true,
				Description: "FQL filter to apply to the task groups query. Cannot be used together with `ids` or individual filter attributes. Allowed filter fields: `access_type`, `created_by`, `created_time`, `modified_by`, `modified_time`, `name`.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"ids": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "List of task group IDs to retrieve. Cannot be used together with `filter` or individual filter attributes.",
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
				Description: "Sort expression for results. Allowed sort fields: `access_type`, `created_by`, `created_time`, `modified_by`, `modified_time`, `name`. Append `|asc` or `|desc` for direction. Example: `name|asc`.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"name": schema.StringAttribute{
				Optional:    true,
				Description: "Filter task groups by name. Translated to FQL. Cannot be used together with `filter` or `ids`.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"access_type": schema.StringAttribute{
				Optional:    true,
				Description: "Filter task groups by access type. Translated to FQL. Cannot be used together with `filter` or `ids`.",
				Validators: []validator.String{
					stringvalidator.OneOf("Public", "Shared", "Private"),
				},
			},
			"task_groups": schema.ListNestedAttribute{
				Computed:    true,
				Description: "The list of IT Automation task groups.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "Identifier for the task group.",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the task group.",
						},
						"description": schema.StringAttribute{
							Computed:    true,
							Description: "Description of the task group.",
						},
						"access_type": schema.StringAttribute{
							Computed:    true,
							Description: "Access type of the task group (Public, Shared, Private).",
						},
						"is_preset": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether this is a preset task group.",
						},
						"supported_os": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "List of supported operating systems.",
						},
						"task_ids": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "List of task IDs in the group.",
						},
						"assigned_user_ids": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "Assigned user IDs of the group.",
						},
						"assigned_user_group_ids": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "Assigned user group IDs of the group.",
						},
						"created_by": schema.StringAttribute{
							Computed:    true,
							Description: "User who created the task group.",
						},
						"created_time": schema.StringAttribute{
							Computed:    true,
							Description: "Timestamp when the task group was created.",
						},
						"modified_by": schema.StringAttribute{
							Computed:    true,
							Description: "User who last modified the task group.",
						},
						"modified_time": schema.StringAttribute{
							Computed:    true,
							Description: "Timestamp when the task group was last modified.",
						},
					},
				},
			},
		},
	}
}

// ValidateConfig validates the data source configuration.
func (d *itAutomationTaskGroupsDataSource) ValidateConfig(
	ctx context.Context,
	req datasource.ValidateConfigRequest,
	resp *datasource.ValidateConfigResponse,
) {
	var data itAutomationTaskGroupsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	hasFilter := utils.IsKnown(data.Filter)
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
			"Cannot specify 'filter', 'ids', and individual filter attributes (name, access_type) together. Please use only one filtering method: either 'filter' for FQL queries, 'ids' for specific IDs, or individual filter attributes.",
		)
	}
}

// getTaskGroupsByIDs fetches task groups directly by their IDs.
func (d *itAutomationTaskGroupsDataSource) getTaskGroupsByIDs(
	ctx context.Context,
	ids []string,
) ([]*models.ItautomationTaskGroup, diag.Diagnostics) {
	var diags diag.Diagnostics

	tflog.Debug(ctx, "[datasource] Getting IT automation task groups by IDs",
		map[string]any{"count": len(ids)})

	ok, multi, err := d.client.ItAutomation.ITAutomationGetTaskGroups(
		&it_automation.ITAutomationGetTaskGroupsParams{
			Context: ctx,
			Ids:     ids,
		},
	)
	if err != nil {
		apiDiag := tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, taskGroupsDataSourceRequiredScopes)
		if apiDiag.Summary() == tferrors.NotFoundErrorSummary {
			tflog.Debug(ctx, "[datasource] No IT automation task groups found for the provided IDs (404), returning empty list")
			return []*models.ItautomationTaskGroup{}, diags
		}
		diags.Append(apiDiag)
		return []*models.ItautomationTaskGroup{}, diags
	}

	if ok != nil && ok.Payload != nil {
		return ok.Payload.Resources, diags
	}

	if multi != nil && multi.Payload != nil {
		return multi.Payload.Resources, diags
	}

	return []*models.ItautomationTaskGroup{}, diags
}

// getTaskGroupsByQuery fetches task groups using the combined filter/sort/pagination endpoint.
func (d *itAutomationTaskGroupsDataSource) getTaskGroupsByQuery(
	ctx context.Context,
	filter string,
	sort string,
) ([]*models.ItautomationTaskGroup, diag.Diagnostics) {
	var diags diag.Diagnostics
	var allGroups []*models.ItautomationTaskGroup

	tflog.Debug(ctx, "[datasource] Getting IT automation task groups by query",
		map[string]any{"filter": filter, "sort": sort})

	limit := int64(paginationLimit)
	offset := int64(0)

	for {
		params := &it_automation.ITAutomationGetTaskGroupsByQueryParams{
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

		ok, multi, err := d.client.ItAutomation.ITAutomationGetTaskGroupsByQuery(params)
		if err != nil {
			apiDiag := tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, taskGroupsDataSourceRequiredScopes)
			if apiDiag.Summary() == tferrors.NotFoundErrorSummary {
				tflog.Debug(ctx, "[datasource] No IT automation task groups found (404), returning empty list")
				return allGroups, diags
			}
			diags.Append(apiDiag)
			return allGroups, diags
		}

		var payload *models.ItautomationGetTaskGroupsResponse
		if ok != nil {
			payload = ok.Payload
		} else if multi != nil {
			payload = multi.Payload
		}

		if payload == nil || len(payload.Resources) == 0 {
			break
		}

		allGroups = append(allGroups, payload.Resources...)

		pageCount := int64(len(payload.Resources))
		if pageCount < limit {
			break
		}

		if payload.Meta != nil && payload.Meta.Pagination != nil &&
			payload.Meta.Pagination.Total != nil {
			if int64(len(allGroups)) >= *payload.Meta.Pagination.Total {
				break
			}
		}

		offset += pageCount
	}

	return allGroups, diags
}

// Read refreshes the Terraform state with the latest data.
func (d *itAutomationTaskGroupsDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data itAutomationTaskGroupsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var groups []*models.ItautomationTaskGroup

	if utils.IsKnown(data.IDs) && len(data.IDs.Elements()) > 0 {
		ids := utils.ListTypeAs[string](ctx, data.IDs, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}

		result, diags := d.getTaskGroupsByIDs(ctx, ids)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		groups = result
	} else {
		filter := data.Filter.ValueString()
		if !utils.IsKnown(data.Filter) && data.hasIndividualFilters() {
			filter = data.toFQL()
		}

		result, diags := d.getTaskGroupsByQuery(ctx, filter, data.Sort.ValueString())
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		groups = result
	}

	resp.Diagnostics.Append(data.wrap(ctx, groups)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
