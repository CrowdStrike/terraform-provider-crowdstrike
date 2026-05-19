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
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
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
	tasksDataSourceDocumentationSection = "IT Automation"
	tasksDataSourceMarkdownDescription  = "This data source provides information about IT Automation tasks in CrowdStrike Falcon."
)

var tasksDataSourceApiScopes = []scopes.Scope{
	{
		Name:  "IT Automation - Tasks",
		Read:  true,
		Write: false,
	},
}

var (
	_ datasource.DataSource                   = &itAutomationTasksDataSource{}
	_ datasource.DataSourceWithConfigure      = &itAutomationTasksDataSource{}
	_ datasource.DataSourceWithValidateConfig = &itAutomationTasksDataSource{}
)

type itAutomationTasksDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type taskScriptColumnDataModel struct {
	Name types.String `tfsdk:"name"`
}

func (m taskScriptColumnDataModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"name": types.StringType,
	}
}

type taskScriptColumnsDataModel struct {
	Delimiter    types.String `tfsdk:"delimiter"`
	GroupResults types.Bool   `tfsdk:"group_results"`
	Columns      types.List   `tfsdk:"columns"`
}

func (m taskScriptColumnsDataModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"delimiter":     types.StringType,
		"group_results": types.BoolType,
		"columns":       types.ListType{ElemType: types.ObjectType{AttrTypes: taskScriptColumnDataModel{}.AttributeTypes()}},
	}
}

type taskVerificationStatementDataModel struct {
	DataComparator types.String `tfsdk:"data_comparator"`
	DataType       types.String `tfsdk:"data_type"`
	Key            types.String `tfsdk:"key"`
	TaskID         types.String `tfsdk:"task_id"`
	Value          types.String `tfsdk:"value"`
}

func (m taskVerificationStatementDataModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"data_comparator": types.StringType,
		"data_type":       types.StringType,
		"key":             types.StringType,
		"task_id":         types.StringType,
		"value":           types.StringType,
	}
}

type taskVerificationConditionDataModel struct {
	Operator   types.String `tfsdk:"operator"`
	Statements types.List   `tfsdk:"statements"`
}

func (m taskVerificationConditionDataModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"operator":   types.StringType,
		"statements": types.ListType{ElemType: types.ObjectType{AttrTypes: taskVerificationStatementDataModel{}.AttributeTypes()}},
	}
}

type taskDataModel struct {
	ID                    types.String      `tfsdk:"id"`
	Name                  types.String      `tfsdk:"name"`
	Description           types.String      `tfsdk:"description"`
	Type                  types.String      `tfsdk:"type"`
	AccessType            types.String      `tfsdk:"access_type"`
	AssignedUserIds       types.List        `tfsdk:"assigned_user_ids"`
	AssignedUserGroupIds  types.List        `tfsdk:"assigned_user_group_ids"`
	Target                types.String      `tfsdk:"target"`
	SupportedOs           types.List        `tfsdk:"supported_os"`
	OsQuery               types.String      `tfsdk:"os_query"`
	Runs                  types.Int32       `tfsdk:"runs"`
	HasTaskParameters     types.Bool        `tfsdk:"has_task_parameters"`
	TaskGroupID           types.String      `tfsdk:"task_group_id"`
	LinuxScriptContent    types.String      `tfsdk:"linux_script_content"`
	LinuxScriptFileId     types.String      `tfsdk:"linux_script_file_id"`
	LinuxScriptLanguage   types.String      `tfsdk:"linux_script_language"`
	MacScriptContent      types.String      `tfsdk:"mac_script_content"`
	MacScriptFileId       types.String      `tfsdk:"mac_script_file_id"`
	MacScriptLanguage     types.String      `tfsdk:"mac_script_language"`
	WindowsScriptContent  types.String      `tfsdk:"windows_script_content"`
	WindowsScriptFileId   types.String      `tfsdk:"windows_script_file_id"`
	WindowsScriptLanguage types.String      `tfsdk:"windows_script_language"`
	AdditionalFileIds     types.List        `tfsdk:"additional_file_ids"`
	ScriptColumns         types.Object      `tfsdk:"script_columns"`
	VerificationCondition types.List        `tfsdk:"verification_condition"`
	CreatedBy             types.String      `tfsdk:"created_by"`
	CreatedTime           timetypes.RFC3339 `tfsdk:"created_time"`
	ModifiedBy            types.String      `tfsdk:"modified_by"`
	ModifiedTime          timetypes.RFC3339 `tfsdk:"modified_time"`
	LastRunTime           timetypes.RFC3339 `tfsdk:"last_run_time"`
}

func (m taskDataModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":                      types.StringType,
		"name":                    types.StringType,
		"description":             types.StringType,
		"type":                    types.StringType,
		"access_type":             types.StringType,
		"assigned_user_ids":       types.ListType{ElemType: types.StringType},
		"assigned_user_group_ids": types.ListType{ElemType: types.StringType},
		"target":                  types.StringType,
		"supported_os":            types.ListType{ElemType: types.StringType},
		"os_query":                types.StringType,
		"runs":                    types.Int32Type,
		"has_task_parameters":     types.BoolType,
		"task_group_id":           types.StringType,
		"linux_script_content":    types.StringType,
		"linux_script_file_id":    types.StringType,
		"linux_script_language":   types.StringType,
		"mac_script_content":      types.StringType,
		"mac_script_file_id":      types.StringType,
		"mac_script_language":     types.StringType,
		"windows_script_content":  types.StringType,
		"windows_script_file_id":  types.StringType,
		"windows_script_language": types.StringType,
		"additional_file_ids":     types.ListType{ElemType: types.StringType},
		"script_columns":          types.ObjectType{AttrTypes: taskScriptColumnsDataModel{}.AttributeTypes()},
		"verification_condition":  types.ListType{ElemType: types.ObjectType{AttrTypes: taskVerificationConditionDataModel{}.AttributeTypes()}},
		"created_by":              types.StringType,
		"created_time":            timetypes.RFC3339Type{},
		"modified_by":             types.StringType,
		"modified_time":           timetypes.RFC3339Type{},
		"last_run_time":           timetypes.RFC3339Type{},
	}
}

type itAutomationTasksDataSourceModel struct {
	Filter     types.String `tfsdk:"filter"`
	IDs        types.List   `tfsdk:"ids"`
	Sort       types.String `tfsdk:"sort"`
	Name       types.String `tfsdk:"name"`
	Type       types.String `tfsdk:"type"`
	AccessType types.String `tfsdk:"access_type"`
	Tasks      types.List   `tfsdk:"tasks"`
}

func (m *itAutomationTasksDataSourceModel) hasIndividualFilters() bool {
	return utils.IsKnown(m.Name) ||
		utils.IsKnown(m.Type) ||
		utils.IsKnown(m.AccessType)
}

// buildFilterFromIndividualAttrs constructs an FQL filter from the convenience
// attributes. Returns an empty string when no convenience attributes are set.
func (m *itAutomationTasksDataSourceModel) buildFilterFromIndividualAttrs() string {
	var parts []string

	if utils.IsKnown(m.Name) {
		parts = append(parts, fmt.Sprintf("name:'%s'", m.Name.ValueString()))
	}

	if utils.IsKnown(m.Type) {
		apiType := convertType(m.Type.ValueString(), "api")
		parts = append(parts, fmt.Sprintf("task_type:'%s'", apiType))
	}

	if utils.IsKnown(m.AccessType) {
		parts = append(parts, fmt.Sprintf("access_type:'%s'", m.AccessType.ValueString()))
	}

	return strings.Join(parts, "+")
}

func (m *itAutomationTasksDataSourceModel) wrap(ctx context.Context, tasks []*models.ItautomationTask) diag.Diagnostics {
	var diags diag.Diagnostics

	taskModels := make([]taskDataModel, 0, len(tasks))
	for _, task := range tasks {
		if task == nil {
			continue
		}

		tm := taskDataModel{}
		tm.ID = flex.StringPointerToFramework(task.ID)
		tm.Name = flex.StringPointerToFramework(task.Name)
		tm.Description = flex.StringPointerToFramework(task.Description)
		tm.AccessType = flex.StringValueToFramework(task.AccessType)
		tm.Target = flex.StringPointerToFramework(task.Target)
		tm.OsQuery = flex.StringValueToFramework(task.OsQuery)
		tm.Runs = flex.Int32PointerToFramework(task.Runs)
		tm.HasTaskParameters = types.BoolValue(task.HasTaskParameters)
		tm.CreatedBy = flex.StringPointerToFramework(task.CreatedBy)
		tm.ModifiedBy = flex.StringPointerToFramework(task.ModifiedBy)

		if task.TaskType != nil {
			tm.Type = types.StringValue(convertType(*task.TaskType, "terraform"))
		} else {
			tm.Type = types.StringNull()
		}

		tm.CreatedTime = flex.DateTimePointerToFramework(task.CreatedTime)
		tm.ModifiedTime = flex.DateTimePointerToFramework(task.ModifiedTime)
		tm.LastRunTime = flex.DateTimePointerToFramework(task.LastRunTime)

		assignedUsers, listDiags := types.ListValueFrom(ctx, types.StringType, task.AssignedUserIds)
		diags.Append(listDiags...)
		tm.AssignedUserIds = assignedUsers

		assignedUserGroups, listDiags := types.ListValueFrom(ctx, types.StringType, task.AssignedUserGroupIds)
		diags.Append(listDiags...)
		tm.AssignedUserGroupIds = assignedUserGroups

		supportedOs, listDiags := types.ListValueFrom(ctx, types.StringType, task.SupportedOs)
		diags.Append(listDiags...)
		tm.SupportedOs = supportedOs

		if hasTaskGroupMembership(task.Groups) {
			tm.TaskGroupID = flex.StringPointerToFramework(task.Groups[0].ID)
		} else {
			tm.TaskGroupID = types.StringNull()
		}

		scriptSources := task.Queries
		if task.Remediations != nil {
			scriptSources = task.Remediations
		}

		var additionalFileIds []string
		if scriptSources != nil {
			scriptMap := []struct {
				script        *models.ItautomationScript
				contentField  *types.String
				languageField *types.String
				fileIdField   *types.String
			}{
				{scriptSources.Linux, &tm.LinuxScriptContent, &tm.LinuxScriptLanguage, &tm.LinuxScriptFileId},
				{scriptSources.Mac, &tm.MacScriptContent, &tm.MacScriptLanguage, &tm.MacScriptFileId},
				{scriptSources.Windows, &tm.WindowsScriptContent, &tm.WindowsScriptLanguage, &tm.WindowsScriptFileId},
			}

			for _, s := range scriptMap {
				if s.script == nil {
					*s.contentField = types.StringNull()
					*s.languageField = types.StringNull()
					*s.fileIdField = types.StringNull()
					continue
				}

				*s.contentField = flex.StringValueToFramework(s.script.Content)
				*s.languageField = flex.StringValueToFramework(s.script.Language)
				*s.fileIdField = flex.StringValueToFramework(s.script.ScriptFileID)

				if len(s.script.FileIds) > 0 && additionalFileIds == nil {
					additionalFileIds = s.script.FileIds
				}
			}
		} else {
			tm.LinuxScriptContent = types.StringNull()
			tm.LinuxScriptLanguage = types.StringNull()
			tm.LinuxScriptFileId = types.StringNull()
			tm.MacScriptContent = types.StringNull()
			tm.MacScriptLanguage = types.StringNull()
			tm.MacScriptFileId = types.StringNull()
			tm.WindowsScriptContent = types.StringNull()
			tm.WindowsScriptLanguage = types.StringNull()
			tm.WindowsScriptFileId = types.StringNull()
		}

		additionalList, listDiags := types.ListValueFrom(ctx, types.StringType, additionalFileIds)
		diags.Append(listDiags...)
		tm.AdditionalFileIds = additionalList

		scriptColumnsObj, scDiags := convertOutputParserToObject(ctx, task.OutputParserConfig)
		diags.Append(scDiags...)
		tm.ScriptColumns = scriptColumnsObj

		verificationList, vDiags := convertVerificationConditionsToList(ctx, task.VerificationCondition)
		diags.Append(vDiags...)
		tm.VerificationCondition = verificationList

		taskModels = append(taskModels, tm)
	}

	m.Tasks = utils.SliceToListTypeObject(ctx, taskModels, taskDataModel{}.AttributeTypes(), &diags)
	return diags
}

func convertOutputParserToObject(ctx context.Context, parser *models.ItautomationOutputParserConfig) (types.Object, diag.Diagnostics) {
	var diags diag.Diagnostics
	attrs := taskScriptColumnsDataModel{}.AttributeTypes()

	if parser == nil {
		return types.ObjectNull(attrs), diags
	}

	columns := make([]taskScriptColumnDataModel, 0, len(parser.Columns))
	for _, col := range parser.Columns {
		if col == nil {
			continue
		}
		columns = append(columns, taskScriptColumnDataModel{
			Name: types.StringPointerValue(col.Name),
		})
	}

	columnsList, listDiags := types.ListValueFrom(
		ctx,
		types.ObjectType{AttrTypes: taskScriptColumnDataModel{}.AttributeTypes()},
		columns,
	)
	diags.Append(listDiags...)
	if diags.HasError() {
		return types.ObjectNull(attrs), diags
	}

	model := taskScriptColumnsDataModel{
		Delimiter:    types.StringPointerValue(parser.Delimiter),
		GroupResults: types.BoolPointerValue(parser.DefaultGroupBy),
		Columns:      columnsList,
	}

	obj, objDiags := types.ObjectValueFrom(ctx, attrs, model)
	diags.Append(objDiags...)
	return obj, diags
}

func convertVerificationConditionsToList(ctx context.Context, conditions []*models.FalconforitapiConditionGroup) (types.List, diag.Diagnostics) {
	var diags diag.Diagnostics
	conditionObjType := types.ObjectType{AttrTypes: taskVerificationConditionDataModel{}.AttributeTypes()}
	statementObjType := types.ObjectType{AttrTypes: taskVerificationStatementDataModel{}.AttributeTypes()}

	result := make([]taskVerificationConditionDataModel, 0, len(conditions))
	for _, cond := range conditions {
		if cond == nil {
			continue
		}

		statements := make([]taskVerificationStatementDataModel, 0, len(cond.Statements))
		for _, stmt := range cond.Statements {
			if stmt == nil {
				continue
			}
			statements = append(statements, taskVerificationStatementDataModel{
				DataComparator: types.StringPointerValue(stmt.DataComparator),
				DataType:       types.StringPointerValue(stmt.DataType),
				Key:            types.StringPointerValue(stmt.Key),
				TaskID:         types.StringPointerValue(stmt.TaskID),
				Value:          types.StringPointerValue(stmt.Value),
			})
		}

		stmtList, stmtDiags := types.ListValueFrom(ctx, statementObjType, statements)
		diags.Append(stmtDiags...)
		if diags.HasError() {
			return types.ListNull(conditionObjType), diags
		}

		result = append(result, taskVerificationConditionDataModel{
			Operator:   types.StringValue(cond.Operator),
			Statements: stmtList,
		})
	}

	list, listDiags := types.ListValueFrom(ctx, conditionObjType, result)
	diags.Append(listDiags...)
	return list, diags
}

func NewItAutomationTasksDataSource() datasource.DataSource {
	return &itAutomationTasksDataSource{}
}

func (d *itAutomationTasksDataSource) Configure(
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

func (d *itAutomationTasksDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_it_automation_tasks"
}

func (d *itAutomationTasksDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			tasksDataSourceDocumentationSection,
			tasksDataSourceMarkdownDescription,
			tasksDataSourceApiScopes,
		),
		Attributes: map[string]schema.Attribute{
			"filter": schema.StringAttribute{
				Optional:    true,
				Description: "FQL filter to apply to the tasks query. Allowed filter fields: `access_type`, `created_by`, `created_time`, `last_run_time`, `modified_by`, `modified_time`, `name`, `runs`, `task_type`. The `task_type` field accepts `query` or `remediation` (note: the `type` attribute on this data source and the `crowdstrike_it_automation_task` resource exposes `remediation` as `action`). Cannot be used together with `ids` or individual filter attributes.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"ids": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "List of task IDs to retrieve. Cannot be used together with `filter` or individual filter attributes.",
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.LengthAtLeast(1),
					),
					listvalidator.SizeAtLeast(1),
					listvalidator.UniqueValues(),
				},
			},
			"sort": schema.StringAttribute{
				Optional:    true,
				Description: "Sort expression for the results. Allowed sort fields: `access_type`, `created_by`, `created_time`, `last_run_time`, `modified_by`, `modified_time`, `name`, `runs`, `task_type`. Example: `name|asc`.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"name": schema.StringAttribute{
				Optional:    true,
				Description: "Filter tasks by name. Supports FQL wildcard matching. Cannot be used together with `filter` or `ids`.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"type": schema.StringAttribute{
				Optional:    true,
				Description: "Filter tasks by type. One of: `query`, `action`. Cannot be used together with `filter` or `ids`.",
				Validators: []validator.String{
					stringvalidator.OneOf(TaskTypeQuery, TaskTypeAction),
				},
			},
			"access_type": schema.StringAttribute{
				Optional:    true,
				Description: "Filter tasks by access type. One of: `Public`, `Shared`. Cannot be used together with `filter` or `ids`.",
				Validators: []validator.String{
					stringvalidator.OneOf(AccessTypePublic, AccessTypeShared),
				},
			},
			"tasks": schema.ListNestedAttribute{
				Computed:    true,
				Description: "The list of IT Automation tasks.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "Identifier for the task.",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the task.",
						},
						"description": schema.StringAttribute{
							Computed:    true,
							Description: "Description of the task.",
						},
						"type": schema.StringAttribute{
							Computed:    true,
							Description: "Type of task (`query` or `action`).",
						},
						"access_type": schema.StringAttribute{
							Computed:    true,
							Description: "Access type of the task (`Public` or `Shared`).",
						},
						"assigned_user_ids": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "Assigned user IDs of the task.",
						},
						"assigned_user_group_ids": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "Assigned user group IDs of the task.",
						},
						"target": schema.StringAttribute{
							Computed:    true,
							Description: "Target filter in FQL format.",
						},
						"supported_os": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "List of supported operating systems.",
						},
						"os_query": schema.StringAttribute{
							Computed:    true,
							Description: "OSQuery string to execute.",
						},
						"runs": schema.Int32Attribute{
							Computed:    true,
							Description: "Number of times the task has been executed.",
						},
						"has_task_parameters": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether the task has parameters.",
						},
						"task_group_id": schema.StringAttribute{
							Computed:    true,
							Description: "The ID of the task group this task belongs to, if any.",
						},
						"linux_script_content": schema.StringAttribute{
							Computed:    true,
							Description: "Linux script content.",
						},
						"linux_script_file_id": schema.StringAttribute{
							Computed:    true,
							Description: "Linux RTR Response script ID.",
						},
						"linux_script_language": schema.StringAttribute{
							Computed:    true,
							Description: "Linux script language.",
						},
						"mac_script_content": schema.StringAttribute{
							Computed:    true,
							Description: "Mac script content.",
						},
						"mac_script_file_id": schema.StringAttribute{
							Computed:    true,
							Description: "Mac RTR Response script ID.",
						},
						"mac_script_language": schema.StringAttribute{
							Computed:    true,
							Description: "Mac script language.",
						},
						"windows_script_content": schema.StringAttribute{
							Computed:    true,
							Description: "Windows script content.",
						},
						"windows_script_file_id": schema.StringAttribute{
							Computed:    true,
							Description: "Windows RTR Response script ID.",
						},
						"windows_script_language": schema.StringAttribute{
							Computed:    true,
							Description: "Windows script language.",
						},
						"additional_file_ids": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "Additional RTR Response file IDs available for the task.",
						},
						"script_columns": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "Column configuration for the script output.",
							Attributes: map[string]schema.Attribute{
								"delimiter": schema.StringAttribute{
									Computed:    true,
									Description: "Delimiter character for script columns.",
								},
								"group_results": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether to group results by column values.",
								},
								"columns": schema.ListNestedAttribute{
									Computed:    true,
									Description: "List of column definitions.",
									NestedObject: schema.NestedAttributeObject{
										Attributes: map[string]schema.Attribute{
											"name": schema.StringAttribute{
												Computed:    true,
												Description: "Name of the column.",
											},
										},
									},
								},
							},
						},
						"verification_condition": schema.ListNestedAttribute{
							Computed:    true,
							Description: "Verification conditions for action tasks.",
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"operator": schema.StringAttribute{
										Computed:    true,
										Description: "Logical operator for the statements (`AND` or `OR`).",
									},
									"statements": schema.ListNestedAttribute{
										Computed:    true,
										Description: "List of verification statements.",
										NestedObject: schema.NestedAttributeObject{
											Attributes: map[string]schema.Attribute{
												"data_comparator": schema.StringAttribute{
													Computed:    true,
													Description: "Comparison operator for verification.",
												},
												"data_type": schema.StringAttribute{
													Computed:    true,
													Description: "Type of data being compared.",
												},
												"key": schema.StringAttribute{
													Computed:    true,
													Description: "Key to compare.",
												},
												"task_id": schema.StringAttribute{
													Computed:    true,
													Description: "ID of the task to query for results.",
												},
												"value": schema.StringAttribute{
													Computed:    true,
													Description: "Value to compare against.",
												},
											},
										},
									},
								},
							},
						},
						"created_by": schema.StringAttribute{
							Computed:    true,
							Description: "User who created the task.",
						},
						"created_time": schema.StringAttribute{
							Computed:    true,
							CustomType:  timetypes.RFC3339Type{},
							Description: "Timestamp when the task was created, in RFC3339 format.",
						},
						"modified_by": schema.StringAttribute{
							Computed:    true,
							Description: "User who last modified the task.",
						},
						"modified_time": schema.StringAttribute{
							Computed:    true,
							CustomType:  timetypes.RFC3339Type{},
							Description: "Timestamp when the task was last modified, in RFC3339 format.",
						},
						"last_run_time": schema.StringAttribute{
							Computed:    true,
							CustomType:  timetypes.RFC3339Type{},
							Description: "Timestamp of the last execution, in RFC3339 format.",
						},
					},
				},
			},
		},
	}
}

func (d *itAutomationTasksDataSource) ValidateConfig(
	ctx context.Context,
	req datasource.ValidateConfigRequest,
	resp *datasource.ValidateConfigResponse,
) {
	var data itAutomationTasksDataSourceModel
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
			"Cannot specify 'filter', 'ids', and individual filter attributes (name, type, access_type) together. Please use only one filtering method: either 'filter' for FQL queries, 'ids' for specific IDs, or individual filter attributes.",
		)
	}
}

// queryTasks retrieves all tasks matching the given FQL filter using the
// combined endpoint, paginating through the full result set.
func (d *itAutomationTasksDataSource) queryTasks(
	ctx context.Context,
	filter string,
	sort string,
) ([]*models.ItautomationTask, diag.Diagnostics) {
	var diags diag.Diagnostics
	var allTasks []*models.ItautomationTask

	tflog.Debug(ctx, "[datasource] Getting IT Automation tasks",
		map[string]any{
			"filter": filter,
			"sort":   sort,
		})

	limit := int64(paginationLimit)
	offset := int64(0)

	for {
		params := &it_automation.ITAutomationGetTasksByQueryParams{
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

		res, err := d.client.ItAutomation.ITAutomationGetTasksByQuery(params)
		if err != nil {
			d := tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, tasksDataSourceApiScopes)
			if d.Summary() == tferrors.NotFoundErrorSummary {
				return allTasks, diags
			}
			diags.Append(d)
			return allTasks, diags
		}

		if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
			break
		}

		allTasks = append(allTasks, res.Payload.Resources...)

		if int64(len(res.Payload.Resources)) < limit {
			break
		}

		offset += limit
	}

	return allTasks, diags
}

// getTasksByIDs retrieves tasks by explicit ID, batching in chunks of
// paginationLimit to stay within API limits.
func (d *itAutomationTasksDataSource) getTasksByIDs(
	ctx context.Context,
	ids []string,
) ([]*models.ItautomationTask, diag.Diagnostics) {
	var diags diag.Diagnostics
	var allTasks []*models.ItautomationTask

	for i := 0; i < len(ids); i += paginationLimit {
		end := min(i+paginationLimit, len(ids))

		params := &it_automation.ITAutomationGetTasksParams{
			Context: ctx,
			Ids:     ids[i:end],
		}

		res, err := d.client.ItAutomation.ITAutomationGetTasks(params)
		if err != nil {
			d := tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, tasksDataSourceApiScopes)
			if d.Summary() == tferrors.NotFoundErrorSummary {
				tflog.Debug(ctx, "[datasource] No IT Automation tasks found for batch",
					map[string]any{
						"batch_start": i,
						"batch_end":   end,
						"batch_size":  end - i,
					})
				continue
			}
			diags.Append(d)
			return allTasks, diags
		}

		if res == nil || res.Payload == nil {
			continue
		}

		allTasks = append(allTasks, res.Payload.Resources...)
	}

	return allTasks, diags
}

func (d *itAutomationTasksDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data itAutomationTasksDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var tasks []*models.ItautomationTask
	var diags diag.Diagnostics

	switch {
	case utils.IsKnown(data.IDs):
		requestedIDs := utils.ListTypeAs[string](ctx, data.IDs, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}

		tasks, diags = d.getTasksByIDs(ctx, requestedIDs)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
	default:
		filter := data.Filter.ValueString()
		if filter == "" && data.hasIndividualFilters() {
			filter = data.buildFilterFromIndividualAttrs()
		}

		tasks, diags = d.queryTasks(ctx, filter, data.Sort.ValueString())
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	resp.Diagnostics.Append(data.wrap(ctx, tasks)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
