package itautomation

import (
	"context"
	"fmt"
	"regexp"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/it_automation"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                     = &itAutomationTaskResource{}
	_ resource.ResourceWithConfigure        = &itAutomationTaskResource{}
	_ resource.ResourceWithImportState      = &itAutomationTaskResource{}
	_ resource.ResourceWithValidateConfig   = &itAutomationTaskResource{}
	_ resource.ResourceWithConfigValidators = &itAutomationTaskResource{}
	_ resource.ResourceWithModifyPlan       = &itAutomationTaskResource{}
)

var (
	tasksDocumentationSection string         = "IT Automation"
	tasksMarkdownDescription  string         = "This resource allows management of IT Automation tasks in the CrowdStrike Falcon platform. Tasks allow you to run queries or actions across your hosts."
	tasksRequiredScopes       []scopes.Scope = itAutomationScopes
)

// NewItAutomationTaskResource is a helper function to simplify the provider implementation.
func NewItAutomationTaskResource() resource.Resource {
	return &itAutomationTaskResource{}
}

// itAutomationTaskResource is the resource implementation.
type itAutomationTaskResource struct {
	client *client.CrowdStrikeAPISpecification
}

type scriptColumnModel struct {
	Name types.String `tfsdk:"name"`
}

type scriptColumnsModel struct {
	Columns      types.List   `tfsdk:"columns"`
	Delimiter    types.String `tfsdk:"delimiter"`
	GroupResults types.Bool   `tfsdk:"group_results"`
}

type verificationStatementModel struct {
	DataComparator types.String `tfsdk:"data_comparator"`
	DataType       types.String `tfsdk:"data_type"`
	Key            types.String `tfsdk:"key"`
	TaskID         types.String `tfsdk:"task_id"`
	Value          types.String `tfsdk:"value"`
}

type verificationConditionModel struct {
	Operator   types.String `tfsdk:"operator"`
	Statements types.List   `tfsdk:"statements"`
}

// itAutomationTaskResourceModel is the resource model.
type itAutomationTaskResourceModel struct {
	ID                       types.String `tfsdk:"id"`
	Name                     types.String `tfsdk:"name"`
	Description              types.String `tfsdk:"description"`
	AccessType               types.String `tfsdk:"access_type"`
	AssignedUserIds          types.Set    `tfsdk:"assigned_user_ids"`
	EffectiveAccessType      types.String `tfsdk:"effective_access_type"`
	EffectiveAssignedUserIds types.Set    `tfsdk:"effective_assigned_user_ids"`
	AdditionalFileIds        types.Set    `tfsdk:"additional_file_ids"`
	LastUpdated              types.String `tfsdk:"last_updated"`
	LinuxScriptContent       types.String `tfsdk:"linux_script_content"`
	LinuxScriptFileId        types.String `tfsdk:"linux_script_file_id"`
	LinuxScriptLanguage      types.String `tfsdk:"linux_script_language"`
	MacScriptContent         types.String `tfsdk:"mac_script_content"`
	MacScriptFileId          types.String `tfsdk:"mac_script_file_id"`
	MacScriptLanguage        types.String `tfsdk:"mac_script_language"`
	OsQuery                  types.String `tfsdk:"os_query"`
	ScriptColumns            types.Object `tfsdk:"script_columns"`
	Target                   types.String `tfsdk:"target"`
	TaskGroupID              types.String `tfsdk:"task_group_id"`
	Type                     types.String `tfsdk:"type"`
	VerificationCondition    types.List   `tfsdk:"verification_condition"`
	WindowsScriptContent     types.String `tfsdk:"windows_script_content"`
	WindowsScriptFileId      types.String `tfsdk:"windows_script_file_id"`
	WindowsScriptLanguage    types.String `tfsdk:"windows_script_language"`
}

// convertType converts the type value to the Terraform or API expected values.
func convertType(typeValue, dest string) string {
	if dest == "terraform" && typeValue == TaskTypeRemediation {
		typeValue = TaskTypeAction
	} else if dest == "api" && typeValue == TaskTypeAction {
		typeValue = TaskTypeRemediation
	}
	return typeValue
}

// createScriptFromPlan creates an API script object from Terraform plan values.
func createScriptFromPlan(
	content types.String,
	language types.String,
	fileID types.String,
	fileIDs []string,
) *models.ItautomationScript {
	if content.IsNull() && fileID.IsNull() {
		return nil
	}

	script := &models.ItautomationScript{}

	if !fileID.IsNull() {
		script.ScriptFileID = fileID.ValueString()
		script.ActionType = "script_file"
		if !language.IsNull() {
			script.Language = language.ValueString()
		}
	} else if !content.IsNull() && !language.IsNull() {
		script.Content = content.ValueString()
		script.Language = language.ValueString()
	}

	if len(fileIDs) > 0 {
		script.FileIds = fileIDs
	}

	return script
}

// createScriptsFromPlan creates scripts for all platforms from the plan.
func createScriptsFromPlan(
	ctx context.Context,
	model *itAutomationTaskResourceModel,
) (*models.ItautomationScripts, diag.Diagnostics) {
	var diags diag.Diagnostics
	scripts := &models.ItautomationScripts{}

	var fileIDs []string
	if !model.AdditionalFileIds.IsNull() && !model.AdditionalFileIds.IsUnknown() {
		var err diag.Diagnostics
		fileIDs, err = setToStringSlice(ctx, model.AdditionalFileIds)

		diags.Append(err...)
		if diags.HasError() {
			return nil, diags
		}
	}

	if linux := createScriptFromPlan(
		model.LinuxScriptContent,
		model.LinuxScriptLanguage,
		model.LinuxScriptFileId,
		fileIDs,
	); linux != nil {
		scripts.Linux = linux
	}

	if mac := createScriptFromPlan(
		model.MacScriptContent,
		model.MacScriptLanguage,
		model.MacScriptFileId,
		fileIDs,
	); mac != nil {
		scripts.Mac = mac
	}

	if windows := createScriptFromPlan(
		model.WindowsScriptContent,
		model.WindowsScriptLanguage,
		model.WindowsScriptFileId,
		fileIDs,
	); windows != nil {
		scripts.Windows = windows
	}

	return scripts, diags
}

// constructUpdatePayload builds the update request payload.
func (r *itAutomationTaskResource) constructUpdatePayload(
	ctx context.Context,
	currentTask *models.ItautomationTask,
	plan *itAutomationTaskResourceModel,
) (*models.ItautomationUpdateTaskRequest, diag.Diagnostics) {
	var diags diag.Diagnostics
	apiType := convertType(plan.Type.ValueString(), "api")
	inTaskGroup := hasTaskGroupMembership(currentTask.Groups)

	body := &models.ItautomationUpdateTaskRequest{
		Name:               plan.Name.ValueString(),
		TaskType:           apiType,
		Queries:            currentTask.Queries,
		Remediations:       currentTask.Remediations,
		OutputParserConfig: currentTask.OutputParserConfig,
	}

	if !inTaskGroup {
		body.AccessType = plan.AccessType.ValueString()
	}

	// handle user id changes only if access and not in task group.
	if plan.AccessType.ValueString() == "Shared" && !plan.AssignedUserIds.IsNull() && !inTaskGroup {
		currentUserIds := currentTask.AssignedUserIds
		plannedUserIds := plan.AssignedUserIds

		usersToAdd, usersToRemove, diags := idsDiff(ctx, currentUserIds, plannedUserIds)
		if !diags.HasError() {
			if len(usersToAdd) > 0 {
				body.AddAssignedUserIds = usersToAdd
			}

			if len(usersToRemove) > 0 {
				body.RemoveAssignedUserIds = usersToRemove
			}
		}
	}

	body.Description = plan.Description.ValueString()

	if !plan.Target.IsNull() {
		body.Target = plan.Target.ValueString()
	}

	if !plan.OsQuery.IsNull() {
		body.OsQuery = plan.OsQuery.ValueString()
	} else if currentTask.OsQuery != "" {
		body.OsQuery = currentTask.OsQuery
	}

	if !plan.ScriptColumns.IsNull() {
		outputParser := &models.ItautomationOutputParserConfig{}

		var scriptColumns scriptColumnsModel
		diags.Append(plan.ScriptColumns.As(ctx, &scriptColumns, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return body, diags
		}

		if !scriptColumns.Delimiter.IsNull() {
			outputParser.Delimiter = scriptColumns.Delimiter.ValueStringPointer()
		}

		if !scriptColumns.GroupResults.IsNull() {
			outputParser.DefaultGroupBy = scriptColumns.GroupResults.ValueBoolPointer()
		}

		if !scriptColumns.Columns.IsNull() && len(scriptColumns.Columns.Elements()) > 0 {
			var columns []scriptColumnModel
			diags.Append(scriptColumns.Columns.ElementsAs(ctx, &columns, false)...)
			if diags.HasError() {
				return body, diags
			}

			apiColumns := make([]*models.ItautomationColumnInfo, 0, len(columns))
			for _, col := range columns {
				if !col.Name.IsNull() {
					apiColumns = append(apiColumns, &models.ItautomationColumnInfo{
						Name: col.Name.ValueStringPointer(),
					})
				}
			}
			outputParser.Columns = apiColumns
		}
		body.OutputParserConfig = outputParser
	}

	switch apiType {
	case "query":
		if plan.OsQuery.IsNull() {
			scripts, scriptDiags := createScriptsFromPlan(ctx, plan)
			diags.Append(scriptDiags...)
			if !diags.HasError() {
				body.Queries = scripts
			}
		}

	case "remediation":
		scripts, scriptDiags := createScriptsFromPlan(ctx, plan)
		diags.Append(scriptDiags...)
		if !diags.HasError() {
			body.Remediations = scripts
		}

		if !plan.VerificationCondition.IsNull() && len(plan.VerificationCondition.Elements()) > 0 {
			verificationConditions, verifyDiags := createVerificationConditions(
				ctx,
				plan.VerificationCondition,
			)

			diags.Append(verifyDiags...)
			if !diags.HasError() {
				body.VerificationCondition = verificationConditions
			}
		} else if len(currentTask.VerificationCondition) > 0 {
			body.VerificationCondition = currentTask.VerificationCondition
		}
	}

	return body, diags
}

func (t *itAutomationTaskResourceModel) wrap(
	ctx context.Context,
	task models.ItautomationTask,
) diag.Diagnostics {
	var diags diag.Diagnostics

	t.ID = types.StringPointerValue(task.ID)
	t.Name = types.StringPointerValue(task.Name)
	t.Type = types.StringValue(convertType(*task.TaskType, "terraform"))
	t.EffectiveAccessType = types.StringValue(task.AccessType)
	t.AccessType = types.StringValue(task.AccessType)
	t.Description = utils.PlanAwareStringValue(t.Description, task.Description)
	t.OsQuery = utils.OptionalString(&task.OsQuery)
	t.Target = utils.OptionalString(task.Target)

	if hasTaskGroupMembership(task.Groups) {
		if task.Groups[0].ID != nil {
			t.TaskGroupID = types.StringPointerValue(task.Groups[0].ID)
		} else {
			t.TaskGroupID = types.StringNull()
		}
	} else {
		t.TaskGroupID = types.StringNull()
	}

	if len(task.AssignedUserIds) > 0 {
		userIds, diag := stringSliceToSet(ctx, task.AssignedUserIds)
		diags.Append(diag...)
		if diags.HasError() {
			return diags
		}
		t.AssignedUserIds = userIds
		t.EffectiveAssignedUserIds = userIds
	} else {
		t.AssignedUserIds = types.SetNull(types.StringType)
		t.EffectiveAssignedUserIds = types.SetNull(types.StringType)
	}

	if len(task.VerificationCondition) > 0 {
		verificationConditions, vDiags := extractVerificationConditions(ctx, task.VerificationCondition)
		diags.Append(vDiags...)
		if !diags.HasError() {
			t.VerificationCondition = verificationConditions
		}
	} else {
		t.VerificationCondition = types.ListNull(types.ObjectType{AttrTypes: verificationConditionAttrTypes()})
	}

	if task.OutputParserConfig != nil {
		scriptColumns := scriptColumnsModel{}
		if task.OutputParserConfig.Delimiter != nil {
			scriptColumns.Delimiter = types.StringPointerValue(task.OutputParserConfig.Delimiter)
		}

		if task.OutputParserConfig.DefaultGroupBy != nil {
			scriptColumns.GroupResults = types.BoolPointerValue(task.OutputParserConfig.DefaultGroupBy)
		}

		if len(task.OutputParserConfig.Columns) > 0 {
			columns := make([]scriptColumnModel, 0, len(task.OutputParserConfig.Columns))
			for _, col := range task.OutputParserConfig.Columns {
				if col.Name != nil {
					columns = append(columns, scriptColumnModel{Name: types.StringPointerValue(col.Name)})
				}
			}
			columnsList, listDiags := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: scriptColumnAttrTypes()}, columns)
			if !listDiags.HasError() {
				scriptColumns.Columns = columnsList
			}
		}

		scriptColumnsObject, objDiags := types.ObjectValueFrom(ctx, scriptColumnsAttrTypes(), scriptColumns)
		diags.Append(objDiags...)
		if !diags.HasError() {
			t.ScriptColumns = scriptColumnsObject
		}
	} else {
		t.ScriptColumns = types.ObjectNull(scriptColumnsAttrTypes())
	}

	scriptSources := task.Queries
	if task.Remediations != nil {
		scriptSources = task.Remediations
	}

	if scriptSources != nil {
		scriptMap := map[string]struct {
			script        *models.ItautomationScript
			contentField  *types.String
			languageField *types.String
			fileIdField   *types.String
		}{
			"linux": {
				scriptSources.Linux, &t.LinuxScriptContent,
				&t.LinuxScriptLanguage, &t.LinuxScriptFileId,
			},
			"mac": {
				scriptSources.Mac, &t.MacScriptContent,
				&t.MacScriptLanguage, &t.MacScriptFileId,
			},
			"windows": {
				scriptSources.Windows, &t.WindowsScriptContent,
				&t.WindowsScriptLanguage, &t.WindowsScriptFileId,
			},
		}

		for _, s := range scriptMap {
			if s.script == nil {
				continue
			}

			if s.script.ScriptFileID != "" {
				*s.fileIdField = types.StringValue(s.script.ScriptFileID)
			} else if s.script.Content != "" {
				*s.contentField = types.StringValue(s.script.Content)
			}

			if s.script.Language != "" {
				*s.languageField = types.StringValue(s.script.Language)
			}

			if len(s.script.FileIds) > 0 {
				fileIds, fileDiags := stringSliceToSet(ctx, s.script.FileIds)
				diags.Append(fileDiags...)
				if !diags.HasError() {
					t.AdditionalFileIds = fileIds
				}
			}
		}
	}

	if t.AdditionalFileIds.IsNull() {
		t.AdditionalFileIds = types.SetNull(types.StringType)
	}

	return diags
}

// Configure adds the provider configured client to the resource.
func (r *itAutomationTaskResource) Configure(
	ctx context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*client.CrowdStrikeAPISpecification)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf(
				"Expected *client.CrowdStrikeAPISpecification, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)

		return
	}

	r.client = client
}

// Metadata returns the resource type name.
func (r *itAutomationTaskResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_it_automation_task"
}

// Schema defines the schema for the resource.
func (r *itAutomationTaskResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			tasksDocumentationSection,
			tasksMarkdownDescription,
			tasksRequiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for the task.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the last Terraform update of the resource.",
			},
			"access_type": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Access control configuration for the task (Public, Shared). Cannot be configured when the task belongs to a task group; inherited from the group instead.",
				Validators: []validator.String{
					stringvalidator.OneOf("Public", "Shared"),
				},
			},
			"assigned_user_ids": schema.SetAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "Assigned user IDs of the task, when access_type is Shared. Required when access_type is 'Shared' and the task is not part of a task group.",
				Validators: []validator.Set{
					setvalidator.NoNullValues(),
					setvalidator.SizeBetween(1, 100),
					setvalidator.ValueStringsAre(
						stringvalidator.RegexMatches(
							regexp.MustCompile(`^[\da-f]{8}-(?:[\da-f]{4}-){3}[\da-f]{12}$`),
							"must be a valid UUID in format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
						),
					),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the task.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description of the task.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"os_query": schema.StringAttribute{
				Optional:    true,
				Description: "OSQuery string. This option will disable the task script options. See https://osquery.readthedocs.io/en/stable for syntax.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(8),
				},
			},
			"target": schema.StringAttribute{
				Optional:    true,
				Description: "Target of the task in FQL string syntax. See https://falconpy.io/Usage/Falcon-Query-Language.html.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(8),
				},
			},
			"type": schema.StringAttribute{
				Required:    true,
				Description: "Type of task (action, query).",
				Validators: []validator.String{
					stringvalidator.OneOf("action", "query"),
				},
			},
			"linux_script_content": schema.StringAttribute{
				Optional:    true,
				Description: "Linux script content.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(2),
				},
			},
			"linux_script_file_id": schema.StringAttribute{
				Optional:    true,
				Description: "Linux RTR Response script ID (65 characters) to be used by the task. This option disables linux_script_content.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(65, 65),
				},
			},
			"linux_script_language": schema.StringAttribute{
				Optional:    true,
				Description: "Linux script language (bash, python).",
				Validators: []validator.String{
					stringvalidator.OneOf("bash", "python"),
				},
			},
			"mac_script_content": schema.StringAttribute{
				Optional:    true,
				Description: "Mac script content.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(2),
				},
			},
			"mac_script_file_id": schema.StringAttribute{
				Optional:    true,
				Description: "Mac RTR Response script ID (65 characters) to be used by the task. This option disables mac_script_content.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(65, 65),
				},
			},
			"mac_script_language": schema.StringAttribute{
				Optional:    true,
				Description: "Mac script language (zsh, python).",
				Validators: []validator.String{
					stringvalidator.OneOf("zsh", "python"),
				},
			},
			"windows_script_content": schema.StringAttribute{
				Optional:    true,
				Description: "Windows script content.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(2),
				},
			},
			"windows_script_file_id": schema.StringAttribute{
				Optional:    true,
				Description: "Windows RTR Response script ID (65 characters) to be used by the task. This option disables windows_script_content.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(65, 65),
				},
			},
			"windows_script_language": schema.StringAttribute{
				Optional:    true,
				Description: "Windows script language (powershell, python).",
				Validators: []validator.String{
					stringvalidator.OneOf("powershell", "python"),
				},
			},
			"additional_file_ids": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Additional RTR Response file IDs (65 characters) to be available for the task.",
				Validators: []validator.Set{
					setvalidator.NoNullValues(),
					setvalidator.SizeBetween(1, 100),
					setvalidator.ValueStringsAre(
						stringvalidator.LengthBetween(65, 65),
					),
				},
			},
			"effective_access_type": schema.StringAttribute{
				Computed:    true,
				Description: "Effective access type for the task. May differ from configured access_type if the task is part of a group.",
			},
			"effective_assigned_user_ids": schema.SetAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Effective assigned user IDs for the task. May differ from configured assigned_user_ids if the task is part of a group.",
			},
			"task_group_id": schema.StringAttribute{
				Computed:    true,
				Description: "The ID of the task group this task belongs to, if any.",
			},
			"script_columns": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Column configuration for the script output.",
				Attributes: map[string]schema.Attribute{
					"delimiter": schema.StringAttribute{
						Required:    true,
						Description: "Delimiter character for script columns.",
					},
					"group_results": schema.BoolAttribute{
						Optional:    true,
						Description: "Whether to group results by column values.",
					},
					"columns": schema.ListNestedAttribute{
						Required:    true,
						Description: "List of column definitions",
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"name": schema.StringAttribute{
									Required:    true,
									Description: "Name of the column.",
								},
							},
						},
					},
				},
			},
			"verification_condition": schema.ListNestedAttribute{
				Optional:    true,
				Description: "Verification conditions for action tasks to determine success (only valid for action tasks).",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"operator": schema.StringAttribute{
							Required:    true,
							Description: "Logical operator for the statements (AND, OR).",
							Validators: []validator.String{
								stringvalidator.OneOf("AND", "OR"),
							},
						},
						"statements": schema.ListNestedAttribute{
							Required:    true,
							Description: "List of verification statements",
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"data_comparator": schema.StringAttribute{
										Required:    true,
										Description: "Comparison operator for verification.",
										Validators: []validator.String{
											stringvalidator.OneOf(
												"LessThan", "GreaterThan", "LessThanEquals",
												"GreaterThanEquals", "Equals", "NotEquals",
												"Contains", "NotContains", "Matches", "NotMatches",
											),
										},
									},
									"data_type": schema.StringAttribute{
										Required:    true,
										Description: "Type of data being compared.",
										Validators: []validator.String{
											stringvalidator.OneOf("StringType", "NumericType", "SemverType"),
										},
									},
									"key": schema.StringAttribute{
										Required:    true,
										Description: "Key to compare (e.g., script_output).",
									},
									"task_id": schema.StringAttribute{
										Required:    true,
										Description: "ID of the task to query for results.",
									},
									"value": schema.StringAttribute{
										Required:    true,
										Description: "Value to compare against.",
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

// ModifyPlan validates configuration when task is in a task group.
func (r *itAutomationTaskResource) ModifyPlan(
	ctx context.Context,
	req resource.ModifyPlanRequest,
	resp *resource.ModifyPlanResponse,
) {
	if req.State.Raw.IsNull() {
		return
	}

	if req.Plan.Raw.IsNull() {
		return
	}

	var plan itAutomationTaskResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state itAutomationTaskResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check if task is in a task group by checking if task_group_id is set
	if !state.TaskGroupID.IsNull() {
		var accessTypeFromConfig types.String
		diags := req.Config.GetAttribute(ctx, path.Root("access_type"), &accessTypeFromConfig)
		if !diags.HasError() && !accessTypeFromConfig.IsNull() {
			resp.Diagnostics.AddError(
				"Invalid Configuration",
				"Cannot configure access_type when task is part of a task group. "+
					"The access_type is inherited from the task group and cannot be overridden. "+
					"Remove the access_type configuration or remove the task from the task group.",
			)
			return
		}

		var assignedUserIdsFromConfig types.Set
		diags = req.Config.GetAttribute(ctx, path.Root("assigned_user_ids"), &assignedUserIdsFromConfig)
		if !diags.HasError() && !assignedUserIdsFromConfig.IsNull() {
			resp.Diagnostics.AddError(
				"Invalid Configuration",
				"Cannot configure assigned_user_ids when task is part of a task group. "+
					"The assigned_user_ids are inherited from the task group and cannot be overridden. "+
					"Remove the assigned_user_ids configuration or remove the task from the task group.",
			)
			return
		}
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *itAutomationTaskResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan itAutomationTaskResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// convert type value for api compatibility.
	apiType := convertType(plan.Type.ValueString(), "api")

	// default access_type to public if not specified.
	accessType := plan.AccessType.ValueString()
	if accessType == "" {
		accessType = AccessTypePublic
	}

	body := &models.ItautomationCreateTaskRequest{
		Name:       plan.Name.ValueStringPointer(),
		TaskType:   &apiType,
		AccessType: &accessType,
	}

	params := it_automation.ITAutomationCreateTaskParams{
		Context: ctx,
		Body:    body,
	}

	if !plan.Description.IsNull() {
		body.Description = plan.Description.ValueString()
	}

	if !plan.AssignedUserIds.IsNull() && !plan.AssignedUserIds.IsUnknown() {
		assignedUserIds, diags := setToStringSlice(ctx, plan.AssignedUserIds)
		resp.Diagnostics.Append(diags...)

		if resp.Diagnostics.HasError() {
			return
		}
		body.AssignedUserIds = assignedUserIds
	}

	body.Target = plan.Target.ValueStringPointer()

	if !plan.OsQuery.IsNull() {
		body.OsQuery = plan.OsQuery.ValueString()
	}

	if !plan.ScriptColumns.IsNull() {
		outputParser := &models.ItautomationOutputParserConfig{}

		var scriptColumns scriptColumnsModel
		resp.Diagnostics.Append(plan.ScriptColumns.As(
			ctx,
			&scriptColumns,
			basetypes.ObjectAsOptions{},
		)...)

		if resp.Diagnostics.HasError() {
			return
		}

		if !scriptColumns.Delimiter.IsNull() {
			outputParser.Delimiter = scriptColumns.Delimiter.ValueStringPointer()
		}

		if !scriptColumns.GroupResults.IsNull() {
			outputParser.DefaultGroupBy = scriptColumns.GroupResults.ValueBoolPointer()
		}

		if !scriptColumns.Columns.IsNull() && len(scriptColumns.Columns.Elements()) > 0 {
			var columns []scriptColumnModel
			resp.Diagnostics.Append(scriptColumns.Columns.ElementsAs(ctx, &columns, false)...)
			if resp.Diagnostics.HasError() {
				return
			}

			apiColumns := make([]*models.ItautomationColumnInfo, 0, len(columns))
			for _, col := range columns {
				if !col.Name.IsNull() {
					apiColumns = append(apiColumns, &models.ItautomationColumnInfo{
						Name: col.Name.ValueStringPointer(),
					})
				}
			}
			outputParser.Columns = apiColumns
		}

		body.OutputParserConfig = outputParser
	}

	switch apiType {
	case "query":
		if plan.OsQuery.IsNull() {
			queries, diags := createScriptsFromPlan(ctx, &plan)
			resp.Diagnostics.Append(diags...)

			if resp.Diagnostics.HasError() {
				return
			}
			body.Queries = queries
		}

	case "remediation":
		remediations, diags := createScriptsFromPlan(ctx, &plan)
		resp.Diagnostics.Append(diags...)

		if resp.Diagnostics.HasError() {
			return
		}
		body.Remediations = remediations

		if !plan.VerificationCondition.IsNull() && len(plan.VerificationCondition.Elements()) > 0 {
			verificationConditions, verifyDiags := createVerificationConditions(ctx, plan.VerificationCondition)
			resp.Diagnostics.Append(verifyDiags...)

			if resp.Diagnostics.HasError() {
				return
			}
			body.VerificationCondition = verificationConditions
		}
	}

	apiResponse, err := r.client.ItAutomation.ITAutomationCreateTask(&params)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating task",
			"Could not create task, error: "+err.Error(),
		)
		tflog.Error(ctx, fmt.Sprintf("API error: %+v", err))
		return
	}

	if apiResponse == nil || apiResponse.Payload == nil || len(apiResponse.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Error creating IT automation task",
			"API returned empty response",
		)
		return
	}

	plan.ID = types.StringPointerValue(apiResponse.Payload.Resources[0].ID)
	plan.LastUpdated = utils.GenerateUpdateTimestamp()

	resp.Diagnostics.Append(plan.wrap(ctx, *apiResponse.Payload.Resources[0])...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *itAutomationTaskResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state itAutomationTaskResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	taskID := state.ID.ValueString()
	task, diags := getItAutomationTask(ctx, r.client, taskID)
	if diags.HasError() {
		// manually parse diagnostic errors.
		// helper functions return standardized diagnostics for consistency.
		// this is due to some IT Automation endpoints not returning structured/generic 404s.
		for _, d := range diags.Errors() {
			if d.Summary() == taskNotFoundErrorSummary {
				tflog.Warn(
					ctx,
					fmt.Sprintf(notFoundRemoving, fmt.Sprintf("%s %s", itAutomationTask, taskID)),
				)
				resp.State.RemoveResource(ctx)
				return
			}
		}
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, task)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *itAutomationTaskResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan itAutomationTaskResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state itAutomationTaskResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	taskID := plan.ID.ValueString()
	currentTask, diags := getItAutomationTask(ctx, r.client, taskID)

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	body, constructDiags := r.constructUpdatePayload(ctx, &currentTask, &plan)
	resp.Diagnostics.Append(constructDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := it_automation.ITAutomationUpdateTaskParams{
		Context: ctx,
		ID:      taskID,
		Body:    body,
	}

	_, err := r.client.ItAutomation.ITAutomationUpdateTask(&params)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating IT automation task",
			fmt.Sprintf("Could not update task, error: %s", err.Error()),
		)
		return
	}

	updatedTask, readDiags := getItAutomationTask(ctx, r.client, taskID)
	resp.Diagnostics.Append(readDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, updatedTask)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *itAutomationTaskResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state itAutomationTaskResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := it_automation.ITAutomationDeleteTaskParams{
		Context: ctx,
		Ids:     []string{state.ID.ValueString()},
	}

	ok, err := r.client.ItAutomation.ITAutomationDeleteTask(&params)
	if ok != nil {
		tflog.Info(
			ctx,
			fmt.Sprintf(
				"Successfully deleted it automation task %s",
				state.ID.ValueString(),
			),
		)
		return
	}

	if err != nil {
		if isNotFoundError(err) {
			return
		}

		resp.Diagnostics.AddError(
			"Error deleting IT automation task",
			fmt.Sprintf(
				"Could not delete task ID %s, error: %s",
				state.ID.ValueString(),
				err.Error(),
			),
		)
		return
	}
}

// ImportState imports the resource.
func (r *itAutomationTaskResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ConfigValidators provides declarative validation for the resource configuration.
func (r *itAutomationTaskResource) ConfigValidators(ctx context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		resourcevalidator.Conflicting(
			path.MatchRoot("linux_script_content"),
			path.MatchRoot("linux_script_file_id"),
		),
		resourcevalidator.Conflicting(
			path.MatchRoot("mac_script_content"),
			path.MatchRoot("mac_script_file_id"),
		),
		resourcevalidator.Conflicting(
			path.MatchRoot("windows_script_content"),
			path.MatchRoot("windows_script_file_id"),
		),
	}
}

// ValidateConfig validates the resource configuration.
//
//nolint:gocyclo
func (r *itAutomationTaskResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config itAutomationTaskResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.AccessType.IsUnknown() {
		return
	}

	accessType := config.AccessType.ValueString()
	if accessType == "" {
		accessType = AccessTypePublic
	}

	if accessType == AccessTypeShared && utils.IsNull(config.AssignedUserIds) {
		resp.Diagnostics.AddAttributeError(path.Root("access_type"),
			"Missing required argument",
			"When access_type is Shared, assigned_user_ids is required")
		return
	}

	if accessType != AccessTypeShared && utils.IsKnown(config.AssignedUserIds) {
		resp.Diagnostics.AddAttributeError(path.Root("assigned_user_ids"),
			"Invalid argument",
			"assigned_user_ids can only be used when access_type is Shared")
		return
	}

	platformScripts := map[string][3]types.String{
		"linux": {
			config.LinuxScriptContent,
			config.LinuxScriptFileId,
			config.LinuxScriptLanguage,
		},
		"mac": {
			config.MacScriptContent,
			config.MacScriptFileId,
			config.MacScriptLanguage,
		},
		"windows": {
			config.WindowsScriptContent,
			config.WindowsScriptFileId,
			config.WindowsScriptLanguage,
		},
	}

	hasValue := func(field types.String) bool {
		return !field.IsNull() && field.ValueString() != ""
	}

	scriptProvided, hasUnknownFileIds := false, false

	for platform, fields := range platformScripts {
		content, fileId, language := fields[0], fields[1], fields[2]

		if fileId.IsUnknown() {
			hasUnknownFileIds = true
		}

		if hasValue(content) || hasValue(fileId) {
			scriptProvided = true
		}

		if hasValue(content) && hasValue(fileId) {
			resp.Diagnostics.AddAttributeError(path.Root(platform+"_script_content"),
				"Invalid argument",
				fmt.Sprintf("The field %s_script_content cannot be used with %s_script_file_id",
					platform, platform))
		}

		if hasValue(content) && !hasValue(language) {
			resp.Diagnostics.AddAttributeError(path.Root(platform+"_script_content"),
				"Missing required argument",
				fmt.Sprintf("The field %s_script_content requires %s_script_language",
					platform, platform))
		}

		if hasValue(fileId) && !hasValue(language) {
			resp.Diagnostics.AddAttributeError(path.Root(platform+"_script_file_id"),
				"Missing required argument",
				fmt.Sprintf("The field %s_script_file_id requires %s_script_language",
					platform, platform))
		}

		if hasValue(config.OsQuery) {
			for _, field := range []struct{ name, suffix string }{
				{platform + "_script_content", "cannot be used with os_query"},
				{platform + "_script_file_id", "cannot be used with os_query"},
				{platform + "_script_language", "cannot be used with os_query"},
			} {
				if (field.name == platform+"_script_content" && hasValue(content)) ||
					(field.name == platform+"_script_file_id" && hasValue(fileId)) ||
					(field.name == platform+"_script_language" && hasValue(language)) {
					resp.Diagnostics.AddAttributeError(path.Root(field.name),
						"Invalid argument", field.name+" "+field.suffix)
				}
			}
		}

		if config.Type.ValueString() == "query" && hasValue(fileId) {
			resp.Diagnostics.AddAttributeError(path.Root(platform+"_script_file_id"),
				"Invalid argument",
				platform+"_script_file_id cannot be used with query tasks")
		}
	}

	if !hasValue(config.OsQuery) &&
		!scriptProvided &&
		!hasUnknownFileIds &&
		config.Type.ValueString() != "" {
		resp.Diagnostics.AddError("Missing field",
			"You must provide one of the script_content or script_file_id fields")
	}

	if hasValue(config.OsQuery) && !config.ScriptColumns.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("script_columns"),
			"Invalid argument", "script_columns cannot be used with os_query")
	}

	switch config.Type.ValueString() {
	case TaskTypeQuery:
		if !config.AdditionalFileIds.IsNull() {
			resp.Diagnostics.AddAttributeError(path.Root("additional_file_ids"),
				"Invalid argument", "additional_file_ids cannot be used with query tasks")
		}

		if !config.VerificationCondition.IsNull() &&
			len(config.VerificationCondition.Elements()) > 0 {
			resp.Diagnostics.AddAttributeError(path.Root("verification_condition"),
				"Invalid argument",
				"verification_condition can only be used with action tasks")
		}
	case TaskTypeAction:
		if hasValue(config.OsQuery) {
			resp.Diagnostics.AddAttributeError(path.Root("os_query"),
				"Invalid argument", "os_query cannot be used with action tasks")
		}

		if !config.ScriptColumns.IsNull() {
			resp.Diagnostics.AddAttributeError(path.Root("script_columns"),
				"Invalid argument", "script_columns cannot be used with action tasks")
		}

		// action tasks can only have scripts for one platform.
		scriptPlatformCount := 0
		if hasValue(config.LinuxScriptContent) || hasValue(config.LinuxScriptFileId) {
			scriptPlatformCount++
		}

		if hasValue(config.WindowsScriptContent) || hasValue(config.WindowsScriptFileId) {
			scriptPlatformCount++
		}

		if hasValue(config.MacScriptContent) || hasValue(config.MacScriptFileId) {
			scriptPlatformCount++
		}

		if scriptPlatformCount > 1 {
			resp.Diagnostics.AddError(
				"Invalid script configuration",
				"Action tasks can only have scripts for one platform. Please specify scripts for only one of: Linux, Windows, or Mac.")
		}
	}
}

func createVerificationConditions(
	ctx context.Context,
	conditionsList types.List,
) ([]*models.FalconforitapiConditionGroup, diag.Diagnostics) {
	var diags diag.Diagnostics

	// return early if no conditions are provided.
	if conditionsList.IsNull() ||
		conditionsList.IsUnknown() ||
		len(conditionsList.Elements()) == 0 {
		return nil, diags
	}

	var conditions []verificationConditionModel
	diags.Append(conditionsList.ElementsAs(ctx, &conditions, false)...)
	if diags.HasError() {
		return nil, diags
	}

	result := make([]*models.FalconforitapiConditionGroup, 0, len(conditions))
	for _, condition := range conditions {
		var statements []verificationStatementModel
		diags.Append(condition.Statements.ElementsAs(ctx, &statements, false)...)
		if diags.HasError() {
			return nil, diags
		}

		apiStatements := make([]*models.FalconforitapiConditionalExpr, 0, len(statements))
		for _, statement := range statements {
			apiStatement := &models.FalconforitapiConditionalExpr{
				DataComparator: statement.DataComparator.ValueStringPointer(),
				DataType:       statement.DataType.ValueStringPointer(),
				Key:            statement.Key.ValueStringPointer(),
				TaskID:         statement.TaskID.ValueStringPointer(),
				Value:          statement.Value.ValueStringPointer(),
			}
			apiStatements = append(apiStatements, apiStatement)
		}

		apiCondition := &models.FalconforitapiConditionGroup{
			Operator:   condition.Operator.ValueString(),
			Statements: apiStatements,
		}

		result = append(result, apiCondition)
	}

	return result, diags
}

func scriptColumnAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"name": types.StringType,
	}
}

func scriptColumnsAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"delimiter":     types.StringType,
		"group_results": types.BoolType,
		"columns":       types.ListType{ElemType: types.ObjectType{AttrTypes: scriptColumnAttrTypes()}},
	}
}

func verificationStatementAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"data_comparator": types.StringType,
		"data_type":       types.StringType,
		"key":             types.StringType,
		"task_id":         types.StringType,
		"value":           types.StringType,
	}
}

func verificationConditionAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"operator":   types.StringType,
		"statements": types.ListType{ElemType: types.ObjectType{AttrTypes: verificationStatementAttrTypes()}},
	}
}

func extractVerificationConditions(
	ctx context.Context,
	verificationConditions []*models.FalconforitapiConditionGroup,
) (types.List, diag.Diagnostics) {
	var diags diag.Diagnostics
	conditionObjType := types.ObjectType{AttrTypes: verificationConditionAttrTypes()}

	if len(verificationConditions) == 0 {
		emptyList, listDiags := types.ListValueFrom(ctx, conditionObjType, []verificationConditionModel{})
		diags.Append(listDiags...)
		return emptyList, diags
	}

	result := make([]verificationConditionModel, 0, len(verificationConditions))
	statementObjType := types.ObjectType{AttrTypes: verificationStatementAttrTypes()}

	for _, apiCondition := range verificationConditions {
		statements := make([]verificationStatementModel, 0, len(apiCondition.Statements))
		for _, apiStatement := range apiCondition.Statements {
			statements = append(statements, verificationStatementModel{
				DataComparator: types.StringPointerValue(apiStatement.DataComparator),
				DataType:       types.StringPointerValue(apiStatement.DataType),
				Key:            types.StringPointerValue(apiStatement.Key),
				TaskID:         types.StringPointerValue(apiStatement.TaskID),
				Value:          types.StringPointerValue(apiStatement.Value),
			})
		}

		statementsList, listDiags := types.ListValueFrom(ctx, statementObjType, statements)
		diags.Append(listDiags...)
		if diags.HasError() {
			return types.ListNull(conditionObjType), diags
		}

		result = append(result, verificationConditionModel{
			Operator:   types.StringValue(apiCondition.Operator),
			Statements: statementsList,
		})
	}

	resultList, listDiags := types.ListValueFrom(ctx, conditionObjType, result)
	diags.Append(listDiags...)
	return resultList, diags
}
