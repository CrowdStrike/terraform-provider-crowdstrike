package itautomation

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/it_automation"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &itAutomationTaskResource{}
	_ resource.ResourceWithConfigure      = &itAutomationTaskResource{}
	_ resource.ResourceWithImportState    = &itAutomationTaskResource{}
	_ resource.ResourceWithValidateConfig = &itAutomationTaskResource{}
)

var (
	tasksDocumentationSection string         = "IT Automation"
	tasksMarkdownDescription  string         = "IT Automation Tasks --- This resource allows management of IT Automation tasks in the CrowdStrike Falcon platform. Tasks allow you to run queries or actions across your hosts."
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
	Columns      []scriptColumnModel `tfsdk:"columns"`
	Delimiter    types.String        `tfsdk:"delimiter"`
	GroupResults types.Bool          `tfsdk:"group_results"`
}

type verificationStatementModel struct {
	DataComparator types.String `tfsdk:"data_comparator"`
	DataType       types.String `tfsdk:"data_type"`
	Key            types.String `tfsdk:"key"`
	TaskID         types.String `tfsdk:"task_id"`
	Value          types.String `tfsdk:"value"`
}

type verificationConditionModel struct {
	Operator   types.String                 `tfsdk:"operator"`
	Statements []verificationStatementModel `tfsdk:"statements"`
}

// itAutomationTaskResourceModel is the resource model.
type itAutomationTaskResourceModel struct {
	ID                       types.String         `tfsdk:"id"`
	LastUpdated              types.String         `tfsdk:"last_updated"`
	EffectiveAccessType      types.String         `tfsdk:"effective_access_type"`
	EffectiveAssignedUserIds types.Set            `tfsdk:"effective_assigned_user_ids"`
	InTaskGroup              types.Bool           `tfsdk:"in_task_group"`
	TaskGroupID              types.String         `tfsdk:"task_group_id"`
	Name                     types.String         `tfsdk:"name"`
	Description              types.String         `tfsdk:"description"`
	AccessType               types.String         `tfsdk:"access_type"`
	AssignedUserIds          types.Set            `tfsdk:"assigned_user_ids"`
	OsQuery                  types.String         `tfsdk:"os_query"`
	ScriptColumns            []scriptColumnsModel `tfsdk:"script_columns"`
	Target                   types.String         `tfsdk:"target"`
	Type                     types.String         `tfsdk:"type"`
	LinuxScriptContent       types.String         `tfsdk:"linux_script_content"`
	LinuxScriptLanguage      types.String         `tfsdk:"linux_script_language"`
	MacScriptContent         types.String         `tfsdk:"mac_script_content"`
	MacScriptLanguage        types.String         `tfsdk:"mac_script_language"`
	WindowsScriptContent     types.String         `tfsdk:"windows_script_content"`
	WindowsScriptLanguage    types.String         `tfsdk:"windows_script_language"`

	// action fields
	FileIds               types.Set                    `tfsdk:"file_ids"`
	LinuxScriptFileId     types.String                 `tfsdk:"linux_script_file_id"`
	MacScriptFileId       types.String                 `tfsdk:"mac_script_file_id"`
	WindowsScriptFileId   types.String                 `tfsdk:"windows_script_file_id"`
	VerificationCondition []verificationConditionModel `tfsdk:"verification_condition"`
}

// convertType converts the type value to the Terraform or API expected values
func convertType(typeValue string, dest string) string {
	if dest == "terraform" && typeValue == "remediation" {
		typeValue = "action"
	} else if dest == "api" && typeValue == "action" {
		typeValue = "remediation"
	}
	return typeValue
}

// createScriptFromPlan creates an API script object from Terraform plan values
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
	} else if !content.IsNull() && !language.IsNull() {
		script.Content = content.ValueString()
		script.Language = language.ValueString()
	}

	if len(fileIDs) > 0 {
		script.FileIds = fileIDs
	}

	return script
}

// createScriptsFromPlan creates scripts for all platforms from the plan
func createScriptsFromPlan(
	ctx context.Context,
	model *itAutomationTaskResourceModel,
) (*models.ItautomationScripts, diag.Diagnostics) {
	var diags diag.Diagnostics
	scripts := &models.ItautomationScripts{}

	var fileIDs []string
	if !model.FileIds.IsNull() && !model.FileIds.IsUnknown() {
		var err diag.Diagnostics
		fileIDs, err = setToStringSlice(ctx, model.FileIds)
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

// constructUpdatePayload builds the update request payload
func (r *itAutomationTaskResource) constructUpdatePayload(
	ctx context.Context,
	currentTask *models.ItautomationTask,
	plan *itAutomationTaskResourceModel,
) *models.ItautomationUpdateTaskRequest {
	apiType := convertType(plan.Type.ValueString(), "api")
	inTaskGroup := hasTaskGroupMembership(currentTask.Groups)

	body := &models.ItautomationUpdateTaskRequest{
		Name:               plan.Name.ValueString(),
		TaskType:           apiType,
		Queries:            currentTask.Queries,
		Remediations:       currentTask.Remediations,
		OutputParserConfig: currentTask.OutputParserConfig,
	}

	// set access type only if not in task group
	if !inTaskGroup {
		body.AccessType = plan.AccessType.ValueString()
	}

	// handle user id changes only if shared access and not in task group
	if plan.AccessType.ValueString() == "Shared" && !plan.AssignedUserIds.IsNull() && !inTaskGroup {
		currentUserIds := currentTask.AssignedUserIds
		plannedUserIds := plan.AssignedUserIds
		diags, usersToAdd, usersToRemove := idsDiff(ctx, currentUserIds, plannedUserIds)
		if !diags.HasError() {
			if len(usersToAdd) > 0 {
				body.AddAssignedUserIds = usersToAdd
			}
			if len(usersToRemove) > 0 {
				body.RemoveAssignedUserIds = usersToRemove
			}
		}
	}

	if !plan.Description.IsNull() {
		body.Description = plan.Description.ValueString()
	}

	if !plan.Target.IsNull() {
		body.Target = plan.Target.ValueString()
	}

	if !plan.OsQuery.IsNull() {
		body.OsQuery = plan.OsQuery.ValueString()
	} else if currentTask.OsQuery != "" {
		body.OsQuery = currentTask.OsQuery
	}

	// include script columns if provided
	if len(plan.ScriptColumns) > 0 {
		outputParser := &models.ItautomationOutputParserConfig{}
		scriptColumns := plan.ScriptColumns[0]

		if !scriptColumns.Delimiter.IsNull() {
			outputParser.Delimiter = scriptColumns.Delimiter.ValueStringPointer()
		}
		if !scriptColumns.GroupResults.IsNull() {
			outputParser.DefaultGroupBy = scriptColumns.GroupResults.ValueBoolPointer()
		}
		if len(scriptColumns.Columns) > 0 {
			columns := make([]*models.ItautomationColumnInfo, 0, len(scriptColumns.Columns))
			for _, col := range scriptColumns.Columns {
				if !col.Name.IsNull() {
					columns = append(columns, &models.ItautomationColumnInfo{
						Name: col.Name.ValueStringPointer(),
					})
				}
			}
			outputParser.Columns = columns
		}
		body.OutputParserConfig = outputParser
	}

	// handle script updates or preserve existing scripts
	switch apiType {
	case "query":
		scripts, diags := createScriptsFromPlan(ctx, plan)
		if !diags.HasError() {
			body.Queries = scripts
		}
	case "remediation":
		scripts, diags := createScriptsFromPlan(ctx, plan)
		if !diags.HasError() {
			body.Remediations = scripts
		}
		if len(plan.VerificationCondition) > 0 {
			body.VerificationCondition = createVerificationConditions(plan.VerificationCondition)
		} else if len(currentTask.VerificationCondition) > 0 {
			body.VerificationCondition = currentTask.VerificationCondition
		}
	}

	return body
}

func (t *itAutomationTaskResourceModel) wrap(
	ctx context.Context,
	task models.ItautomationTask,
) diag.Diagnostics {
	var diags diag.Diagnostics

	// preserve current state
	currentModel := *t

	t.ID = types.StringValue(*task.ID)
	t.Name = types.StringValue(*task.Name)
	t.Type = types.StringValue(convertType(*task.TaskType, "terraform"))
	t.EffectiveAccessType = types.StringValue(task.AccessType)
	t.InTaskGroup = types.BoolValue(hasTaskGroupMembership(task.Groups))

	// task group handling
	if hasTaskGroupMembership(task.Groups) {
		t.TaskGroupID = types.StringValue(*task.Groups[0].ID)
		if !currentModel.AccessType.IsNull() {
			t.AccessType = currentModel.AccessType
		} else {
			t.AccessType = types.StringValue("Public")
		}
	} else {
		t.AccessType = types.StringValue(task.AccessType)
		t.TaskGroupID = types.StringNull()
	}

	// preserve configured fields over API values
	preserveField := func(apiVal *string, current types.String, target *types.String) {
		if !current.IsNull() {
			*target = current
		} else if apiVal != nil && *apiVal != "" {
			*target = types.StringValue(*apiVal)
		}
	}
	preserveField(task.Description, currentModel.Description, &t.Description)
	preserveField(&task.OsQuery, currentModel.OsQuery, &t.OsQuery)
	preserveField(task.Target, currentModel.Target, &t.Target)

	// user ID handling
	if len(task.AssignedUserIds) > 0 {
		effectiveUserIds, diag := stringSliceToSet(ctx, task.AssignedUserIds)
		diags.Append(diag...)
		if diags.HasError() {
			return diags
		}
		t.EffectiveAssignedUserIds = effectiveUserIds

		if (!t.InTaskGroup.ValueBool() || currentModel.AssignedUserIds.IsNull()) &&
			task.AccessType == "Shared" {
			t.AssignedUserIds = effectiveUserIds
		} else if t.InTaskGroup.ValueBool() && !currentModel.AssignedUserIds.IsNull() {
			t.AssignedUserIds = currentModel.AssignedUserIds
		} else {
			t.AssignedUserIds = types.SetNull(types.StringType)
		}
	} else {
		t.EffectiveAssignedUserIds = types.SetNull(types.StringType)
		if t.InTaskGroup.ValueBool() && !currentModel.AssignedUserIds.IsNull() {
			t.AssignedUserIds = currentModel.AssignedUserIds
		} else {
			t.AssignedUserIds = types.SetNull(types.StringType)
		}
	}

	// verification conditions
	if len(task.VerificationCondition) > 0 {
		t.VerificationCondition = extractVerificationConditions(task.VerificationCondition)
	} else if len(currentModel.VerificationCondition) > 0 {
		t.VerificationCondition = currentModel.VerificationCondition
	}

	// script columns
	if task.OutputParserConfig != nil {
		scriptColumns := scriptColumnsModel{}
		if task.OutputParserConfig.Delimiter != nil {
			scriptColumns.Delimiter = types.StringValue(*task.OutputParserConfig.Delimiter)
		}
		if task.OutputParserConfig.DefaultGroupBy != nil {
			scriptColumns.GroupResults = types.BoolValue(*task.OutputParserConfig.DefaultGroupBy)
		}
		if len(task.OutputParserConfig.Columns) > 0 {
			columns := make([]scriptColumnModel, 0, len(task.OutputParserConfig.Columns))
			for _, col := range task.OutputParserConfig.Columns {
				if col.Name != nil {
					columns = append(columns, scriptColumnModel{Name: types.StringValue(*col.Name)})
				}
			}
			scriptColumns.Columns = columns
		}
		t.ScriptColumns = []scriptColumnsModel{scriptColumns}
	} else if len(currentModel.ScriptColumns) > 0 {
		t.ScriptColumns = currentModel.ScriptColumns
	}

	// process all scripts
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
					t.FileIds = fileIds
				}
			}
		}
	}

	// preserve current file ids if not set from API
	if t.FileIds.IsNull() && !currentModel.FileIds.IsNull() {
		t.FileIds = currentModel.FileIds
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
				Required:    true,
				Description: "Access control configuration for the task (Public, Shared).",
				Validators: []validator.String{
					stringvalidator.OneOf("Public", "Shared"),
				},
			},
			"assigned_user_ids": schema.SetAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "Assigned user IDs of the task, when access_type is Shared.",
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
			"file_ids": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Set of RTR Response file IDs (65 characters) to be used by the task.",
				Validators: []validator.Set{
					setvalidator.NoNullValues(),
					setvalidator.SizeBetween(1, 100),
					setvalidator.ValueStringsAre(
						stringvalidator.LengthBetween(65, 65),
					),
				},
			},
			// effective values - computed based on API response
			"effective_access_type": schema.StringAttribute{
				Computed:    true,
				Description: "Effective access type for the task. May differ from configured access_type if the task is part of a group.",
			},
			"effective_assigned_user_ids": schema.SetAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Effective assigned user IDs for the task. May differ from configured assigned_user_ids if the task is part of a group.",
			},
			"in_task_group": schema.BoolAttribute{
				Computed:    true,
				Description: "Indicates whether this task is part of a task group.",
			},
			"task_group_id": schema.StringAttribute{
				Computed:    true,
				Description: "The ID of the task group this task belongs to, if any.",
			},
		},
		Blocks: map[string]schema.Block{
			"script_columns": schema.ListNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Blocks: map[string]schema.Block{
						"columns": schema.ListNestedBlock{
							NestedObject: schema.NestedBlockObject{
								Attributes: map[string]schema.Attribute{
									"name": schema.StringAttribute{
										Required:    true,
										Description: "Name of the column.",
									},
								},
							},
						},
					},
					Attributes: map[string]schema.Attribute{
						"delimiter": schema.StringAttribute{
							Required:    true,
							Description: "Delimiter character for script columns.",
						},
						"group_results": schema.BoolAttribute{
							Optional:    true,
							Description: "Whether to group results by column values.",
						},
					},
				},
				Description: "Column configuration for the script output.",
			},
			"verification_condition": schema.ListNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Blocks: map[string]schema.Block{
						"statements": schema.ListNestedBlock{
							NestedObject: schema.NestedBlockObject{
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
					Attributes: map[string]schema.Attribute{
						"operator": schema.StringAttribute{
							Required:    true,
							Description: "Logical operator for the statements (AND, OR).",
							Validators: []validator.String{
								stringvalidator.OneOf("AND", "OR"),
							},
						},
					},
				},
				Description: "Verification conditions for action tasks to determine success (only valid for action tasks). Maps directly to the API's FalconforitapiConditionGroup model.",
			},
		},
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

	// convert type value for API compatibility
	apiType := convertType(plan.Type.ValueString(), "api")
	body := &models.ItautomationCreateTaskRequest{
		Name:       plan.Name.ValueStringPointer(),
		TaskType:   &apiType,
		AccessType: plan.AccessType.ValueStringPointer(),
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

	if !plan.Target.IsNull() {
		body.Target = plan.Target.ValueStringPointer()
	}

	if !plan.OsQuery.IsNull() {
		body.OsQuery = plan.OsQuery.ValueString()
	}

	// handle script columns
	if len(plan.ScriptColumns) > 0 {
		outputParser := &models.ItautomationOutputParserConfig{}
		scriptColumns := plan.ScriptColumns[0]

		if !scriptColumns.Delimiter.IsNull() {
			outputParser.Delimiter = scriptColumns.Delimiter.ValueStringPointer()
		}

		if !scriptColumns.GroupResults.IsNull() {
			outputParser.DefaultGroupBy = scriptColumns.GroupResults.ValueBoolPointer()
		}

		if len(scriptColumns.Columns) > 0 {
			columns := make([]*models.ItautomationColumnInfo, 0, len(scriptColumns.Columns))
			for _, col := range scriptColumns.Columns {
				if !col.Name.IsNull() {
					columns = append(columns, &models.ItautomationColumnInfo{
						Name: col.Name.ValueStringPointer(),
					})
				}
			}
			outputParser.Columns = columns
		}

		body.OutputParserConfig = outputParser
	}

	switch apiType {
	case "query":
		queries, diags := createScriptsFromPlan(ctx, &plan)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		body.Queries = queries

	case "remediation":
		remediations, diags := createScriptsFromPlan(ctx, &plan)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		body.Remediations = remediations

		if len(plan.VerificationCondition) > 0 {
			body.VerificationCondition = createVerificationConditions(
				plan.VerificationCondition,
			)
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

	plan.ID = types.StringValue(*apiResponse.Payload.Resources[0].ID)
	plan.LastUpdated = types.StringValue(time.Now().Format(timeFormat))

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
	resp.Diagnostics.Append(diags...)

	if resp.Diagnostics.HasError() {
		for _, d := range resp.Diagnostics.Errors() {
			if d.Summary() == taskNotFoundErrorSummary {
				tflog.Warn(
					ctx,
					fmt.Sprintf("IT Automation Task %s not found, removing from state", taskID),
				)
				resp.State.RemoveResource(ctx)
				return
			}
		}
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, *task)...)
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

	// if task is in a group, log warning about access_type and assigned_user_ids
	inTaskGroup := hasTaskGroupMembership(currentTask.Groups)
	if inTaskGroup {
		apiAccessType := currentTask.AccessType
		configuredAccessType := plan.AccessType.ValueString()

		if apiAccessType != configuredAccessType {
			tflog.Warn(
				ctx,
				fmt.Sprintf("Task access type overridden by group: %s", apiAccessType),
			)
		}
	}

	body := r.constructUpdatePayload(ctx, currentTask, &plan)
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

	updatedTask, diags := getItAutomationTask(ctx, r.client, taskID)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// always set effective fields from API response for task group inheritance visibility
	plan.EffectiveAccessType = types.StringValue(updatedTask.AccessType)
	plan.InTaskGroup = types.BoolValue(hasTaskGroupMembership(updatedTask.Groups))

	if len(updatedTask.AssignedUserIds) > 0 {
		effectiveUserIds, diags := stringSliceToSet(ctx, updatedTask.AssignedUserIds)
		resp.Diagnostics.Append(diags...)
		if !resp.Diagnostics.HasError() {
			plan.EffectiveAssignedUserIds = effectiveUserIds
		}
	} else {
		plan.EffectiveAssignedUserIds = types.SetNull(types.StringType)
	}

	if hasTaskGroupMembership(updatedTask.Groups) {
		plan.TaskGroupID = types.StringValue(*updatedTask.Groups[0].ID)
	} else {
		plan.TaskGroupID = types.StringNull()
	}

	resp.Diagnostics.Append(plan.wrap(ctx, *updatedTask)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.ID = types.StringValue(*updatedTask.ID)
	plan.Name = types.StringValue(*updatedTask.Name)
	plan.Type = types.StringValue(convertType(*updatedTask.TaskType, "terraform"))

	if updatedTask.Description != nil {
		plan.Description = types.StringValue(*updatedTask.Description)
	}

	plan.LastUpdated = types.StringValue(time.Now().Format(timeFormat))
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
			tflog.Warn(
				ctx,
				fmt.Sprintf("IT automation task %s not found, removing from state", state.ID.ValueString()),
				map[string]any{"error": err.Error()},
			)
			resp.State.RemoveResource(ctx)
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

// ValidateConfig validates the resource configuration.
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

	// validate access type and user ids relationship
	if config.AccessType.ValueString() == "Shared" && config.AssignedUserIds.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("access_type"),
			"Missing required argument",
			"When access_type is Shared, assigned_user_ids is required")
		return
	}
	if config.AccessType.ValueString() != "Shared" && !config.AssignedUserIds.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("assigned_user_ids"),
			"Invalid argument",
			"assigned_user_ids can only be used when access_type is Shared")
		return
	}

	// platform script validation
	platformScripts := map[string][3]types.String{
		"linux": {config.LinuxScriptContent, config.LinuxScriptFileId,
			config.LinuxScriptLanguage},
		"mac": {config.MacScriptContent, config.MacScriptFileId,
			config.MacScriptLanguage},
		"windows": {config.WindowsScriptContent, config.WindowsScriptFileId,
			config.WindowsScriptLanguage},
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

		// validate script field conflicts and requirements
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

		// validate os_query conflicts
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

		// validate task type specific conflicts
		if config.Type.ValueString() == "query" && hasValue(fileId) {
			resp.Diagnostics.AddAttributeError(path.Root(platform+"_script_file_id"),
				"Invalid argument",
				platform+"_script_file_id cannot be used with query tasks")
		}
	}

	// validate missing script requirement
	if !hasValue(config.OsQuery) && !scriptProvided && !hasUnknownFileIds &&
		config.Type.ValueString() != "" {
		resp.Diagnostics.AddError("Missing field",
			"You must provide one of the script_content or script_file_id fields")
	}

	// validate os_query and script_columns conflicts
	if hasValue(config.OsQuery) && config.ScriptColumns != nil {
		resp.Diagnostics.AddAttributeError(path.Root("script_columns"),
			"Invalid argument", "script_columns cannot be used with os_query")
	}

	// validate task type specific fields
	switch config.Type.ValueString() {
	case "query":
		if !config.FileIds.IsNull() {
			resp.Diagnostics.AddAttributeError(path.Root("file_ids"),
				"Invalid argument", "file_ids cannot be used with query tasks")
		}
		if len(config.VerificationCondition) > 0 {
			resp.Diagnostics.AddAttributeError(path.Root("verification_condition"),
				"Invalid argument",
				"verification_condition can only be used with action tasks")
		}
	case "action":
		if hasValue(config.OsQuery) {
			resp.Diagnostics.AddAttributeError(path.Root("os_query"),
				"Invalid argument", "os_query cannot be used with action tasks")
		}
		if config.ScriptColumns != nil {
			resp.Diagnostics.AddAttributeError(path.Root("script_columns"),
				"Invalid argument", "script_columns cannot be used with action tasks")
		}
	}
}

// createVerificationConditions converts Terraform verification conditions to API model.
func createVerificationConditions(
	conditions []verificationConditionModel,
) []*models.FalconforitapiConditionGroup {
	if len(conditions) == 0 {
		return nil
	}

	result := make([]*models.FalconforitapiConditionGroup, 0, len(conditions))
	for _, condition := range conditions {
		statements := make(
			[]*models.FalconforitapiConditionalExpr,
			0,
			len(condition.Statements),
		)

		for _, statement := range condition.Statements {
			apiStatement := &models.FalconforitapiConditionalExpr{
				DataComparator: statement.DataComparator.ValueStringPointer(),
				DataType:       statement.DataType.ValueStringPointer(),
				Key:            statement.Key.ValueStringPointer(),
				TaskID:         statement.TaskID.ValueStringPointer(),
				Value:          statement.Value.ValueStringPointer(),
			}
			statements = append(statements, apiStatement)
		}

		apiCondition := &models.FalconforitapiConditionGroup{
			Operator:   condition.Operator.ValueString(),
			Statements: statements,
		}

		result = append(result, apiCondition)
	}

	return result
}

// extractVerificationConditions converts API verification conditions to Terraform model.
func extractVerificationConditions(
	verificationConditions []*models.FalconforitapiConditionGroup,
) []verificationConditionModel {
	if len(verificationConditions) == 0 {
		return nil
	}

	result := make([]verificationConditionModel, 0, len(verificationConditions))

	for _, apiCondition := range verificationConditions {
		condition := verificationConditionModel{
			Operator: types.StringValue(apiCondition.Operator),
		}

		statements := make([]verificationStatementModel, 0, len(apiCondition.Statements))
		for _, apiStatement := range apiCondition.Statements {
			statements = append(statements, verificationStatementModel{
				DataComparator: types.StringValue(*apiStatement.DataComparator),
				DataType:       types.StringValue(*apiStatement.DataType),
				Key:            types.StringValue(*apiStatement.Key),
				TaskID:         types.StringValue(*apiStatement.TaskID),
				Value:          types.StringValue(*apiStatement.Value),
			})
		}

		condition.Statements = statements
		result = append(result, condition)
	}

	return result
}
