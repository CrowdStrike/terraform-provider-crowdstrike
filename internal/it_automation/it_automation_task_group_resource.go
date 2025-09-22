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
	_ resource.Resource                   = &itAutomationTaskGroupResource{}
	_ resource.ResourceWithConfigure      = &itAutomationTaskGroupResource{}
	_ resource.ResourceWithImportState    = &itAutomationTaskGroupResource{}
	_ resource.ResourceWithValidateConfig = &itAutomationTaskGroupResource{}
)

var (
	taskGroupsDocumentationSection string         = "IT Automation"
	taskGroupsMarkdownDescription  string         = "IT Automation Task groups --- This resource allows management of IT Automation task groups in the CrowdStrike Falcon platform. Task groups allow you to group tasks for RBAC and organization."
	taskGroupsRequiredScopes       []scopes.Scope = itAutomationScopes
)

// NewItAutomationTaskGroupResource is a helper function to simplify the provider implementation.
func NewItAutomationTaskGroupResource() resource.Resource {
	return &itAutomationTaskGroupResource{}
}

// itAutomationTaskGroupResource is the resource implementation.
type itAutomationTaskGroupResource struct {
	client *client.CrowdStrikeAPISpecification
}

// itAutomationTaskGroupResourceModel is the resource model.
type itAutomationTaskGroupResourceModel struct {
	ID              types.String `tfsdk:"id"`
	LastUpdated     types.String `tfsdk:"last_updated"`
	AccessType      types.String `tfsdk:"access_type"`
	AssignedUserIds types.Set    `tfsdk:"assigned_user_ids"`
	Description     types.String `tfsdk:"description"`
	Name            types.String `tfsdk:"name"`
	TaskIds         types.Set    `tfsdk:"task_ids"`
}

func (t *itAutomationTaskGroupResourceModel) wrap(
	ctx context.Context,
	group models.ItautomationTaskGroup,
) diag.Diagnostics {
	var diags diag.Diagnostics

	// preserve current state for selective restoration.
	currentDescription := t.Description

	t.ID = types.StringValue(*group.ID)
	t.AccessType = types.StringValue(*group.AccessType)
	t.Name = types.StringValue(*group.Name)

	if group.Description != nil {
		t.Description = types.StringValue(*group.Description)
	} else if !currentDescription.IsNull() {
		t.Description = currentDescription
	}

	if group.AssignedUserIds != nil {
		AssignedUserIds, diag := stringSliceToSet(ctx, group.AssignedUserIds)
		diags.Append(diag...)
		if diags.HasError() {
			return diags
		}
		t.AssignedUserIds = AssignedUserIds
	}

	if group.TaskIds != nil {
		TaskIds, diag := stringSliceToSet(ctx, group.TaskIds)
		diags.Append(diag...)
		if diags.HasError() {
			return diags
		}
		t.TaskIds = TaskIds
	}

	return diags
}

// Configure adds the provider configured client to the resource.
func (r *itAutomationTaskGroupResource) Configure(
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
func (r *itAutomationTaskGroupResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_it_automation_task_group"
}

// Schema defines the schema for the resource.
func (r *itAutomationTaskGroupResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			taskGroupsDocumentationSection,
			taskGroupsMarkdownDescription,
			taskGroupsRequiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for the task group.",
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
				Description: "Access control configuration for the task.",
				Validators: []validator.String{
					stringvalidator.OneOf("Public", "Shared"),
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
			"assigned_user_ids": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Assigned user IDs of the group, when access_type is Shared.",
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, 100),
					setvalidator.NoNullValues(),
					setvalidator.ValueStringsAre(
						stringvalidator.RegexMatches(
							regexp.MustCompile(`^[\da-f]{8}-(?:[\da-f]{4}-){3}[\da-f]{12}$`),
							"must be a valid UUID in format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
						),
					),
				},
			},
			"task_ids": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Assigned task IDs of the group.",
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, 500),
					setvalidator.NoNullValues(),
					setvalidator.ValueStringsAre(
						stringvalidator.RegexMatches(
							regexp.MustCompile(`^[\da-f]{32}$`),
							"must be a valid 32-character hex string",
						),
					),
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *itAutomationTaskGroupResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan itAutomationTaskGroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body := &models.ItautomationCreateTaskGroupRequest{
		Name:       plan.Name.ValueStringPointer(),
		AccessType: plan.AccessType.ValueStringPointer(),
	}
	params := it_automation.ITAutomationCreateTaskGroupParams{
		Context: ctx,
		Body:    body,
	}

	if !plan.AssignedUserIds.IsNull() {
		var AssignedUserIds []string
		diags := plan.AssignedUserIds.ElementsAs(ctx, &AssignedUserIds, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		body.AssignedUserIds = AssignedUserIds
	}

	if !plan.TaskIds.IsNull() {
		var TaskIds []string
		diags := plan.TaskIds.ElementsAs(ctx, &TaskIds, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		body.TaskIds = TaskIds
	}

	if !plan.Description.IsNull() {
		body.Description = plan.Description.ValueString()
	}

	apiResponse, err := r.client.ItAutomation.ITAutomationCreateTaskGroup(&params)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating task",
			"Could not create task, error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(*apiResponse.Payload.Resources[0].ID)
	plan.LastUpdated = types.StringValue(time.Now().Format(timeFormat))

	resp.Diagnostics.Append(plan.wrap(ctx, *apiResponse.Payload.Resources[0])...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *itAutomationTaskGroupResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state itAutomationTaskGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupID := state.ID.ValueString()
	taskGroup, diags := getItAutomationTaskGroup(ctx, r.client, groupID)
	resp.Diagnostics.Append(diags...)

	if resp.Diagnostics.HasError() {
		for _, d := range resp.Diagnostics.Errors() {
			if d.Summary() == taskGroupNotFoundErrorSummary {
				tflog.Warn(
					ctx,
					fmt.Sprintf(notFoundRemoving, fmt.Sprintf("IT Automation Task Group %s", groupID)),
				)
				resp.State.RemoveResource(ctx)
				return
			}
		}
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, *taskGroup)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *itAutomationTaskGroupResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan itAutomationTaskGroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state itAutomationTaskGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupID := state.ID.ValueString()
	currentGroup, diags := getItAutomationTaskGroup(ctx, r.client, groupID)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	body := &models.ItautomationUpdateTaskGroupRequest{
		Name:       plan.Name.ValueString(),
		AccessType: plan.AccessType.ValueString(),
	}
	params := it_automation.ITAutomationUpdateTaskGroupParams{
		Context: ctx,
		ID:      groupID,
		Body:    body,
	}

	if !plan.Description.IsNull() {
		body.Description = plan.Description.ValueString()
	}

	if !plan.AssignedUserIds.IsNull() {
		currentUserIds := currentGroup.AssignedUserIds
		plannedUserIds := plan.AssignedUserIds
		diags, usersToAdd, usersToRemove := idsDiff(ctx, currentUserIds, plannedUserIds)
		if !diags.HasError() {
			body.AddAssignedUserIds = usersToAdd
			body.RemoveAssignedUserIds = usersToRemove
		}
	}

	if !plan.TaskIds.IsNull() {
		currentTaskIds := currentGroup.TaskIds
		plannedTaskIds := plan.TaskIds
		diags, tasksToAdd, tasksToRemove := idsDiff(ctx, currentTaskIds, plannedTaskIds)
		if !diags.HasError() {
			body.AddTaskIds = tasksToAdd
			body.RemoveTaskIds = tasksToRemove
		}
	}

	_, err := r.client.ItAutomation.ITAutomationUpdateTaskGroup(&params)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating IT automation task group",
			"Could not update task group, error: "+err.Error(),
		)
		return
	}

	updatedTask, diags := getItAutomationTaskGroup(ctx, r.client, groupID)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, *updatedTask)...)
	plan.LastUpdated = types.StringValue(time.Now().Format(timeFormat))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *itAutomationTaskGroupResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state itAutomationTaskGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := it_automation.ITAutomationDeleteTaskGroupsParams{
		Context: ctx,
		Ids:     []string{state.ID.ValueString()},
	}

	ok, multi, err := r.client.ItAutomation.ITAutomationDeleteTaskGroups(&params)
	if ok != nil || multi != nil {
		tflog.Info(
			ctx,
			fmt.Sprintf(
				"Successfully deleted it automation task group %s",
				state.ID.ValueString(),
			),
		)
		return
	}

	if err != nil {
		if isNotFoundError(err) {
			tflog.Warn(
				ctx,
				fmt.Sprintf(notFoundRemoving, fmt.Sprintf("IT automation task group %s", state.ID.ValueString())),
				map[string]any{"error": err.Error()},
			)
			resp.State.RemoveResource(ctx)
			return
		}

		resp.Diagnostics.AddError(
			"Error deleting IT automation task group",
			fmt.Sprintf(
				"Could not delete task group ID %s, error: %s",
				state.ID.ValueString(),
				err.Error(),
			),
		)
		return
	}
}

// ImportState imports the resource.
func (r *itAutomationTaskGroupResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ValidateConfig validates the resource configuration.
func (r *itAutomationTaskGroupResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config itAutomationTaskGroupResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	AccessType := config.AccessType.ValueString()
	AssignedUserIdsProvided := !config.AssignedUserIds.IsNull() &&
		!config.AssignedUserIds.IsUnknown()
	TaskIdsProvided := !config.TaskIds.IsNull() &&
		!config.TaskIds.IsUnknown()

	if TaskIdsProvided {
		var taskIds []types.String
		diags := config.TaskIds.ElementsAs(ctx, &taskIds, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	if AccessType == "Shared" {
		if AssignedUserIdsProvided {
			var AssignedUserIds []types.String
			diags := config.AssignedUserIds.ElementsAs(ctx, &AssignedUserIds, false)
			resp.Diagnostics.Append(diags...)
			if resp.Diagnostics.HasError() {
				return
			}
		} else {
			resp.Diagnostics.AddAttributeError(
				path.Root("assigned_user_ids"),
				"Missing required field",
				"The argument assigned_user_ids is required when access_type is Shared",
			)
		}
	} else if AssignedUserIdsProvided {
		resp.Diagnostics.AddAttributeError(
			path.Root("assigned_user_ids"),
			"Invalid field",
			"The argument assigned_user_ids can only be used when access_type is Shared",
		)
	}
}
