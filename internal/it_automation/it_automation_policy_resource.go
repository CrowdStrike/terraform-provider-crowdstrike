package itautomation

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/it_automation"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/int32validator"
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
	_ resource.Resource                   = &itAutomationPolicyResource{}
	_ resource.ResourceWithConfigure      = &itAutomationPolicyResource{}
	_ resource.ResourceWithImportState    = &itAutomationPolicyResource{}
	_ resource.ResourceWithValidateConfig = &itAutomationPolicyResource{}
)

var (
	policiesDocumentationSection string         = "IT Automation"
	policiesMarkdownDescription  string         = "IT Automation policies --- This resource allows management of IT Automation policies in the CrowdStrike Falcon platform. IT Automation policies allow you to configure settings related to the module and apply them to host groups."
	policiesRequiredScopes       []scopes.Scope = itAutomationScopes
)

// NewItAutomationPolicyResource is a helper function to simplify the provider implementation.
func NewItAutomationPolicyResource() resource.Resource {
	return &itAutomationPolicyResource{}
}

// itAutomationPolicyResource is the resource implementation.
type itAutomationPolicyResource struct {
	client *client.CrowdStrikeAPISpecification
}

// itAutomationPolicyResourceModel is the resource model.
type itAutomationPolicyResourceModel struct {
	ID                              types.String `tfsdk:"id"`
	Name                            types.String `tfsdk:"name"`
	Description                     types.String `tfsdk:"description"`
	ConcurrentHostFileTransferLimit types.Int32  `tfsdk:"concurrent_host_file_transfer_limit"`
	ConcurrentHostLimit             types.Int32  `tfsdk:"concurrent_host_limit"`
	ConcurrentTaskLimit             types.Int32  `tfsdk:"concurrent_task_limit"`
	CPUSchedulingPriority           types.String `tfsdk:"cpu_scheduling_priority"`
	CPUThrottle                     types.Int32  `tfsdk:"cpu_throttle"`
	EnableOsQuery                   types.Bool   `tfsdk:"enable_os_query"`
	EnablePythonExecution           types.Bool   `tfsdk:"enable_python_execution"`
	EnableScriptExecution           types.Bool   `tfsdk:"enable_script_execution"`
	ExecutionTimeout                types.Int32  `tfsdk:"execution_timeout"`
	ExecutionTimeoutUnit            types.String `tfsdk:"execution_timeout_unit"`
	HostGroups                      types.Set    `tfsdk:"host_groups"`
	IsEnabled                       types.Bool   `tfsdk:"is_enabled"`
	LastUpdated                     types.String `tfsdk:"last_updated"`
	MemoryAllocation                types.Int32  `tfsdk:"memory_allocation"`
	MemoryAllocationUnit            types.String `tfsdk:"memory_allocation_unit"`
	MemoryPressureLevel             types.String `tfsdk:"memory_pressure_level"`
	Platform                        types.String `tfsdk:"platform"`
}

func (t *itAutomationPolicyResourceModel) wrap(
	ctx context.Context,
	policy models.ItautomationPolicy,
) diag.Diagnostics {
	var diags diag.Diagnostics

	currentDescription := t.Description
	currentHostGroups := t.HostGroups

	t.ID = types.StringValue(*policy.ID)
	t.Name = types.StringValue(*policy.Name)
	t.IsEnabled = types.BoolValue(policy.IsEnabled)

	if policy.Description != nil {
		t.Description = types.StringValue(*policy.Description)
	} else if !currentDescription.IsNull() {
		t.Description = currentDescription
	}

	if policy.Target != nil {
		t.Platform = types.StringValue(*policy.Target)
	}

	if policy.HostGroups != nil {
		hostGroups, diag := stringSliceToSet(ctx, policy.HostGroups)
		diags.Append(diag...)
		if !diags.HasError() {
			t.HostGroups = hostGroups
		}
	} else if !currentHostGroups.IsNull() {
		t.HostGroups = currentHostGroups
	}

	if policy.Config != nil {
		c := policy.Config.Concurrency
		if c != nil {
			t.ConcurrentHostFileTransferLimit = types.Int32Value(c.ConcurrentHostFileTransferLimit)
			t.ConcurrentHostLimit = types.Int32Value(c.ConcurrentHostLimit)
			t.ConcurrentTaskLimit = types.Int32Value(c.ConcurrentTaskLimit)
		}

		e := policy.Config.Execution
		if e != nil {
			t.EnableOsQuery = types.BoolValue(e.EnableOsQuery != nil && *e.EnableOsQuery)
			t.EnablePythonExecution = types.BoolValue(e.EnablePythonExecution != nil && *e.EnablePythonExecution)
			t.EnableScriptExecution = types.BoolValue(e.EnableScriptExecution != nil && *e.EnableScriptExecution)
			t.ExecutionTimeout = types.Int32Value(e.ExecutionTimeout)

			if e.ExecutionTimeoutUnit != "" {
				t.ExecutionTimeoutUnit = types.StringValue(e.ExecutionTimeoutUnit)
			}
		}

		r := policy.Config.Resources
		if r != nil {
			isMac := *policy.Target == "Mac"

			if isMac {
				if r.CPUScheduling != "" {
					t.CPUSchedulingPriority = types.StringValue(r.CPUScheduling)
				}
				if r.MemoryPressureLevel != "" {
					t.MemoryPressureLevel = types.StringValue(r.MemoryPressureLevel)
				}
			} else {
				if r.CPUThrottle != 0 {
					t.CPUThrottle = types.Int32Value(r.CPUThrottle)
				}
				if r.MemoryAllocation != 0 {
					t.MemoryAllocation = types.Int32Value(r.MemoryAllocation)
				}
				if r.MemoryAllocationUnit != "" {
					t.MemoryAllocationUnit = types.StringValue(r.MemoryAllocationUnit)
				}
			}
		}
	}

	t.LastUpdated = types.StringValue(time.Now().Format(timeFormat))
	return diags
}

// Configure adds the provider configured client to the resource.
func (r *itAutomationPolicyResource) Configure(
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
				"Expected *client.CrowdStrikeAPISpecification, got: %T. %s.",
				req.ProviderData,
				"Please report this issue to the provider developers",
			),
		)

		return
	}

	r.client = client
}

// Metadata returns the resource type name.
func (r *itAutomationPolicyResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_it_automation_policy"
}

// Schema defines the schema for the resource.
func (r *itAutomationPolicyResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			policiesDocumentationSection,
			policiesMarkdownDescription,
			policiesRequiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for the policy.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the last Terraform update of the resource.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the policy.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description of the policy.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"platform": schema.StringAttribute{
				Required:    true,
				Description: "Platform for the policy (Windows, Linux, Mac).",
				Validators: []validator.String{
					stringvalidator.OneOf("Windows", "Linux", "Mac"),
				},
			},
			"is_enabled": schema.BoolAttribute{
				Required:    true,
				Description: "Whether the policy is enabled or disabled.",
			},
			"host_groups": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "List of host group IDs associated with this policy.",
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, 100),
					setvalidator.NoNullValues(),
					setvalidator.ValueStringsAre(
						stringvalidator.RegexMatches(
							regexp.MustCompile(`^[\da-f]{32}$`),
							"must be a valid 32-character hex string",
						),
					),
				},
			},
			"concurrent_host_file_transfer_limit": schema.Int32Attribute{
				Optional:    true,
				Description: "Maximum number of hosts that can transfer files simultaneously (1-5000).",
				Validators: []validator.Int32{
					int32validator.Between(1, 5000),
				},
			},
			"concurrent_host_limit": schema.Int32Attribute{
				Optional:    true,
				Description: "Maximum number of hosts that can run operations simultaneously (1-100000).",
				Validators: []validator.Int32{
					int32validator.Between(1, 100000),
				},
			},
			"concurrent_task_limit": schema.Int32Attribute{
				Optional:    true,
				Description: "Maximum number of tasks that can run in parallel (1-5).",
				Validators: []validator.Int32{
					int32validator.Between(1, 5),
				},
			},
			"enable_os_query": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether OSQuery functionality is enabled.",
			},
			"enable_python_execution": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether Python script execution is enabled.",
			},
			"enable_script_execution": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether script execution is enabled.",
			},
			"execution_timeout": schema.Int32Attribute{
				Optional:    true,
				Description: "Maximum time a script can run before timing out.",
			},
			"execution_timeout_unit": schema.StringAttribute{
				Optional:    true,
				Description: "Unit of time for execution timeout.",
				Validators: []validator.String{
					stringvalidator.OneOf("Minutes", "Hours"),
				},
			},
			"cpu_scheduling_priority": schema.StringAttribute{
				Optional:    true,
				Description: "Sets priority for CPU scheduling.",
				Validators: []validator.String{
					stringvalidator.OneOf("Low", "Medium", "High"),
				},
			},
			"cpu_throttle": schema.Int32Attribute{
				Optional:    true,
				Description: "CPU usage limit as a percentage (1-100).",
				Validators: []validator.Int32{
					int32validator.Between(1, 100),
				},
			},
			"memory_allocation": schema.Int32Attribute{
				Optional:    true,
				Description: "Amount of memory allocated.",
			},
			"memory_allocation_unit": schema.StringAttribute{
				Optional:    true,
				Description: "Unit for memory allocation.",
				Validators: []validator.String{
					stringvalidator.OneOf("MB", "GB"),
				},
			},
			"memory_pressure_level": schema.StringAttribute{
				Optional:    true,
				Description: "Sets memory pressure level to control system resource allocation during task execution.",
				Validators: []validator.String{
					stringvalidator.OneOf("Low", "Medium", "High"),
				},
			},
		},
	}
}

// createPolicyConfigFromModel creates a policy configuration from the resource model.
func createPolicyConfigFromModel(
	plan *itAutomationPolicyResourceModel,
) *models.ItautomationPolicyConfig {
	config := &models.ItautomationPolicyConfig{}

	config.Concurrency = &models.ItautomationConcurrencyConfig{}
	if !plan.ConcurrentHostFileTransferLimit.IsNull() {
		config.Concurrency.ConcurrentHostFileTransferLimit = plan.ConcurrentHostFileTransferLimit.ValueInt32()
	}
	if !plan.ConcurrentHostLimit.IsNull() {
		config.Concurrency.ConcurrentHostLimit = plan.ConcurrentHostLimit.ValueInt32()
	}
	if !plan.ConcurrentTaskLimit.IsNull() {
		config.Concurrency.ConcurrentTaskLimit = plan.ConcurrentTaskLimit.ValueInt32()
	}

	config.Execution = &models.ItautomationExecutionConfig{}
	setBoolPointer(plan.EnableOsQuery, &config.Execution.EnableOsQuery)
	setBoolPointer(plan.EnablePythonExecution, &config.Execution.EnablePythonExecution)
	setBoolPointer(plan.EnableScriptExecution, &config.Execution.EnableScriptExecution)

	if !plan.ExecutionTimeout.IsNull() {
		config.Execution.ExecutionTimeout = plan.ExecutionTimeout.ValueInt32()
	}
	if !plan.ExecutionTimeoutUnit.IsNull() {
		config.Execution.ExecutionTimeoutUnit = plan.ExecutionTimeoutUnit.ValueString()
	}

	config.Resources = &models.ItautomationResourceConfig{}
	if !plan.CPUSchedulingPriority.IsNull() {
		config.Resources.CPUScheduling = plan.CPUSchedulingPriority.ValueString()
	}
	if !plan.CPUThrottle.IsNull() {
		config.Resources.CPUThrottle = plan.CPUThrottle.ValueInt32()
	}
	if !plan.MemoryAllocation.IsNull() {
		config.Resources.MemoryAllocation = plan.MemoryAllocation.ValueInt32()
	}
	if !plan.MemoryAllocationUnit.IsNull() {
		config.Resources.MemoryAllocationUnit = plan.MemoryAllocationUnit.ValueString()
	}
	if !plan.MemoryPressureLevel.IsNull() {
		config.Resources.MemoryPressureLevel = plan.MemoryPressureLevel.ValueString()
	}

	return config
}

// Create creates the resource and sets the initial Terraform state.
func (r *itAutomationPolicyResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan itAutomationPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body := &models.ItautomationCreatePolicyRequest{
		Name:        plan.Name.ValueString(),
		Description: plan.Description.ValueStringPointer(),
		Platform:    plan.Platform.ValueStringPointer(),
		Config:      createPolicyConfigFromModel(&plan),
	}

	params := &it_automation.ITAutomationCreatePolicyParams{
		Context: ctx,
		Body:    body,
	}

	ok, err := r.client.ItAutomation.ITAutomationCreatePolicy(params)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating IT automation policy",
			"Could not create policy, unexpected error: "+err.Error(),
		)
		return
	}

	policy := ok.Payload.Resources[0]
	plan.ID = types.StringPointerValue(policy.ID)
	plan.LastUpdated = types.StringValue(time.Now().Format(timeFormat))

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.IsEnabled.ValueBool() {
		err := r.updatePolicyEnabledState(ctx, *policy.ID, true)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error enabling IT automation policy",
				err.Error(),
			)
			return
		}
	}

	if !plan.HostGroups.IsNull() && !plan.HostGroups.IsUnknown() {
		hostGroups, diags := setToStringSlice(ctx, plan.HostGroups)
		resp.Diagnostics.Append(diags...)
		if diags.HasError() {
			return
		}

		if len(hostGroups) > 0 {
			action := "assign"

			body := &models.ItautomationUpdatePoliciesHostGroupsRequest{
				Action:       &action,
				HostGroupIds: hostGroups,
				PolicyID:     policy.ID,
			}

			params := &it_automation.ITAutomationUpdatePolicyHostGroupsParams{
				Body: body,
			}

			_, err := r.client.ItAutomation.ITAutomationUpdatePolicyHostGroups(params)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error updating IT automation policy host groups",
					"Could not update host groups for policy ID: "+*policy.ID+", error: "+err.Error(),
				)
			}
		}
	}

	updatedPolicy, diags := getItAutomationPolicy(ctx, r.client, *policy.ID)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, *updatedPolicy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *itAutomationPolicyResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state itAutomationPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policyID := state.ID.ValueString()
	policy, diags := getItAutomationPolicy(ctx, r.client, policyID)
	resp.Diagnostics.Append(diags...)

	if resp.Diagnostics.HasError() {
		// manually parse diagnostic errors.
		// helper functions return standardized diagnostics for consistency.
		// this is due to some IT Automation endpoints not returning structured/generic 404s.
		for _, d := range resp.Diagnostics.Errors() {
			if d.Summary() == policyNotFoundErrorSummary {
				tflog.Warn(
					ctx,
					fmt.Sprintf(notFoundRemoving, fmt.Sprintf("IT Automation Policy %s", policyID)),
				)
				resp.State.RemoveResource(ctx)
				return
			}
		}
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, *policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *itAutomationPolicyResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan itAutomationPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state itAutomationPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !plan.Platform.Equal(state.Platform) {
		resp.Diagnostics.AddError(
			"Platform change not supported",
			"Changing the platform of an IT automation policy requires resource replacement. Please use terraform destroy and apply, or add 'replace_triggered_by' lifecycle rule.",
		)
		return
	}

	policyID := state.ID.ValueString()

	body := &models.ItautomationUpdatePolicyRequest{
		ID:          policyID,
		Name:        plan.Name.ValueString(),
		Description: plan.Description.ValueString(),
		Config:      createPolicyConfigFromModel(&plan),
	}

	params := &it_automation.ITAutomationUpdatePoliciesParams{
		Context: ctx,
		Body:    body,
	}

	_, err := r.client.ItAutomation.ITAutomationUpdatePolicies(params)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating IT automation policy",
			"Could not update policy ID "+policyID+", unexpected error: "+err.Error(),
		)
		return
	}

	if !plan.IsEnabled.Equal(state.IsEnabled) {
		err := r.updatePolicyEnabledState(ctx, policyID, plan.IsEnabled.ValueBool())
		if err != nil {
			resp.Diagnostics.AddError(
				"Error updating IT automation policy enabled state",
				err.Error(),
			)
			return
		}
	}

	if !plan.HostGroups.Equal(state.HostGroups) {
		if !plan.HostGroups.IsNull() && !plan.HostGroups.IsUnknown() {
			hostGroups, diags := setToStringSlice(ctx, plan.HostGroups)
			resp.Diagnostics.Append(diags...)
			if diags.HasError() {
				return
			}

			if len(hostGroups) > 0 {
				action := "assign"
				body := &models.ItautomationUpdatePoliciesHostGroupsRequest{
					Action:       &action,
					HostGroupIds: hostGroups,
					PolicyID:     &policyID,
				}

				params := &it_automation.ITAutomationUpdatePolicyHostGroupsParams{
					Context: ctx,
					Body:    body,
				}

				_, err := r.client.ItAutomation.ITAutomationUpdatePolicyHostGroups(params)
				if err != nil {
					resp.Diagnostics.AddError(
						"Error updating IT automation policy host groups",
						"Could not update host groups for policy ID: "+policyID+", error: "+err.Error(),
					)
					return
				}
			}
		}
	}

	updatedPolicy, diags := getItAutomationPolicy(ctx, r.client, policyID)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, *updatedPolicy)...)
	plan.LastUpdated = types.StringValue(time.Now().Format(timeFormat))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// updatePolicyEnabledState enables or disables a policy.
func (r *itAutomationPolicyResource) updatePolicyEnabledState(
	ctx context.Context,
	policyID string,
	enabled bool,
) error {
	action := "enabling"
	if !enabled {
		action = "disabling"
	}

	tflog.Info(
		ctx,
		fmt.Sprintf(
			"Starting %s operation for policy ID: %s",
			action,
			policyID,
		),
	)

	body := &models.ItautomationUpdatePolicyRequest{
		ID:        policyID,
		IsEnabled: &enabled,
	}

	params := &it_automation.ITAutomationUpdatePoliciesParams{
		Context: ctx,
		Body:    body,
	}

	_, err := r.client.ItAutomation.ITAutomationUpdatePolicies(params)
	if err != nil {
		return fmt.Errorf("error %s policy ID %s: %w", action, policyID, err)
	}

	tflog.Info(
		ctx,
		fmt.Sprintf(
			"Successfully %s policy %s",
			action,
			policyID,
		),
	)

	return nil
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *itAutomationPolicyResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state itAutomationPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policyID := state.ID.ValueString()

	currentPolicy, diags := getItAutomationPolicy(ctx, r.client, policyID)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if currentPolicy.IsEnabled {
		err := r.updatePolicyEnabledState(ctx, policyID, false)
		if err != nil {
			if isNotFoundError(err) {
				tflog.Warn(
					ctx,
					fmt.Sprintf("%s %s not found during disable, removing from state", itAutomationPolicy, policyID),
					map[string]any{"error": err.Error()},
				)
				resp.State.RemoveResource(ctx)
				return
			}

			resp.Diagnostics.AddError(
				"Error disabling IT automation policy before deletion",
				err.Error(),
			)
			return
		}

		verifyPolicy, diags := getItAutomationPolicy(ctx, r.client, policyID)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		if verifyPolicy.IsEnabled {
			resp.Diagnostics.AddError(
				"Policy disable verification failed",
				fmt.Sprintf(
					"Policy %s still shows IsEnabled=true after disable operation",
					policyID,
				),
			)
			return
		}
	}

	params := &it_automation.ITAutomationDeletePolicyParams{
		Context: ctx,
		Ids:     []string{policyID},
	}

	_, err := r.client.ItAutomation.ITAutomationDeletePolicy(params)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") ||
			strings.Contains(err.Error(), "404") {
			tflog.Warn(
				ctx,
				fmt.Sprintf(notFoundRemoving, fmt.Sprintf("%s %s", itAutomationPolicy, policyID)),
				map[string]any{"error": err.Error()},
			)
			resp.State.RemoveResource(ctx)
			return
		}

		/*
			workaround for api limitation where concurrent policy deletes can return errors
			even when the policy was successfully deleted by another request.
			verify the policy actually exists before treating this as a failure.
		*/
		_, verifyDiags := getItAutomationPolicy(ctx, r.client, policyID)
		if verifyDiags.HasError() {
			for _, diag := range verifyDiags {
				if diag.Summary() == policyNotFoundErrorSummary {
					resp.State.RemoveResource(ctx)
					return
				}
			}
		}

		resp.Diagnostics.AddError(
			"Error deleting IT automation policy",
			fmt.Sprintf(
				"Could not delete policy ID %s, error: %s",
				policyID,
				err.Error(),
			),
		)
		return
	}

	tflog.Info(
		ctx,
		fmt.Sprintf(
			"Successfully deleted IT automation policy %s",
			policyID,
		),
	)
}

// ImportState imports the resource.
func (r *itAutomationPolicyResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ValidateConfig validates the resource configuration.
func (r *itAutomationPolicyResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config itAutomationPolicyResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	isMac := config.Platform.ValueString() == "Mac"

	if isMac {
		if config.CPUSchedulingPriority.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("cpu_scheduling_priority"),
				"Missing required field",
				"cpu_scheduling_priority is required for Mac policies",
			)
		}

		if config.MemoryPressureLevel.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("memory_pressure_level"),
				"Missing required field",
				"memory_pressure_level is required for Mac policies",
			)
		}

		if !config.CPUThrottle.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("cpu_throttle"),
				"Invalid argument",
				"cpu_throttle cannot be used with Mac policies",
			)
		}

		if !config.MemoryAllocation.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("memory_allocation"),
				"Invalid argument",
				"memory_allocation cannot be used with Mac policies",
			)
		}

		if !config.MemoryAllocationUnit.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("memory_allocation_unit"),
				"Invalid argument",
				"memory_allocation_unit cannot be used with Mac policies",
			)
		}
	} else {
		if config.CPUThrottle.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("cpu_throttle"),
				"Missing required field",
				fmt.Sprintf("cpu_throttle is required for %s policies", config.Platform.ValueString()),
			)
		}

		if config.MemoryAllocation.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("memory_allocation"),
				"Missing required field",
				fmt.Sprintf("memory_allocation is required for %s policies", config.Platform.ValueString()),
			)
		}

		if config.MemoryAllocationUnit.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("memory_allocation_unit"),
				"Missing required field",
				fmt.Sprintf("memory_allocation_unit is required for %s policies", config.Platform.ValueString()),
			)
		}

		if !config.CPUSchedulingPriority.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("cpu_scheduling_priority"),
				"Invalid argument",
				fmt.Sprintf(
					"cpu_scheduling_priority cannot be used with %s policies",
					config.Platform.ValueString(),
				),
			)
		}

		if !config.MemoryPressureLevel.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("memory_pressure_level"),
				"Invalid argument",
				fmt.Sprintf(
					"memory_pressure_level cannot be used with %s policies",
					config.Platform.ValueString(),
				),
			)
		}
	}
}
