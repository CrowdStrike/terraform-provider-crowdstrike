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
	policiesMarkdownDescription  string         = "IT Automation policies --- This resource allows management of IT Automation policies in the CrowdStrike Falcon platform. IT Automation policies allow you to configure settings related to the module apply them to host groups."
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
	ID          types.String            `tfsdk:"id"`
	LastUpdated types.String            `tfsdk:"last_updated"`
	Name        types.String            `tfsdk:"name"`
	Description types.String            `tfsdk:"description"`
	Platform    types.String            `tfsdk:"platform"`
	IsEnabled   types.Bool              `tfsdk:"is_enabled"`
	HostGroups  types.Set               `tfsdk:"host_groups"`
	Concurrency *concurrencyConfigModel `tfsdk:"concurrency"`
	Execution   *executionConfigModel   `tfsdk:"execution"`
	Resources   *resourceConfigModel    `tfsdk:"resources"`
}

type concurrencyConfigModel struct {
	ConcurrentHostFileTransferLimit types.Int32 `tfsdk:"concurrent_host_file_transfer_limit"`
	ConcurrentHostLimit             types.Int32 `tfsdk:"concurrent_host_limit"`
	ConcurrentTaskLimit             types.Int32 `tfsdk:"concurrent_task_limit"`
}

type executionConfigModel struct {
	EnableOsQuery         types.Bool   `tfsdk:"enable_os_query"`
	EnablePythonExecution types.Bool   `tfsdk:"enable_python_execution"`
	EnableScriptExecution types.Bool   `tfsdk:"enable_script_execution"`
	ExecutionTimeout      types.Int32  `tfsdk:"execution_timeout"`
	ExecutionTimeoutUnit  types.String `tfsdk:"execution_timeout_unit"`
}

type resourceConfigModel struct {
	CPUScheduling        types.String `tfsdk:"cpu_scheduling_priority"`
	CPUThrottle          types.Int32  `tfsdk:"cpu_throttle"`
	MemoryAllocation     types.Int32  `tfsdk:"memory_allocation"`
	MemoryAllocationUnit types.String `tfsdk:"memory_allocation_unit"`
	MemoryPressureLevel  types.String `tfsdk:"memory_pressure_level"`
}

func (t *itAutomationPolicyResourceModel) wrap(
	ctx context.Context,
	policy models.ItautomationPolicy,
) diag.Diagnostics {
	var diags diag.Diagnostics

	currentDescription := t.Description
	currentHostGroups := t.HostGroups
	currentConcurrency := t.Concurrency
	currentExecution := t.Execution
	currentResources := t.Resources

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

	// process config blocks.
	t.Concurrency = nil
	t.Execution = nil
	t.Resources = nil

	if policy.Config != nil {
		c := policy.Config.Concurrency
		if c != nil {
			t.Concurrency = &concurrencyConfigModel{
				ConcurrentHostFileTransferLimit: types.Int32Value(c.ConcurrentHostFileTransferLimit),
				ConcurrentHostLimit:             types.Int32Value(c.ConcurrentHostLimit),
				ConcurrentTaskLimit:             types.Int32Value(c.ConcurrentTaskLimit),
			}
		} else if currentConcurrency != nil {
			t.Concurrency = currentConcurrency
		}

		e := policy.Config.Execution
		if e != nil {
			t.Execution = &executionConfigModel{
				EnableOsQuery:         types.BoolValue(e.EnableOsQuery != nil && *e.EnableOsQuery),
				EnablePythonExecution: types.BoolValue(e.EnablePythonExecution != nil && *e.EnablePythonExecution),
				EnableScriptExecution: types.BoolValue(e.EnableScriptExecution != nil && *e.EnableScriptExecution),
				ExecutionTimeout:      types.Int32Value(e.ExecutionTimeout),
			}

			if e.ExecutionTimeoutUnit != "" {
				t.Execution.ExecutionTimeoutUnit = types.StringValue(e.ExecutionTimeoutUnit)
			}
		} else if currentExecution != nil {
			t.Execution = currentExecution
		}

		r := policy.Config.Resources
		if r != nil {
			t.Resources = &resourceConfigModel{}
			isMac := *policy.Target == "Mac"

			if isMac {
				// mac only supports cpu_scheduling_priority and memory_pressure_level.
				if r.CPUScheduling != "" {
					t.Resources.CPUScheduling = types.StringValue(r.CPUScheduling)
				}
				if r.MemoryPressureLevel != "" {
					t.Resources.MemoryPressureLevel = types.StringValue(r.MemoryPressureLevel)
				}
			} else {
				// windows and linux support cpu_throttle, memory_allocation, and memory_allocation_unit.
				if r.CPUThrottle != 0 {
					t.Resources.CPUThrottle = types.Int32Value(r.CPUThrottle)
				}
				if r.MemoryAllocation != 0 {
					t.Resources.MemoryAllocation = types.Int32Value(r.MemoryAllocation)
				}
				if r.MemoryAllocationUnit != "" {
					t.Resources.MemoryAllocationUnit = types.StringValue(r.MemoryAllocationUnit)
				}
			}
		} else if currentResources != nil {
			t.Resources = currentResources
		}
	}

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
		},
		Blocks: map[string]schema.Block{
			"concurrency": schema.SingleNestedBlock{
				Description: "Configuration for concurrency settings.",
				Attributes: map[string]schema.Attribute{
					"concurrent_host_file_transfer_limit": schema.Int32Attribute{
						Required:    true,
						Description: "Maximum number of hosts that can transfer files simultaneously (1-5000).",
						Validators: []validator.Int32{
							int32validator.Between(1, 5000),
						},
					},
					"concurrent_host_limit": schema.Int32Attribute{
						Required:    true,
						Description: "Maximum number of hosts that can run operations simultaneously (1-100000).",
						Validators: []validator.Int32{
							int32validator.Between(1, 100000),
						},
					},
					"concurrent_task_limit": schema.Int32Attribute{
						Required:    true,
						Description: "Maximum number of tasks that can run in parallel (1-5).",
						Validators: []validator.Int32{
							int32validator.Between(1, 5),
						},
					},
				},
			},
			"execution": schema.SingleNestedBlock{
				Description: "Configuration for execution settings.",
				Attributes: map[string]schema.Attribute{
					"enable_os_query": schema.BoolAttribute{
						Required:    true,
						Description: "Whether OSQuery functionality is enabled.",
					},
					"enable_python_execution": schema.BoolAttribute{
						Required:    true,
						Description: "Whether Python script execution is enabled.",
					},
					"enable_script_execution": schema.BoolAttribute{
						Required:    true,
						Description: "Whether script execution is enabled.",
					},
					"execution_timeout": schema.Int32Attribute{
						Required:    true,
						Description: "Maximum time a script can run before timing out.",
					},
					"execution_timeout_unit": schema.StringAttribute{
						Required:    true,
						Description: "Unit of time for execution timeout.",
						Validators: []validator.String{
							stringvalidator.OneOf("Minutes", "Hours"),
						},
					},
				},
			},
			"resources": schema.SingleNestedBlock{
				Description: "Configuration for resource allocation settings.",
				Attributes: map[string]schema.Attribute{
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
			},
		},
	}
}

// createPolicyConfigFromModel creates a policy configuration from the resource model.
func createPolicyConfigFromModel(
	plan *itAutomationPolicyResourceModel,
) *models.ItautomationPolicyConfig {
	config := &models.ItautomationPolicyConfig{}

	if plan.Concurrency != nil {
		config.Concurrency = &models.ItautomationConcurrencyConfig{}
		cc := plan.Concurrency

		if !cc.ConcurrentHostFileTransferLimit.IsNull() {
			config.Concurrency.ConcurrentHostFileTransferLimit = cc.ConcurrentHostFileTransferLimit.ValueInt32()
		}

		if !cc.ConcurrentHostLimit.IsNull() {
			config.Concurrency.ConcurrentHostLimit = cc.ConcurrentHostLimit.ValueInt32()
		}

		if !cc.ConcurrentTaskLimit.IsNull() {
			config.Concurrency.ConcurrentTaskLimit = cc.ConcurrentTaskLimit.ValueInt32()
		}
	}

	if plan.Execution != nil {
		config.Execution = &models.ItautomationExecutionConfig{}
		ec := plan.Execution

		setBoolPointer(ec.EnableOsQuery, &config.Execution.EnableOsQuery)
		setBoolPointer(ec.EnablePythonExecution, &config.Execution.EnablePythonExecution)
		setBoolPointer(ec.EnableScriptExecution, &config.Execution.EnableScriptExecution)

		if !ec.ExecutionTimeout.IsNull() {
			config.Execution.ExecutionTimeout = ec.ExecutionTimeout.ValueInt32()
		}

		if !ec.ExecutionTimeoutUnit.IsNull() {
			config.Execution.ExecutionTimeoutUnit = ec.ExecutionTimeoutUnit.ValueString()
		}
	}

	if plan.Resources != nil {
		config.Resources = &models.ItautomationResourceConfig{}
		rc := plan.Resources

		if !rc.CPUScheduling.IsNull() {
			config.Resources.CPUScheduling = rc.CPUScheduling.ValueString()
		}

		if !rc.CPUThrottle.IsNull() {
			config.Resources.CPUThrottle = rc.CPUThrottle.ValueInt32()
		}

		if !rc.MemoryAllocation.IsNull() {
			config.Resources.MemoryAllocation = rc.MemoryAllocation.ValueInt32()
		}

		if !rc.MemoryAllocationUnit.IsNull() {
			config.Resources.MemoryAllocationUnit = rc.MemoryAllocationUnit.ValueString()
		}

		if !rc.MemoryPressureLevel.IsNull() {
			config.Resources.MemoryPressureLevel = rc.MemoryPressureLevel.ValueString()
		}
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
					fmt.Sprintf("IT automation policy %s not found during disable, removing from state", policyID),
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
				fmt.Sprintf(notFoundRemoving, fmt.Sprintf("IT automation policy %s", policyID)),
				map[string]any{"error": err.Error()},
			)
			resp.State.RemoveResource(ctx)
			return
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

	if config.Concurrency == nil {
		resp.Diagnostics.AddAttributeError(
			path.Root("concurrency"),
			"Missing required block",
			"concurrency block is required for all IT automation policies",
		)
	}

	if config.Execution == nil {
		resp.Diagnostics.AddAttributeError(
			path.Root("execution"),
			"Missing required block",
			"execution block is required for all IT automation policies",
		)
	}

	if config.Resources != nil {
		res := config.Resources

		if isMac {
			// require mac-specific resource fields.
			if res.CPUScheduling.IsNull() {
				resp.Diagnostics.AddAttributeError(
					path.Root("resources").AtName("cpu_scheduling_priority"),
					"Missing required field",
					"cpu_scheduling_priority is required for Mac policies",
				)
			}

			if res.MemoryPressureLevel.IsNull() {
				resp.Diagnostics.AddAttributeError(
					path.Root("resources").AtName("memory_pressure_level"),
					"Missing required field",
					"memory_pressure_level is required for Mac policies",
				)
			}

			// forbid windows and linux specific fields on mac.
			if !res.CPUThrottle.IsNull() {
				resp.Diagnostics.AddAttributeError(
					path.Root("resources").AtName("cpu_throttle"),
					"Invalid argument",
					"cpu_throttle cannot be used with Mac policies",
				)
			}

			if !res.MemoryAllocation.IsNull() {
				resp.Diagnostics.AddAttributeError(
					path.Root("resources").AtName("memory_allocation"),
					"Invalid argument",
					"memory_allocation cannot be used with Mac policies",
				)
			}

			if !res.MemoryAllocationUnit.IsNull() {
				resp.Diagnostics.AddAttributeError(
					path.Root("resources").AtName("memory_allocation_unit"),
					"Invalid argument",
					"memory_allocation_unit cannot be used with Mac policies",
				)
			}
		} else {
			// require windows and linux resource fields.
			if res.CPUThrottle.IsNull() {
				resp.Diagnostics.AddAttributeError(
					path.Root("resources").AtName("cpu_throttle"),
					"Missing required field",
					fmt.Sprintf("cpu_throttle is required for %s policies", config.Platform.ValueString()),
				)
			}

			if res.MemoryAllocation.IsNull() {
				resp.Diagnostics.AddAttributeError(
					path.Root("resources").AtName("memory_allocation"),
					"Missing required field",
					fmt.Sprintf("memory_allocation is required for %s policies", config.Platform.ValueString()),
				)
			}

			if res.MemoryAllocationUnit.IsNull() {
				resp.Diagnostics.AddAttributeError(
					path.Root("resources").AtName("memory_allocation_unit"),
					"Missing required field",
					fmt.Sprintf("memory_allocation_unit is required for %s policies", config.Platform.ValueString()),
				)
			}

			// forbid mac fields on windows and linux.
			if !res.CPUScheduling.IsNull() {
				resp.Diagnostics.AddAttributeError(
					path.Root("resources").AtName("cpu_scheduling_priority"),
					"Invalid argument",
					fmt.Sprintf(
						"cpu_scheduling_priority cannot be used with %s policies",
						config.Platform.ValueString(),
					),
				)
			}

			if !res.MemoryPressureLevel.IsNull() {
				resp.Diagnostics.AddAttributeError(
					path.Root("resources").AtName("memory_pressure_level"),
					"Invalid argument",
					fmt.Sprintf(
						"memory_pressure_level cannot be used with %s policies",
						config.Platform.ValueString(),
					),
				)
			}
		}
	} else {
		// require resources block for all platforms.
		resp.Diagnostics.AddAttributeError(
			path.Root("resources"),
			"Missing required block",
			"resources block is required for all IT automation policies",
		)
	}

}
