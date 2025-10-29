package itautomation

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/it_automation"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/int32validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &itAutomationDefaultPolicyResource{}
	_ resource.ResourceWithConfigure      = &itAutomationDefaultPolicyResource{}
	_ resource.ResourceWithImportState    = &itAutomationDefaultPolicyResource{}
	_ resource.ResourceWithValidateConfig = &itAutomationDefaultPolicyResource{}
)

var (
	defaultPoliciesDocumentationSection string         = "IT Automation"
	defaultPoliciesMarkdownDescription  string         = "IT Automation default policies --- This resource allows management of default IT Automation policy configuration settings in the CrowdStrike Falcon platform."
	defaultPoliciesRequiredScopes       []scopes.Scope = itAutomationScopes
)

// NewItAutomationDefaultPolicyResource is a helper function to simplify the provider implementation.
func NewItAutomationDefaultPolicyResource() resource.Resource {
	return &itAutomationDefaultPolicyResource{}
}

// itAutomationDefaultPolicyResource is the resource implementation.
type itAutomationDefaultPolicyResource struct {
	client *client.CrowdStrikeAPISpecification
}

// itAutomationDefaultPolicyResourceModel is the resource model.
type itAutomationDefaultPolicyResourceModel struct {
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
	Enabled                         types.Bool   `tfsdk:"enabled"`
	LastUpdated                     types.String `tfsdk:"last_updated"`
	MemoryAllocation                types.Int32  `tfsdk:"memory_allocation"`
	MemoryAllocationUnit            types.String `tfsdk:"memory_allocation_unit"`
	MemoryPressureLevel             types.String `tfsdk:"memory_pressure_level"`
	PlatformName                    types.String `tfsdk:"platform_name"`
}

func (t *itAutomationDefaultPolicyResourceModel) wrap(
	policy models.ItautomationPolicy,
) {
	t.ID = types.StringPointerValue(policy.ID)
	t.Name = types.StringPointerValue(policy.Name)
	t.Enabled = types.BoolValue(policy.IsEnabled)
	t.Description = types.StringPointerValue(policy.Description)
	t.PlatformName = types.StringPointerValue(policy.Target)

	t.wrapConcurrency(policy.Config)
	t.wrapExecution(policy.Config)
	t.wrapResources(policy.Config, policy.Target)
}

func (t *itAutomationDefaultPolicyResourceModel) wrapConcurrency(config *models.ItautomationPolicyConfig) {
	if config == nil || config.Concurrency == nil {
		t.ConcurrentHostFileTransferLimit = types.Int32Null()
		t.ConcurrentHostLimit = types.Int32Null()
		t.ConcurrentTaskLimit = types.Int32Null()
		return
	}

	c := config.Concurrency
	t.ConcurrentHostFileTransferLimit = types.Int32Value(c.ConcurrentHostFileTransferLimit)
	t.ConcurrentHostLimit = types.Int32Value(c.ConcurrentHostLimit)
	t.ConcurrentTaskLimit = types.Int32Value(c.ConcurrentTaskLimit)
}

func (t *itAutomationDefaultPolicyResourceModel) wrapExecution(config *models.ItautomationPolicyConfig) {
	if config == nil || config.Execution == nil {
		t.EnableOsQuery = types.BoolNull()
		t.EnablePythonExecution = types.BoolNull()
		t.EnableScriptExecution = types.BoolNull()
		t.ExecutionTimeout = types.Int32Null()
		t.ExecutionTimeoutUnit = types.StringNull()
		return
	}

	e := config.Execution
	t.EnableOsQuery = types.BoolPointerValue(e.EnableOsQuery)
	t.EnablePythonExecution = types.BoolPointerValue(e.EnablePythonExecution)
	t.EnableScriptExecution = types.BoolPointerValue(e.EnableScriptExecution)
	t.ExecutionTimeout = types.Int32Value(e.ExecutionTimeout)
	t.ExecutionTimeoutUnit = types.StringValue(e.ExecutionTimeoutUnit)
}

func (t *itAutomationDefaultPolicyResourceModel) wrapResources(config *models.ItautomationPolicyConfig, target *string) {
	t.CPUSchedulingPriority = types.StringNull()
	t.MemoryPressureLevel = types.StringNull()
	t.CPUThrottle = types.Int32Null()
	t.MemoryAllocation = types.Int32Null()
	t.MemoryAllocationUnit = types.StringNull()

	if config == nil || config.Resources == nil {
		return
	}

	r := config.Resources

	if target != nil && *target == "Mac" {
		t.CPUSchedulingPriority = types.StringValue(r.CPUScheduling)
		t.MemoryPressureLevel = types.StringValue(r.MemoryPressureLevel)
	} else {
		t.CPUThrottle = types.Int32Value(r.CPUThrottle)
		t.MemoryAllocation = types.Int32Value(r.MemoryAllocation)
		t.MemoryAllocationUnit = types.StringValue(r.MemoryAllocationUnit)
	}
}

// getDefaultPolicyByPlatform finds the default policy for a given platform.
func (r *itAutomationDefaultPolicyResource) getDefaultPolicyByPlatform(
	ctx context.Context,
	platform string,
) (*models.ItautomationPolicy, diag.Diagnostics) {
	var diags diag.Diagnostics

	policies, _, policyDiags := getItAutomationPolicies(ctx, r.client, platform)
	diags.Append(policyDiags...)
	if diags.HasError() {
		return nil, diags
	}

	for _, policy := range policies {
		if policy != nil && policy.Name != nil && isDefaultPolicy(*policy.Name) {
			return policy, diags
		}
	}

	diags.AddError(
		"Default policy not found",
		fmt.Sprintf("No default policy found for platform %s", platform),
	)
	return nil, diags
}

// Configure adds the provider configured client to the resource.
func (r *itAutomationDefaultPolicyResource) Configure(
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
func (r *itAutomationDefaultPolicyResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_it_automation_default_policy"
}

// Schema defines the schema for the resource.
func (r *itAutomationDefaultPolicyResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			defaultPoliciesDocumentationSection,
			defaultPoliciesMarkdownDescription,
			defaultPoliciesRequiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for the default policy.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the last Terraform update of the resource.",
			},
			"platform_name": schema.StringAttribute{
				Required:    true,
				Description: "Platform for the default policy (Windows, Linux, Mac).",
				Validators: []validator.String{
					stringvalidator.OneOf("Windows", "Linux", "Mac"),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"name": schema.StringAttribute{
				Computed:    true,
				Description: "Name of the default policy. This is read-only as default policy names cannot be changed.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"description": schema.StringAttribute{
				Required:    true,
				Description: "Description of the default policy.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the default policy is enabled or disabled. This is read-only as default policies cannot be enabled or disabled.",
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
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

// Create creates the resource and sets the initial Terraform state.
func (r *itAutomationDefaultPolicyResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan itAutomationDefaultPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := r.getDefaultPolicyByPlatform(ctx, plan.PlatformName.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.ID = types.StringValue(*policy.ID)
	plan.LastUpdated = utils.GenerateUpdateTimestamp()

	if r.hasConfigChanges(&plan) {
		updatedPolicy, err := r.updateDefaultPolicyConfig(ctx, &plan)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error updating default policy configuration",
				err.Error(),
			)
			return
		}
		plan.wrap(*updatedPolicy)
	} else {
		plan.wrap(*policy)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *itAutomationDefaultPolicyResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state itAutomationDefaultPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policyID := state.ID.ValueString()
	policy, diags := getItAutomationPolicy(ctx, r.client, policyID)

	if diags.HasError() {
		// manually parse diagnostic errors.
		// helper functions return standardized diagnostics for consistency.
		// this is due to some IT Automation endpoints not returning structured/generic 404s.
		for _, d := range diags.Errors() {
			if d.Summary() == policyNotFoundErrorSummary {
				tflog.Warn(
					ctx,
					fmt.Sprintf(notFoundRemoving, fmt.Sprintf("IT Automation Default Policy %s", policyID)),
				)
				resp.State.RemoveResource(ctx)
				return
			}
		}
		resp.Diagnostics.Append(diags...)
		return
	}

	state.wrap(*policy)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *itAutomationDefaultPolicyResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan itAutomationDefaultPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updatedPolicy, err := r.updateDefaultPolicyConfig(ctx, &plan)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating default policy configuration",
			err.Error(),
		)
		return
	}

	plan.wrap(*updatedPolicy)
	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *itAutomationDefaultPolicyResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	// default policies cannot be deleted, just remove from terraform state.
	tflog.Info(
		ctx,
		"Default policy cannot be deleted, removing from Terraform state only",
	)
}

// ImportState imports the resource.
func (r *itAutomationDefaultPolicyResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ValidateConfig validates the resource configuration.
func (r *itAutomationDefaultPolicyResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config itAutomationDefaultPolicyResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.PlatformName.IsUnknown() {
		return
	}

	isMac := config.PlatformName.ValueString() == "Mac"

	if isMac {
		if config.CPUSchedulingPriority.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("cpu_scheduling_priority"),
				"Missing required field",
				"cpu_scheduling_priority is required for Mac default policies",
			)
		}

		if config.MemoryPressureLevel.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("memory_pressure_level"),
				"Missing required field",
				"memory_pressure_level is required for Mac default policies",
			)
		}

		if !config.CPUThrottle.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("cpu_throttle"),
				"Invalid argument",
				"cpu_throttle cannot be used with Mac default policies",
			)
		}

		if !config.MemoryAllocation.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("memory_allocation"),
				"Invalid argument",
				"memory_allocation cannot be used with Mac default policies",
			)
		}

		if !config.MemoryAllocationUnit.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("memory_allocation_unit"),
				"Invalid argument",
				"memory_allocation_unit cannot be used with Mac default policies",
			)
		}
	} else {
		if config.CPUThrottle.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("cpu_throttle"),
				"Missing required field",
				fmt.Sprintf("cpu_throttle is required for %s default policies", config.PlatformName.ValueString()),
			)
		}

		if config.MemoryAllocation.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("memory_allocation"),
				"Missing required field",
				fmt.Sprintf("memory_allocation is required for %s default policies", config.PlatformName.ValueString()),
			)
		}

		if config.MemoryAllocationUnit.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("memory_allocation_unit"),
				"Missing required field",
				fmt.Sprintf("memory_allocation_unit is required for %s default policies", config.PlatformName.ValueString()),
			)
		}

		if !config.CPUSchedulingPriority.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("cpu_scheduling_priority"),
				"Invalid argument",
				fmt.Sprintf(
					"cpu_scheduling_priority cannot be used with %s default policies",
					config.PlatformName.ValueString(),
				),
			)
		}

		if !config.MemoryPressureLevel.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("memory_pressure_level"),
				"Invalid argument",
				fmt.Sprintf(
					"memory_pressure_level cannot be used with %s default policies",
					config.PlatformName.ValueString(),
				),
			)
		}
	}
}

// hasConfigChanges checks if any configuration fields or description are provided.
func (r *itAutomationDefaultPolicyResource) hasConfigChanges(plan *itAutomationDefaultPolicyResourceModel) bool {
	return !plan.ConcurrentHostFileTransferLimit.IsNull() ||
		!plan.ConcurrentHostLimit.IsNull() ||
		!plan.ConcurrentTaskLimit.IsNull() ||
		!plan.EnableOsQuery.IsNull() ||
		!plan.EnablePythonExecution.IsNull() ||
		!plan.EnableScriptExecution.IsNull() ||
		!plan.ExecutionTimeout.IsNull() ||
		!plan.ExecutionTimeoutUnit.IsNull() ||
		!plan.CPUSchedulingPriority.IsNull() ||
		!plan.CPUThrottle.IsNull() ||
		!plan.MemoryAllocation.IsNull() ||
		!plan.MemoryAllocationUnit.IsNull() ||
		!plan.MemoryPressureLevel.IsNull() ||
		(!plan.Description.IsNull() && !plan.Description.IsUnknown())
}

// updateDefaultPolicyConfig updates the default policy configuration.
func (r *itAutomationDefaultPolicyResource) updateDefaultPolicyConfig(
	ctx context.Context,
	plan *itAutomationDefaultPolicyResourceModel,
) (*models.ItautomationPolicy, error) {
	policyID := plan.ID.ValueString()
	config := createPolicyConfigFromModelDefault(plan)

	body := &models.ItautomationUpdatePolicyRequest{
		ID:          policyID,
		Description: plan.Description.ValueStringPointer(),
		Config:      config,
	}

	params := &it_automation.ITAutomationUpdatePoliciesParams{
		Context: ctx,
		Body:    body,
	}

	ok, err := r.client.ItAutomation.ITAutomationUpdatePolicies(params)
	if err != nil {
		return nil, fmt.Errorf("could not update default policy ID %s: %w", policyID, err)
	}

	if ok == nil || ok.Payload == nil || len(ok.Payload.Resources) == 0 {
		return nil, fmt.Errorf("API returned empty response")
	}

	tflog.Info(
		ctx,
		fmt.Sprintf(
			"Successfully updated default policy %s for platform %s",
			policyID,
			plan.PlatformName.ValueString(),
		),
	)

	return ok.Payload.Resources[0], nil
}

// createPolicyConfigFromModelDefault creates a policy configuration from the default policy resource model.
func createPolicyConfigFromModelDefault(
	plan *itAutomationDefaultPolicyResourceModel,
) *models.ItautomationPolicyConfig {
	config := &models.ItautomationPolicyConfig{}

	config.Concurrency = &models.ItautomationConcurrencyConfig{
		ConcurrentHostFileTransferLimit: plan.ConcurrentHostFileTransferLimit.ValueInt32(),
		ConcurrentHostLimit:             plan.ConcurrentHostLimit.ValueInt32(),
		ConcurrentTaskLimit:             plan.ConcurrentTaskLimit.ValueInt32(),
	}

	config.Execution = &models.ItautomationExecutionConfig{
		EnableOsQuery:         plan.EnableOsQuery.ValueBoolPointer(),
		EnablePythonExecution: plan.EnablePythonExecution.ValueBoolPointer(),
		EnableScriptExecution: plan.EnableScriptExecution.ValueBoolPointer(),
		ExecutionTimeout:      plan.ExecutionTimeout.ValueInt32(),
		ExecutionTimeoutUnit:  plan.ExecutionTimeoutUnit.ValueString(),
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
