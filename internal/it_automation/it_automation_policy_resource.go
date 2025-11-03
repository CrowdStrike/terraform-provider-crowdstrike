package itautomation

import (
	"context"
	"fmt"
	"regexp"
	"strings"

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
	policiesMarkdownDescription  string         = "This resource allows management of IT Automation policies in the CrowdStrike Falcon platform. IT Automation policies allow you to configure settings related to the module and apply them to host groups."
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
	Enabled                         types.Bool   `tfsdk:"enabled"`
	LastUpdated                     types.String `tfsdk:"last_updated"`
	MemoryAllocation                types.Int32  `tfsdk:"memory_allocation"`
	MemoryAllocationUnit            types.String `tfsdk:"memory_allocation_unit"`
	MemoryPressureLevel             types.String `tfsdk:"memory_pressure_level"`
	PlatformName                    types.String `tfsdk:"platform_name"`
}

func (t *itAutomationPolicyResourceModel) wrap(
	ctx context.Context,
	policy models.ItautomationPolicy,
) diag.Diagnostics {
	var diags diag.Diagnostics

	t.ID = types.StringPointerValue(policy.ID)
	t.Name = types.StringPointerValue(policy.Name)
	t.Enabled = types.BoolValue(policy.IsEnabled)
	t.Description = types.StringPointerValue(policy.Description)
	t.PlatformName = types.StringPointerValue(policy.Target)

	hostGroups, diag := stringSliceToSet(ctx, policy.HostGroups)
	diags.Append(diag...)
	if !diags.HasError() {
		t.HostGroups = hostGroups
	}

	t.wrapConcurrency(policy.Config)
	t.wrapExecution(policy.Config)
	t.wrapResources(policy.Config, policy.Target)

	return diags
}

func (t *itAutomationPolicyResourceModel) wrapConcurrency(config *models.ItautomationPolicyConfig) {
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

func (t *itAutomationPolicyResourceModel) wrapExecution(config *models.ItautomationPolicyConfig) {
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

func (t *itAutomationPolicyResourceModel) wrapResources(config *models.ItautomationPolicyConfig, target *string) {
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
				Required:    true,
				Description: "Description of the policy.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"platform_name": schema.StringAttribute{
				Required:    true,
				Description: "Platform for the policy (Windows, Linux, Mac).",
				Validators: []validator.String{
					stringvalidator.OneOf("Windows", "Linux", "Mac"),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"enabled": schema.BoolAttribute{
				Required:    true,
				Description: "Whether the policy is enabled or disabled.",
			},
			"host_groups": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Set of host group IDs where this policy will be applied. Hosts in these groups will use this policy's configuration for IT automation tasks.",
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

// createPolicyConfigFromModel creates a policy configuration from the resource model.
func createPolicyConfigFromModel(
	plan *itAutomationPolicyResourceModel,
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
	if plan.PlatformName.ValueString() == "Mac" {
		config.Resources.CPUScheduling = plan.CPUSchedulingPriority.ValueString()
		config.Resources.MemoryPressureLevel = plan.MemoryPressureLevel.ValueString()
	} else {
		config.Resources.CPUThrottle = plan.CPUThrottle.ValueInt32()
		config.Resources.MemoryAllocation = plan.MemoryAllocation.ValueInt32()
		config.Resources.MemoryAllocationUnit = plan.MemoryAllocationUnit.ValueString()
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
		Platform:    plan.PlatformName.ValueStringPointer(),
		Config:      createPolicyConfigFromModel(&plan),
	}

	params := &it_automation.ITAutomationCreatePolicyParams{
		Context: ctx,
		Body:    body,
	}

	res, err := r.client.ItAutomation.ITAutomationCreatePolicy(params)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating IT automation policy",
			"Could not create policy, unexpected error: "+err.Error(),
		)
		return
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Error creating IT automation policy",
			"API returned empty response",
		)
		return
	}

	policy := res.Payload.Resources[0]
	plan.ID = types.StringPointerValue(policy.ID)
	plan.LastUpdated = utils.GenerateUpdateTimestamp()

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Enabled.ValueBool() {
		err := r.updatePolicyEnabledState(ctx, *policy.ID, true)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error enabling IT automation policy",
				err.Error(),
			)
			return
		}
	}

	if !plan.HostGroups.IsNull() && len(plan.HostGroups.Elements()) != 0 {
		hostGroups, diags := setToStringSlice(ctx, plan.HostGroups)
		resp.Diagnostics.Append(diags...)
		if diags.HasError() {
			return
		}

		body := &models.ItautomationUpdatePoliciesHostGroupsRequest{
			Action:       utils.Addr("assign"),
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

	updatedPolicy, diags := getItAutomationPolicy(ctx, r.client, *policy.ID)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, updatedPolicy)...)
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
	if diags.HasError() {
		for _, d := range diags.Errors() {
			if d.Summary() == policyNotFoundErrorSummary {
				tflog.Warn(
					ctx,
					fmt.Sprintf(
						notFoundRemoving,
						fmt.Sprintf("%s %s", itAutomationPolicy, policyID),
					),
				)
				resp.State.RemoveResource(ctx)
				return
			}
		}
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, policy)...)
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

	policyID := state.ID.ValueString()

	body := &models.ItautomationUpdatePolicyRequest{
		ID:          policyID,
		Name:        plan.Name.ValueString(),
		Description: plan.Description.ValueStringPointer(),
		Config:      createPolicyConfigFromModel(&plan),
	}

	params := &it_automation.ITAutomationUpdatePoliciesParams{
		Context: ctx,
		Body:    body,
	}

	res, err := r.client.ItAutomation.ITAutomationUpdatePolicies(params)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating IT automation policy",
			"Could not update policy ID "+policyID+", unexpected error: "+err.Error(),
		)
		return
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Error updating IT automation policy",
			"API returned empty response",
		)
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()

	if !plan.Enabled.Equal(state.Enabled) {
		err := r.updatePolicyEnabledState(ctx, policyID, plan.Enabled.ValueBool())
		if err != nil {
			resp.Diagnostics.AddError(
				"Error updating IT automation policy enabled state",
				err.Error(),
			)
			return
		}
	}

	hostGroupsToAdd, hostGroupsToRemove, diags := utils.SetIDsToModify(
		ctx,
		plan.HostGroups,
		state.HostGroups,
	)
	resp.Diagnostics.Append(diags...)
	if diags.HasError() {
		return
	}

	if len(hostGroupsToAdd) > 0 {
		body := &models.ItautomationUpdatePoliciesHostGroupsRequest{
			Action:       utils.Addr("assign"),
			HostGroupIds: hostGroupsToAdd,
			PolicyID:     &policyID,
		}

		params := &it_automation.ITAutomationUpdatePolicyHostGroupsParams{
			Context: ctx,
			Body:    body,
		}

		_, err := r.client.ItAutomation.ITAutomationUpdatePolicyHostGroups(params)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error adding IT automation policy host groups",
				fmt.Sprintf(
					"Could not add host groups: (%s) to policy with id: %s\n\n%s",
					strings.Join(hostGroupsToAdd, ", "),
					policyID,
					err.Error(),
				),
			)
			return
		}
	}

	if len(hostGroupsToRemove) > 0 {
		body := &models.ItautomationUpdatePoliciesHostGroupsRequest{
			Action:       utils.Addr("unassign"),
			HostGroupIds: hostGroupsToRemove,
			PolicyID:     &policyID,
		}

		params := &it_automation.ITAutomationUpdatePolicyHostGroupsParams{
			Context: ctx,
			Body:    body,
		}

		_, err := r.client.ItAutomation.ITAutomationUpdatePolicyHostGroups(params)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error removing IT automation policy host groups",
				fmt.Sprintf(
					"Could not remove host groups: (%s) from policy with id: %s\n\n%s",
					strings.Join(hostGroupsToRemove, ", "),
					policyID,
					err.Error(),
				),
			)
			return
		}
	}

	if !plan.Enabled.Equal(state.Enabled) || len(hostGroupsToAdd) > 0 || len(hostGroupsToRemove) > 0 {
		updatedPolicy, diags := getItAutomationPolicy(ctx, r.client, policyID)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
		resp.Diagnostics.Append(plan.wrap(ctx, updatedPolicy)...)
	} else {
		resp.Diagnostics.Append(plan.wrap(ctx, *res.Payload.Resources[0])...)
	}

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
	if diags.HasError() {
		for _, d := range diags.Errors() {
			if d.Summary() == policyNotFoundErrorSummary {
				return
			}
		}
		resp.Diagnostics.Append(diags...)
		return
	}

	if currentPolicy.IsEnabled {
		err := r.updatePolicyEnabledState(ctx, policyID, false)
		if err != nil {
			if isNotFoundError(err) {
				return
			}

			resp.Diagnostics.AddError(
				"Error disabling IT automation policy before deletion",
				err.Error(),
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
			return
		}

		if strings.Contains(err.Error(), "500") || strings.Contains(err.Error(), "409") {
			checkPolicy, checkDiags := getItAutomationPolicy(ctx, r.client, policyID)
			if checkDiags.HasError() {
				for _, d := range checkDiags.Errors() {
					if d.Summary() == policyNotFoundErrorSummary {
						return
					}
				}

				resp.Diagnostics.Append(checkDiags...)
				return
			}

			if checkPolicy.ID == nil {
				return
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

	if config.PlatformName.IsUnknown() {
		return
	}

	if config.PlatformName.ValueString() == "Mac" {
		if utils.IsNull(config.CPUSchedulingPriority) {
			resp.Diagnostics.AddAttributeError(
				path.Root("cpu_scheduling_priority"),
				"Missing required field",
				"cpu_scheduling_priority is required for Mac policies",
			)
		}

		if utils.IsNull(config.MemoryPressureLevel) {
			resp.Diagnostics.AddAttributeError(
				path.Root("memory_pressure_level"),
				"Missing required field",
				"memory_pressure_level is required for Mac policies",
			)
		}

		if utils.IsKnown(config.CPUThrottle) {
			resp.Diagnostics.AddAttributeError(
				path.Root("cpu_throttle"),
				"Invalid argument",
				"cpu_throttle cannot be used with Mac policies",
			)
		}

		if utils.IsKnown(config.MemoryAllocation) {
			resp.Diagnostics.AddAttributeError(
				path.Root("memory_allocation"),
				"Invalid argument",
				"memory_allocation cannot be used with Mac policies",
			)
		}

		if utils.IsKnown(config.MemoryAllocationUnit) {
			resp.Diagnostics.AddAttributeError(
				path.Root("memory_allocation_unit"),
				"Invalid argument",
				"memory_allocation_unit cannot be used with Mac policies",
			)
		}
	} else {
		if utils.IsNull(config.CPUThrottle) {
			resp.Diagnostics.AddAttributeError(
				path.Root("cpu_throttle"),
				"Missing required field",
				fmt.Sprintf(
					"cpu_throttle is required for %s policies",
					config.PlatformName.ValueString(),
				),
			)
		}

		if utils.IsNull(config.MemoryAllocation) {
			resp.Diagnostics.AddAttributeError(
				path.Root("memory_allocation"),
				"Missing required field",
				fmt.Sprintf(
					"memory_allocation is required for %s policies",
					config.PlatformName.ValueString(),
				),
			)
		}

		if utils.IsNull(config.MemoryAllocationUnit) {
			resp.Diagnostics.AddAttributeError(
				path.Root("memory_allocation_unit"),
				"Missing required field",
				fmt.Sprintf(
					"memory_allocation_unit is required for %s policies",
					config.PlatformName.ValueString(),
				),
			)
		}

		if utils.IsKnown(config.CPUSchedulingPriority) {
			resp.Diagnostics.AddAttributeError(
				path.Root("cpu_scheduling_priority"),
				"Invalid argument",
				fmt.Sprintf(
					"cpu_scheduling_priority cannot be used with %s policies",
					config.PlatformName.ValueString(),
				),
			)
		}

		if utils.IsKnown(config.MemoryPressureLevel) {
			resp.Diagnostics.AddAttributeError(
				path.Root("memory_pressure_level"),
				"Invalid argument",
				fmt.Sprintf(
					"memory_pressure_level cannot be used with %s policies",
					config.PlatformName.ValueString(),
				),
			)
		}
	}
}
