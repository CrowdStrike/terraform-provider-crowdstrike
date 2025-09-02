package preventionpolicy

import (
	"context"
	"fmt"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &preventionPolicyLinuxResource{}
	_ resource.ResourceWithConfigure      = &preventionPolicyLinuxResource{}
	_ resource.ResourceWithImportState    = &preventionPolicyLinuxResource{}
	_ resource.ResourceWithValidateConfig = &preventionPolicyLinuxResource{}
)

// NewPreventionPolicyLinuxResource is a helper function to simplify the provider implementation.
func NewPreventionPolicyLinuxResource() resource.Resource {
	return &preventionPolicyLinuxResource{}
}

// preventionPolicyLinuxResource is the resource implementation.
type preventionPolicyLinuxResource struct {
	client *client.CrowdStrikeAPISpecification
}

// preventionPolicyLinuxResourceModel is the resource implementation.
type preventionPolicyLinuxResourceModel struct {
	ID                                 types.String `tfsdk:"id"`
	Enabled                            types.Bool   `tfsdk:"enabled"`
	Name                               types.String `tfsdk:"name"`
	Description                        types.String `tfsdk:"description"`
	HostGroups                         types.Set    `tfsdk:"host_groups"`
	RuleGroups                         types.Set    `tfsdk:"ioa_rule_groups"`
	LastUpdated                        types.String `tfsdk:"last_updated"`
	CloudAntiMalware                   types.Object `tfsdk:"cloud_anti_malware"`
	OnSensorMLSlider                   types.Object `tfsdk:"sensor_anti_malware"`
	UnknownDetectionRelatedExecutables types.Bool   `tfsdk:"upload_unknown_detection_related_executables"`
	UnknownExecutables                 types.Bool   `tfsdk:"upload_unknown_executables"`
	ScriptBasedExecutionMonitoring     types.Bool   `tfsdk:"script_based_execution_monitoring"`
	NextGenAV                          types.Bool   `tfsdk:"quarantine"`
	CustomBlacklisting                 types.Bool   `tfsdk:"custom_blocking"`
	PreventSuspiciousProcesses         types.Bool   `tfsdk:"prevent_suspicious_processes"`
	DriftPrevention                    types.Bool   `tfsdk:"drift_prevention"`
	FilesystemVisibility               types.Bool   `tfsdk:"filesystem_visibility"`
	NetworkVisibility                  types.Bool   `tfsdk:"network_visibility"`
	HTTPVisibility                     types.Bool   `tfsdk:"http_visibility"`
	FTPVisibility                      types.Bool   `tfsdk:"ftp_visibility"`
	TLSVisibility                      types.Bool   `tfsdk:"tls_visibility"`
	EmailProtocolVisibility            types.Bool   `tfsdk:"email_protocol_visibility"`
	SensorTamperingProtection          types.Bool   `tfsdk:"sensor_tampering_protection"`
	MemoryVisibility                   types.Bool   `tfsdk:"memory_visibility"`
	OnWriteScriptFileVisibility        types.Bool   `tfsdk:"on_write_script_file_visibility"`
	ExtendedCommandLineVisibility      types.Bool   `tfsdk:"extended_command_line_visibility"`
}

// Configure adds the provider configured client to the resource.
func (r *preventionPolicyLinuxResource) Configure(
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
func (r *preventionPolicyLinuxResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_prevention_policy_linux"
}

// Schema defines the schema for the resource.
func (r *preventionPolicyLinuxResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = generateLinuxSchema(false)
}

// Create creates the resource and sets the initial Terraform state.
func (r *preventionPolicyLinuxResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {

	var plan preventionPolicyLinuxResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	preventionSettings, diagsGen := r.generatePreventionSettings(ctx, plan)
	resp.Diagnostics.Append(diagsGen...)
	if resp.Diagnostics.HasError() {
		return
	}

	res, diags := createPreventionPolicy(
		ctx,
		r.client,
		plan.Name.ValueString(),
		plan.Description.ValueString(),
		linuxPlatformName,
		preventionSettings,
	)

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	preventionPolicy := res.Payload.Resources[0]
	plan.ID = types.StringValue(*preventionPolicy.ID)
	plan.Description = types.StringValue(*preventionPolicy.Description)
	plan.Name = types.StringValue(*preventionPolicy.Name)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Enabled.ValueBool() {
		actionResp, diags := updatePolicyEnabledState(
			ctx,
			r.client,
			plan.ID.ValueString(),
			plan.Enabled.ValueBool(),
		)

		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		plan.Enabled = types.BoolValue(*actionResp.Payload.Resources[0].Enabled)
	} else {
		plan.Enabled = types.BoolValue(*preventionPolicy.Enabled)
	}

	resp.Diagnostics.Append(r.assignPreventionSettings(ctx, &plan, preventionPolicy.PreventionSettings)...)
	if resp.Diagnostics.HasError() {
		return
	}

	emptySet, diags := types.SetValueFrom(ctx, types.StringType, []string{})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		syncHostGroups(ctx, r.client, plan.HostGroups, emptySet, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		syncRuleGroups(ctx, r.client, plan.RuleGroups, emptySet, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *preventionPolicyLinuxResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state preventionPolicyLinuxResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := getPreventionPolicy(ctx, r.client, state.ID.ValueString())
	for _, err := range diags.Errors() {
		if err.Summary() == notFoundErrorSummary {
			tflog.Warn(
				ctx,
				fmt.Sprintf("prevention policy %s not found, removing from state", state.ID),
			)

			resp.State.RemoveResource(ctx)
			return
		}
	}
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state.ID = types.StringValue(*policy.ID)
	state.Name = types.StringValue(*policy.Name)
	state.Description = types.StringValue(*policy.Description)
	state.Enabled = types.BoolValue(*policy.Enabled)
	resp.Diagnostics.Append(r.assignPreventionSettings(ctx, &state, policy.PreventionSettings)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.assignHostGroups(ctx, &state, policy.Groups)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.assignRuleGroups(ctx, &state, policy.IoaRuleGroups)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *preventionPolicyLinuxResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	// Retrieve values from plan
	var plan preventionPolicyLinuxResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Retrieve values from state
	var state preventionPolicyLinuxResourceModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		syncHostGroups(ctx, r.client, plan.HostGroups, state.HostGroups, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		syncRuleGroups(ctx, r.client, plan.RuleGroups, state.RuleGroups, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	preventionSettings, diagsGen := r.generatePreventionSettings(ctx, plan)
	resp.Diagnostics.Append(diagsGen...)
	if resp.Diagnostics.HasError() {
		return
	}

	preventionPolicy, diags := updatePreventionPolicy(
		ctx,
		r.client,
		preventionSettings,
		plan.ID.ValueString(),
		updatePreventionPolicyOptions{
			Name:        plan.Name.ValueString(),
			Description: plan.Description.ValueString(),
		},
	)

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.ID = types.StringValue(*preventionPolicy.ID)
	plan.Description = types.StringValue(*preventionPolicy.Description)
	plan.Name = types.StringValue(*preventionPolicy.Name)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))
	resp.Diagnostics.Append(r.assignPreventionSettings(ctx, &plan, preventionPolicy.PreventionSettings)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Enabled.ValueBool() != state.Enabled.ValueBool() {
		actionResp, diags := updatePolicyEnabledState(
			ctx,
			r.client,
			plan.ID.ValueString(),
			plan.Enabled.ValueBool(),
		)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		plan.Enabled = types.BoolValue(*actionResp.Payload.Resources[0].Enabled)
	} else {
		plan.Enabled = types.BoolValue(*preventionPolicy.Enabled)
	}

	resp.Diagnostics.Append(r.assignHostGroups(ctx, &plan, preventionPolicy.Groups)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.assignRuleGroups(ctx, &plan, preventionPolicy.IoaRuleGroups)...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *preventionPolicyLinuxResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state preventionPolicyLinuxResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := state.ID.ValueString()

	resp.Diagnostics.Append(deletePreventionPolicy(ctx, r.client, id)...)
}

// ImportState implements the logic to support resource imports.
func (r *preventionPolicyLinuxResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	// Retrieve import ID and save to id attribute
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ValidateConfig runs during validate, plan, and apply
// validate resource is configured as expected.
func (r *preventionPolicyLinuxResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {

	var config preventionPolicyLinuxResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(utils.ValidateEmptyIDs(ctx, config.HostGroups, "host_groups")...)
	resp.Diagnostics.Append(utils.ValidateEmptyIDs(ctx, config.RuleGroups, "ioa_rule_groups")...)

	if !config.CloudAntiMalware.IsNull() {
		var slider mlSlider
		if diagsSlider := config.CloudAntiMalware.As(ctx, &slider, basetypes.ObjectAsOptions{}); !diagsSlider.HasError() {
			resp.Diagnostics.Append(
				validateMlSlider(
					"cloud_anti_malware",
					slider,
				)...)
		}
	}

	if !config.OnSensorMLSlider.IsNull() {
		var slider mlSlider
		if diagsSlider := config.OnSensorMLSlider.As(ctx, &slider, basetypes.ObjectAsOptions{}); !diagsSlider.HasError() {
			resp.Diagnostics.Append(
				validateMlSlider(
					"sensor_anti_malware",
					slider,
				)...)
		}
	}
}

// assignRuleGroups assigns the rule groups returned from the api into the resource model.
func (r *preventionPolicyLinuxResource) assignRuleGroups(
	ctx context.Context,
	config *preventionPolicyLinuxResourceModel,
	groups []*models.IoaRuleGroupsRuleGroupV1,
) diag.Diagnostics {

	ruleGroups := make([]types.String, 0, len(groups))
	for _, ruleGroup := range groups {
		ruleGroups = append(ruleGroups, types.StringValue(*ruleGroup.ID))
	}

	ruleGroupIDs, diags := types.SetValueFrom(ctx, types.StringType, ruleGroups)
	config.RuleGroups = ruleGroupIDs

	return diags
}

// assignHostGroups assigns the host groups returned from the api into the resource model.
func (r *preventionPolicyLinuxResource) assignHostGroups(
	ctx context.Context,
	config *preventionPolicyLinuxResourceModel,
	groups []*models.HostGroupsHostGroupV1,
) diag.Diagnostics {

	hostGroups := make([]types.String, 0, len(groups))
	for _, hostGroup := range groups {
		hostGroups = append(hostGroups, types.StringValue(*hostGroup.ID))
	}

	hostGroupIDs, diags := types.SetValueFrom(ctx, types.StringType, hostGroups)
	config.HostGroups = hostGroupIDs

	return diags
}

// assignPreventionSettings assigns the prevention settings returned from the api into the resource model.
func (r *preventionPolicyLinuxResource) assignPreventionSettings(
	ctx context.Context,
	state *preventionPolicyLinuxResourceModel,
	categories []*models.PreventionCategoryRespV1,
) diag.Diagnostics {
	var diags diag.Diagnostics
	toggleSettings, mlSliderSettings, _ := mapPreventionSettings(categories)

	// toggle settings
	state.UnknownDetectionRelatedExecutables = defaultBoolFalse(
		toggleSettings["UnknownDetectionRelatedExecutables"],
	)
	state.UnknownExecutables = defaultBoolFalse(toggleSettings["UnknownExecutables"])
	state.ScriptBasedExecutionMonitoring = defaultBoolFalse(
		toggleSettings["ScriptBasedExecutionMonitoring"],
	)
	state.NextGenAV = defaultBoolFalse(toggleSettings["NextGenAV"])
	state.CustomBlacklisting = defaultBoolFalse(toggleSettings["CustomBlacklisting"])
	state.PreventSuspiciousProcesses = defaultBoolFalse(
		toggleSettings["PreventSuspiciousProcesses"],
	)
	state.DriftPrevention = defaultBoolFalse(toggleSettings["DriftPrevention"])
	state.FilesystemVisibility = defaultBoolFalse(toggleSettings["FilesystemVisibility"])
	state.NetworkVisibility = defaultBoolFalse(toggleSettings["NetworkVisibility"])
	state.HTTPVisibility = defaultBoolFalse(toggleSettings["HTTPVisibility"])
	state.FTPVisibility = defaultBoolFalse(toggleSettings["FTPVisibility"])
	state.TLSVisibility = defaultBoolFalse(toggleSettings["TLSVisibility"])
	state.EmailProtocolVisibility = defaultBoolFalse(toggleSettings["EmailProtocolVisibility"])
	state.SensorTamperingProtection = defaultBoolFalse(toggleSettings["SensorTamperingProtection"])
	state.MemoryVisibility = defaultBoolFalse(toggleSettings["MemoryVisibility"])
	state.OnWriteScriptFileVisibility = defaultBoolFalse(
		toggleSettings["OnWriteScriptFileVisibility"],
	)
	state.ExtendedCommandLineVisibility = defaultBoolFalse(
		toggleSettings["ExtendedCommandLineVisibility"],
	)

	// mlslider settings
	if slider, ok := mlSliderSettings["CloudAntiMalware"]; ok {
		objValue, diagsObj := types.ObjectValueFrom(ctx, mlSlider{}.AttributeTypes(), slider)
		diags.Append(diagsObj...)
		if diags.HasError() {
			return diags
		}
		state.CloudAntiMalware = objValue
	}

	if slider, ok := mlSliderSettings["OnSensorMLSlider"]; ok {
		objValue, diagsObj := types.ObjectValueFrom(ctx, mlSlider{}.AttributeTypes(), slider)
		diags.Append(diagsObj...)
		if diags.HasError() {
			return diags
		}
		state.OnSensorMLSlider = objValue
	}

	return diags
}

// generatePreventionSettings maps plan prevention settings to api params for create and update.
func (r *preventionPolicyLinuxResource) generatePreventionSettings(
	ctx context.Context,
	config preventionPolicyLinuxResourceModel,
) ([]*models.PreventionSettingReqV1, diag.Diagnostics) {
	preventionSettings := []*models.PreventionSettingReqV1{}
	var diags diag.Diagnostics

	toggleSettings := map[string]types.Bool{
		"UnknownDetectionRelatedExecutables": config.UnknownDetectionRelatedExecutables,
		"UnknownExecutables":                 config.UnknownExecutables,
		"ScriptBasedExecutionMonitoring":     config.ScriptBasedExecutionMonitoring,
		"NextGenAV":                          config.NextGenAV,
		"CustomBlacklisting":                 config.CustomBlacklisting,
		"PreventSuspiciousProcesses":         config.PreventSuspiciousProcesses,
		"DriftPrevention":                    config.DriftPrevention,
		"FilesystemVisibility":               config.FilesystemVisibility,
		"NetworkVisibility":                  config.NetworkVisibility,
		"HTTPVisibility":                     config.HTTPVisibility,
		"FTPVisibility":                      config.FTPVisibility,
		"TLSVisibility":                      config.TLSVisibility,
		"EmailProtocolVisibility":            config.EmailProtocolVisibility,
		"SensorTamperingProtection":          config.SensorTamperingProtection,
		"MemoryVisibility":                   config.MemoryVisibility,
		"OnWriteScriptFileVisibility":        config.OnWriteScriptFileVisibility,
		"ExtendedCommandLineVisibility":      config.ExtendedCommandLineVisibility,
	}

	mlSliderSettings := map[string]mlSlider{}

	if !config.CloudAntiMalware.IsNull() {
		var slider mlSlider
		diagsSlider := config.CloudAntiMalware.As(ctx, &slider, basetypes.ObjectAsOptions{})
		diags.Append(diagsSlider...)
		if diags.HasError() {
			return preventionSettings, diags
		}
		mlSliderSettings["CloudAntiMalware"] = slider
	}

	if !config.OnSensorMLSlider.IsNull() {
		var slider mlSlider
		diagsSlider := config.OnSensorMLSlider.As(ctx, &slider, basetypes.ObjectAsOptions{})
		diags.Append(diagsSlider...)
		if diags.HasError() {
			return preventionSettings, diags
		}
		mlSliderSettings["OnSensorMLSlider"] = slider
	}

	for k, v := range toggleSettings {
		kCopy := k
		vCopy := v
		preventionSettings = append(preventionSettings, &models.PreventionSettingReqV1{
			ID:    &kCopy,
			Value: apiToggle{Enabled: vCopy.ValueBool()},
		})
	}

	for k, v := range mlSliderSettings {
		kCopy := k
		vCopy := v
		preventionSettings = append(preventionSettings, &models.PreventionSettingReqV1{
			ID: &kCopy,
			Value: apiMlSlider{
				Prevention: vCopy.Prevention.ValueString(),
				Detection:  vCopy.Detection.ValueString(),
			},
		})
	}

	return preventionSettings, diags
}
