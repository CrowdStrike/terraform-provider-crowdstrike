package preventionpolicy

import (
	"context"
	"fmt"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &preventionPolicyMacResource{}
	_ resource.ResourceWithConfigure      = &preventionPolicyMacResource{}
	_ resource.ResourceWithImportState    = &preventionPolicyMacResource{}
	_ resource.ResourceWithValidateConfig = &preventionPolicyMacResource{}
)

// NewPreventionPolicyMacResource is a helper function to simplify the provider implementation.
func NewPreventionPolicyMacResource() resource.Resource {
	return &preventionPolicyMacResource{}
}

// preventionPolicyMacResource is the resource implementation.
type preventionPolicyMacResource struct {
	client *client.CrowdStrikeAPISpecification
}

// preventionPolicyMacResourceModel is the resource implementation.
type preventionPolicyMacResourceModel struct {
	ID                                 types.String `tfsdk:"id"`
	Enabled                            types.Bool   `tfsdk:"enabled"`
	Name                               types.String `tfsdk:"name"`
	Description                        types.String `tfsdk:"description"`
	HostGroups                         types.Set    `tfsdk:"host_groups"`
	RuleGroups                         types.Set    `tfsdk:"ioa_rule_groups"`
	LastUpdated                        types.String `tfsdk:"last_updated"`
	CloudAntiMalware                   *mlSlider    `tfsdk:"cloud_anti_malware"`
	AdwarePUP                          *mlSlider    `tfsdk:"cloud_adware_and_pup"`
	OnSensorMLSlider                   *mlSlider    `tfsdk:"sensor_anti_malware"`
	EndUserNotifications               types.Bool   `tfsdk:"notify_end_users"`
	UnknownDetectionRelatedExecutables types.Bool   `tfsdk:"upload_unknown_detection_related_executables"`
	UnknownExecutables                 types.Bool   `tfsdk:"upload_unknown_executables"`
	SensorTamperingProtection          types.Bool   `tfsdk:"sensor_tampering_protection"`
	ScriptBasedExecutionMonitoring     types.Bool   `tfsdk:"script_based_execution_monitoring"`
	DetectOnWrite                      types.Bool   `tfsdk:"detect_on_write"`
	QuarantineOnWrite                  types.Bool   `tfsdk:"quarantine_on_write"`
	NextGenAV                          types.Bool   `tfsdk:"quarantine"`
	CustomBlacklisting                 types.Bool   `tfsdk:"custom_blocking"`
	PreventSuspiciousProcesses         types.Bool   `tfsdk:"prevent_suspicious_processes"`
	IntelPrevention                    types.Bool   `tfsdk:"intelligence_sourced_threats"`
	ChopperWebshell                    types.Bool   `tfsdk:"chopper_webshell"`
	OnSensorMLAdwarePUPSlider          *mlSlider    `tfsdk:"sensor_adware_and_pup"`
	XPCOMShell                         types.Bool   `tfsdk:"xpcom_shell"`
	EmpyreBackdoor                     types.Bool   `tfsdk:"empyre_backdoor"`
	KcPasswordDecoded                  types.Bool   `tfsdk:"kc_password_decoded"`
	HashCollector                      types.Bool   `tfsdk:"hash_collector"`
}

// Configure adds the provider configured client to the resource.
func (r *preventionPolicyMacResource) Configure(
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
func (r *preventionPolicyMacResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_prevention_policy_mac"
}

// Schema defines the schema for the resource.
func (r *preventionPolicyMacResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for the prevention policy.",
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
				Description: "Name of the prevention policy.",
			},
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Enable the prevention policy.",
				Default:     booldefault.StaticBool(true),
			},
			"host_groups": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Host Group ids to attach to the prevention policy.",
			},
			"ioa_rule_groups": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "IOA Rule Group to attach to the prevention policy.",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description of the prevention policy.",
			},
			"cloud_anti_malware": mlSLiderAttribute(
				"Use cloud-based machine learning informed by global analysis of executables to detect and prevent known malware for your online hosts.",
			),
			"cloud_adware_and_pup": mlSLiderAttribute(
				"Use cloud-based machine learning informed by global analysis of executables to detect and prevent adware and potentially unwanted programs (PUP) for your online hosts.",
			),
			"sensor_anti_malware": mlSLiderAttribute(
				"For offline and online hosts, use sensor-based machine learning to identify and analyze unknown executables as they run to detect and prevent malware.",
			),
			"sensor_adware_and_pup": mlSLiderAttribute(
				"For offline and online hosts, use sensor-based machine learning to identify and analyze unknown executables as they run to detect and prevent adware and potentially unwanted programs (PUP).",
			),
			"notify_end_users": toggleAttribute(
				"Show a pop-up notification to the end user when the Falcon sensor blocks, kills, or quarantines. See these messages in Console.app by searching for Process: Falcon Notifications.",
			),
			"upload_unknown_detection_related_executables": toggleAttribute(
				"Upload all unknown detection-related executables for advanced analysis in the cloud.",
			),
			"upload_unknown_executables": toggleAttribute(
				"Upload all unknown executables for advanced analysis in the cloud.",
			),
			"sensor_tampering_protection": toggleAttribute(
				"Blocks attempts to tamper with the sensor. If disabled, the sensor still creates detections for tampering attempts but doesn’t block them. Disabling not recommended.",
			),
			"script_based_execution_monitoring": toggleAttribute(
				"Provides visibility into suspicious scripts, including shell and other scripting languages.",
			),
			"detect_on_write": toggleAttribute(
				"Use machine learning to analyze suspicious files when they're written to disk. To adjust detection sensitivity, change Anti-malware Detection levels in Sensor Machine Learning and Cloud Machine Learning.",
			),
			"quarantine_on_write": toggleAttribute(
				"Use machine learning to quarantine suspicious files when they're written to disk. To adjust quarantine sensitivity, change Anti-malware Prevention levels in Sensor Machine Learning and Cloud Machine Learning.",
			),
			"quarantine": toggleAttribute(
				"Quarantine executable files after they’re prevented by NGAV. When this is enabled, we recommend setting anti-malware prevention levels to Moderate or higher and not using other antivirus solutions.",
			),
			"custom_blocking": toggleAttribute(
				"Block processes matching hashes that you add to IOC Management with the action set to \"Block\" or \"Block, hide detection\".",
			),
			"intelligence_sourced_threats": toggleAttribute(
				"Block processes that CrowdStrike Intelligence analysts classify as malicious. These are focused on static hash-based IOCs.",
			),
			"xpcom_shell": toggleAttribute("The execution of an XPCOM shell was blocked."),
			"empyre_backdoor": toggleAttribute(
				"A process with behaviors indicative of the Empyre Backdoor was terminated.",
			),
			"chopper_webshell": toggleAttribute(
				"Execution of a command shell was blocked and is indicative of the system hosting a Chopper web page.",
			),
			"kc_password_decoded": toggleAttribute(
				"An attempt to recover a plaintext password via the kcpassword file was blocked.",
			),
			"hash_collector": toggleAttribute(
				"An attempt to dump a user’s hashed password was blocked.",
			),
			"prevent_suspicious_processes": toggleAttribute(
				"Block processes that CrowdStrike analysts classify as suspicious. These are focused on dynamic IOAs, such as malware, exploits and other threats.",
			),
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *preventionPolicyMacResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {

	var plan preventionPolicyMacResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	preventionSettings := r.generatePreventionSettings(plan)
	res, diags := createPreventionPolicy(
		ctx,
		r.client,
		plan.Name.ValueString(),
		plan.Description.ValueString(),
		macPlatformName,
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

	r.assignPreventionSettings(&plan, preventionPolicy.PreventionSettings)

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
func (r *preventionPolicyMacResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state preventionPolicyMacResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := getPreventionPolicy(ctx, r.client, state.ID.ValueString())

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state.ID = types.StringValue(*policy.ID)
	state.Name = types.StringValue(*policy.Name)
	state.Description = types.StringValue(*policy.Description)
	state.Enabled = types.BoolValue(*policy.Enabled)
	r.assignPreventionSettings(&state, policy.PreventionSettings)

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
func (r *preventionPolicyMacResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	// Retrieve values from plan
	var plan preventionPolicyMacResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Retrieve values from state
	var state preventionPolicyMacResourceModel
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

	preventionSettings := r.generatePreventionSettings(plan)

	preventionPolicy, diags := updatePreventionPolicy(
		ctx,
		r.client,
		plan.Name.ValueString(),
		plan.Description.ValueString(),
		preventionSettings,
		plan.ID.ValueString(),
	)

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.ID = types.StringValue(*preventionPolicy.ID)
	plan.Description = types.StringValue(*preventionPolicy.Description)
	plan.Name = types.StringValue(*preventionPolicy.Name)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))
	r.assignPreventionSettings(&plan, preventionPolicy.PreventionSettings)

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
func (r *preventionPolicyMacResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state preventionPolicyMacResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := state.ID.ValueString()

	resp.Diagnostics.Append(deletePreventionPolicy(ctx, r.client, id)...)
}

// ImportState implements the logic to support resource imports.
func (r *preventionPolicyMacResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	// Retrieve import ID and save to id attribute
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ValidateConfig runs during validate, plan, and apply
// validate resource is configured as expected.
func (r *preventionPolicyMacResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {

	var config preventionPolicyMacResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.QuarantineOnWrite.ValueBool(),
			(config.NextGenAV.ValueBool() && config.DetectOnWrite.ValueBool()),
			"quarantine_on_write",
			"quarantine and detect_on_write",
		)...)

	if config.CloudAntiMalware != nil {
		resp.Diagnostics.Append(
			validateMlSlider(
				"cloud_anti_malware",
				*config.CloudAntiMalware,
			)...)
	}

	if config.AdwarePUP != nil {
		resp.Diagnostics.Append(
			validateMlSlider(
				"cloud_adware_and_pup",
				*config.AdwarePUP,
			)...)
	}

	if config.OnSensorMLSlider != nil {
		resp.Diagnostics.Append(
			validateMlSlider(
				"sensor_anti_malware",
				*config.OnSensorMLSlider,
			)...)
	}

	if config.OnSensorMLAdwarePUPSlider != nil {
		resp.Diagnostics.Append(
			validateMlSlider(
				"sensor_adware_and_pup",
				*config.OnSensorMLAdwarePUPSlider,
			)...)
	}
}

// assignRuleGroups assigns the rule groups returned from the api into the resource model.
func (r *preventionPolicyMacResource) assignRuleGroups(
	ctx context.Context,
	config *preventionPolicyMacResourceModel,
	groups []*models.IoaRuleGroupsRuleGroupV1,
) diag.Diagnostics {

	var ruleGroups []string
	for _, hostGroup := range groups {
		ruleGroups = append(ruleGroups, *hostGroup.ID)
	}

	hostGroupIDs, diags := types.SetValueFrom(ctx, types.StringType, ruleGroups)
	config.RuleGroups = hostGroupIDs

	return diags
}

// assignHostGroups assigns the host groups returned from the api into the resource model.
func (r *preventionPolicyMacResource) assignHostGroups(
	ctx context.Context,
	config *preventionPolicyMacResourceModel,
	groups []*models.HostGroupsHostGroupV1,
) diag.Diagnostics {

	var hostGroups []string
	for _, hostGroup := range groups {
		hostGroups = append(hostGroups, *hostGroup.ID)
	}

	hostGroupIDs, diags := types.SetValueFrom(ctx, types.StringType, hostGroups)
	config.HostGroups = hostGroupIDs

	return diags
}

// assignPreventionSettings assigns the prevention settings returned from the api into the resource model.
func (r *preventionPolicyMacResource) assignPreventionSettings(
	state *preventionPolicyMacResourceModel,
	categories []*models.PreventionCategoryRespV1,
) {
	toggleSettings, mlSliderSettings, _ := mapPreventionSettings(categories)

	//todo: check if value exists??

	// toggle settings
	state.EndUserNotifications = toggleSettings["EndUserNotifications"]
	state.UnknownDetectionRelatedExecutables = toggleSettings["UnknownDetectionRelatedExecutables"]
	state.UnknownExecutables = toggleSettings["UnknownExecutables"]
	state.SensorTamperingProtection = toggleSettings["SensorTamperingProtection"]
	state.ScriptBasedExecutionMonitoring = toggleSettings["ScriptBasedExecutionMonitoring"]
	state.DetectOnWrite = toggleSettings["DetectOnWrite"]
	state.QuarantineOnWrite = toggleSettings["QuarantineOnWrite"]
	state.NextGenAV = toggleSettings["NextGenAV"]
	state.CustomBlacklisting = toggleSettings["CustomBlacklisting"]
	state.PreventSuspiciousProcesses = toggleSettings["PreventSuspiciousProcesses"]
	state.IntelPrevention = toggleSettings["IntelPrevention"]
	state.ChopperWebshell = toggleSettings["ChopperWebshell"]
	state.XPCOMShell = toggleSettings["XPCOMShell"]
	state.EmpyreBackdoor = toggleSettings["EmpyreBackdoor"]
	state.KcPasswordDecoded = toggleSettings["KcPasswordDecoded"]
	state.HashCollector = toggleSettings["HashCollector"]

	// mlslider settings
	state.CloudAntiMalware = mlSliderSettings["CloudAntiMalware"]
	state.AdwarePUP = mlSliderSettings["AdwarePUP"]
	state.OnSensorMLSlider = mlSliderSettings["OnSensorMLSlider"]
	state.OnSensorMLAdwarePUPSlider = mlSliderSettings["OnSensorMLAdwarePUPSlider"]
}

// generatePreventionSettings maps plan prevention settings to api params for create and update.
func (r *preventionPolicyMacResource) generatePreventionSettings(
	config preventionPolicyMacResourceModel,
) []*models.PreventionSettingReqV1 {
	preventionSettings := []*models.PreventionSettingReqV1{}

	toggleSettings := map[string]types.Bool{
		"EndUserNotifications":               config.EndUserNotifications,
		"UnknownDetectionRelatedExecutables": config.UnknownDetectionRelatedExecutables,
		"UnknownExecutables":                 config.UnknownExecutables,
		"SensorTamperingProtection":          config.SensorTamperingProtection,
		"ScriptBasedExecutionMonitoring":     config.ScriptBasedExecutionMonitoring,
		"DetectOnWrite":                      config.DetectOnWrite,
		"QuarantineOnWrite":                  config.QuarantineOnWrite,
		"NextGenAV":                          config.NextGenAV,
		"CustomBlacklisting":                 config.CustomBlacklisting,
		"PreventSuspiciousProcesses":         config.PreventSuspiciousProcesses,
		"IntelPrevention":                    config.IntelPrevention,
		"ChopperWebshell":                    config.ChopperWebshell,
		"XPCOMShell":                         config.XPCOMShell,
		"EmpyreBackdoor":                     config.EmpyreBackdoor,
		"KcPasswordDecoded":                  config.KcPasswordDecoded,
		"HashCollector":                      config.HashCollector,
	}

	mlSliderSettings := map[string]mlSlider{
		"CloudAntiMalware":          *config.CloudAntiMalware,
		"AdwarePUP":                 *config.AdwarePUP,
		"OnSensorMLSlider":          *config.OnSensorMLSlider,
		"OnSensorMLAdwarePUPSlider": *config.OnSensorMLAdwarePUPSlider,
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

	return preventionSettings
}
