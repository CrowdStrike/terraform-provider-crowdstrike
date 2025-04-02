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
)

var (
	_ resource.Resource                   = &defaultPreventionPolicyMacResource{}
	_ resource.ResourceWithConfigure      = &defaultPreventionPolicyMacResource{}
	_ resource.ResourceWithImportState    = &defaultPreventionPolicyMacResource{}
	_ resource.ResourceWithValidateConfig = &defaultPreventionPolicyMacResource{}
)

func NewDefaultPreventionPolicyMacResource() resource.Resource {
	return &defaultPreventionPolicyMacResource{}
}

type defaultPreventionPolicyMacResource struct {
	client *client.CrowdStrikeAPISpecification
}

type defaultPreventionPolicyMacResourceModel struct {
	ID                                 types.String `tfsdk:"id"`
	Description                        types.String `tfsdk:"description"`
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

// wrap transforms Go values to their terraform wrapped values.
func (m *defaultPreventionPolicyMacResourceModel) wrap(
	ctx context.Context,
	policy models.PreventionPolicyV1,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if *policy.Description != "" {
		m.Description = types.StringValue(*policy.Description)
	}
	m.assignPreventionSettings(policy.PreventionSettings)
	ruleGroupSet, diag := convertRuleGroupToSet(ctx, policy.IoaRuleGroups)
	diags.Append(diag...)
	if diags.HasError() {
		return diags
	}
	m.RuleGroups = ruleGroupSet
	return diags
}

// generatePreventionSettings maps plan prevention settings to api params for create and update.
func (m *defaultPreventionPolicyMacResourceModel) generatePreventionSettings() []*models.PreventionSettingReqV1 {
	preventionSettings := []*models.PreventionSettingReqV1{}

	toggleSettings := map[string]types.Bool{
		"EndUserNotifications":               m.EndUserNotifications,
		"UnknownDetectionRelatedExecutables": m.UnknownDetectionRelatedExecutables,
		"UnknownExecutables":                 m.UnknownExecutables,
		"SensorTamperingProtection":          m.SensorTamperingProtection,
		"ScriptBasedExecutionMonitoring":     m.ScriptBasedExecutionMonitoring,
		"DetectOnWrite":                      m.DetectOnWrite,
		"QuarantineOnWrite":                  m.QuarantineOnWrite,
		"NextGenAV":                          m.NextGenAV,
		"CustomBlacklisting":                 m.CustomBlacklisting,
		"PreventSuspiciousProcesses":         m.PreventSuspiciousProcesses,
		"IntelPrevention":                    m.IntelPrevention,
		"ChopperWebshell":                    m.ChopperWebshell,
		"XPCOMShell":                         m.XPCOMShell,
		"EmpyreBackdoor":                     m.EmpyreBackdoor,
		"KcPasswordDecoded":                  m.KcPasswordDecoded,
		"HashCollector":                      m.HashCollector,
	}

	mlSliderSettings := map[string]mlSlider{
		"CloudAntiMalware":          *m.CloudAntiMalware,
		"AdwarePUP":                 *m.AdwarePUP,
		"OnSensorMLSlider":          *m.OnSensorMLSlider,
		"OnSensorMLAdwarePUPSlider": *m.OnSensorMLAdwarePUPSlider,
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

// assignPreventionSettings assigns the prevention settings returned from the api into the resource model.
func (m *defaultPreventionPolicyMacResourceModel) assignPreventionSettings(
	categories []*models.PreventionCategoryRespV1,
) {
	toggleSettings, mlSliderSettings, _ := mapPreventionSettings(categories)

	// toggle settings
	m.EndUserNotifications = defaultBoolFalse(toggleSettings["EndUserNotifications"])
	m.UnknownDetectionRelatedExecutables = defaultBoolFalse(
		toggleSettings["UnknownDetectionRelatedExecutables"],
	)
	m.UnknownExecutables = defaultBoolFalse(toggleSettings["UnknownExecutables"])
	m.SensorTamperingProtection = defaultBoolFalse(toggleSettings["SensorTamperingProtection"])
	m.ScriptBasedExecutionMonitoring = defaultBoolFalse(
		toggleSettings["ScriptBasedExecutionMonitoring"],
	)
	m.DetectOnWrite = defaultBoolFalse(toggleSettings["DetectOnWrite"])
	m.QuarantineOnWrite = defaultBoolFalse(toggleSettings["QuarantineOnWrite"])
	m.NextGenAV = defaultBoolFalse(toggleSettings["NextGenAV"])
	m.CustomBlacklisting = defaultBoolFalse(toggleSettings["CustomBlacklisting"])
	m.PreventSuspiciousProcesses = defaultBoolFalse(
		toggleSettings["PreventSuspiciousProcesses"],
	)
	m.IntelPrevention = defaultBoolFalse(toggleSettings["IntelPrevention"])
	m.ChopperWebshell = defaultBoolFalse(toggleSettings["ChopperWebshell"])
	m.XPCOMShell = defaultBoolFalse(toggleSettings["XPCOMShell"])
	m.EmpyreBackdoor = defaultBoolFalse(toggleSettings["EmpyreBackdoor"])
	m.KcPasswordDecoded = defaultBoolFalse(toggleSettings["KcPasswordDecoded"])
	m.HashCollector = defaultBoolFalse(toggleSettings["HashCollector"])

	// mlslider settings
	m.CloudAntiMalware = mlSliderSettings["CloudAntiMalware"]
	m.AdwarePUP = mlSliderSettings["AdwarePUP"]
	m.OnSensorMLSlider = mlSliderSettings["OnSensorMLSlider"]
	m.OnSensorMLAdwarePUPSlider = mlSliderSettings["OnSensorMLAdwarePUPSlider"]

}

func (r *defaultPreventionPolicyMacResource) Configure(
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

func (r *defaultPreventionPolicyMacResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_default_prevention_policy_mac"
}

func (r *defaultPreventionPolicyMacResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = generateMacSchema(true)
}

func (r *defaultPreventionPolicyMacResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan defaultPreventionPolicyMacResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := getDefaultPolicy(ctx, r.client, macPlatformName)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.ID = types.StringValue(*policy.ID)
	resp.Diagnostics.Append(
		resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleGroups, diag := convertRuleGroupToSet(ctx, policy.IoaRuleGroups)
	resp.Diagnostics.Append(diag...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		syncRuleGroups(ctx, r.client, plan.RuleGroups, ruleGroups, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags = updatePreventionPolicy(
		ctx,
		r.client,
		plan.generatePreventionSettings(),
		plan.ID.ValueString(),
		updatePreventionPolicyOptions{Description: plan.Description.ValueString()},
	)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))
	resp.Diagnostics.Append(plan.wrap(ctx, *policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)

}

func (r *defaultPreventionPolicyMacResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state defaultPreventionPolicyMacResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := getPreventionPolicy(ctx, r.client, state.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, *policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *defaultPreventionPolicyMacResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan defaultPreventionPolicyMacResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state defaultPreventionPolicyMacResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		syncRuleGroups(ctx, r.client, plan.RuleGroups, state.RuleGroups, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	preventionPolicy, diags := updatePreventionPolicy(
		ctx,
		r.client,
		plan.generatePreventionSettings(),
		plan.ID.ValueString(),
		updatePreventionPolicyOptions{Description: plan.Description.ValueString()},
	)

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	resp.Diagnostics.Append(plan.wrap(ctx, *preventionPolicy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *defaultPreventionPolicyMacResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
}

func (r *defaultPreventionPolicyMacResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *defaultPreventionPolicyMacResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {

	var config defaultPreventionPolicyMacResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(utils.ValidateEmptyIDs(ctx, config.RuleGroups, "ioa_rule_groups")...)

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
