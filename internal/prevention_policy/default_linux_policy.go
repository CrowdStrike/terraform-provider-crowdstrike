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
)

var (
	_ resource.Resource                   = &defaultPreventionPolicyLinuxResource{}
	_ resource.ResourceWithConfigure      = &defaultPreventionPolicyLinuxResource{}
	_ resource.ResourceWithImportState    = &defaultPreventionPolicyLinuxResource{}
	_ resource.ResourceWithValidateConfig = &defaultPreventionPolicyLinuxResource{}
)

func NewDefaultPreventionPolicyLinuxResource() resource.Resource {
	return &defaultPreventionPolicyLinuxResource{}
}

type defaultPreventionPolicyLinuxResource struct {
	client *client.CrowdStrikeAPISpecification
}

type defaultPreventionPolicyLinuxResourceModel struct {
	ID          types.String `tfsdk:"id"`
	LastUpdated types.String `tfsdk:"last_updated"`

	Description                        types.String `tfsdk:"description"`
	RuleGroups                         types.Set    `tfsdk:"ioa_rule_groups"`
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

// wrap transforms Go values to their terraform wrapped values.
func (m *defaultPreventionPolicyLinuxResourceModel) wrap(
	ctx context.Context,
	policy models.PreventionPolicyV1,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if *policy.Description != "" {
		m.Description = types.StringValue(*policy.Description)
	}
	diags.Append(m.assignPreventionSettings(ctx, policy.PreventionSettings)...)
	ruleGroupSet, diag := convertRuleGroupToSet(ctx, policy.IoaRuleGroups)
	diags.Append(diag...)
	if diags.HasError() {
		return diags
	}
	m.RuleGroups = ruleGroupSet
	return diags
}

// generatePreventionSettings maps plan prevention settings to api params for create and update.
func (m *defaultPreventionPolicyLinuxResourceModel) generatePreventionSettings(ctx context.Context) ([]*models.PreventionSettingReqV1, diag.Diagnostics) {
	preventionSettings := []*models.PreventionSettingReqV1{}
	var diags diag.Diagnostics

	toggleSettings := map[string]types.Bool{
		"UnknownDetectionRelatedExecutables": m.UnknownDetectionRelatedExecutables,
		"UnknownExecutables":                 m.UnknownExecutables,
		"ScriptBasedExecutionMonitoring":     m.ScriptBasedExecutionMonitoring,
		"NextGenAV":                          m.NextGenAV,
		"CustomBlacklisting":                 m.CustomBlacklisting,
		"PreventSuspiciousProcesses":         m.PreventSuspiciousProcesses,
		"DriftPrevention":                    m.DriftPrevention,
		"FilesystemVisibility":               m.FilesystemVisibility,
		"NetworkVisibility":                  m.NetworkVisibility,
		"HTTPVisibility":                     m.HTTPVisibility,
		"FTPVisibility":                      m.FTPVisibility,
		"TLSVisibility":                      m.TLSVisibility,
		"EmailProtocolVisibility":            m.EmailProtocolVisibility,
		"SensorTamperingProtection":          m.SensorTamperingProtection,
		"MemoryVisibility":                   m.MemoryVisibility,
		"OnWriteScriptFileVisibility":        m.OnWriteScriptFileVisibility,
		"ExtendedCommandLineVisibility":      m.ExtendedCommandLineVisibility,
	}

	mlSliderSettings := map[string]mlSlider{}

	if !m.CloudAntiMalware.IsNull() {
		var slider mlSlider
		diagsSlider := m.CloudAntiMalware.As(ctx, &slider, basetypes.ObjectAsOptions{})
		diags.Append(diagsSlider...)
		if diags.HasError() {
			return preventionSettings, diags
		}
		mlSliderSettings["CloudAntiMalware"] = slider
	}

	if !m.OnSensorMLSlider.IsNull() {
		var slider mlSlider
		diagsSlider := m.OnSensorMLSlider.As(ctx, &slider, basetypes.ObjectAsOptions{})
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

// assignPreventionSettings assigns the prevention settings returned from the api into the resource model.
func (m *defaultPreventionPolicyLinuxResourceModel) assignPreventionSettings(
	ctx context.Context,
	categories []*models.PreventionCategoryRespV1,
) diag.Diagnostics {
	var diags diag.Diagnostics
	toggleSettings, mlSliderSettings, _ := mapPreventionSettings(categories)

	// toggle settings
	m.UnknownDetectionRelatedExecutables = defaultBoolFalse(
		toggleSettings["UnknownDetectionRelatedExecutables"],
	)
	m.UnknownExecutables = defaultBoolFalse(toggleSettings["UnknownExecutables"])
	m.ScriptBasedExecutionMonitoring = defaultBoolFalse(
		toggleSettings["ScriptBasedExecutionMonitoring"],
	)
	m.NextGenAV = defaultBoolFalse(toggleSettings["NextGenAV"])
	m.CustomBlacklisting = defaultBoolFalse(toggleSettings["CustomBlacklisting"])
	m.PreventSuspiciousProcesses = defaultBoolFalse(
		toggleSettings["PreventSuspiciousProcesses"],
	)
	m.DriftPrevention = defaultBoolFalse(toggleSettings["DriftPrevention"])
	m.FilesystemVisibility = defaultBoolFalse(toggleSettings["FilesystemVisibility"])
	m.NetworkVisibility = defaultBoolFalse(toggleSettings["NetworkVisibility"])
	m.HTTPVisibility = defaultBoolFalse(toggleSettings["HTTPVisibility"])
	m.FTPVisibility = defaultBoolFalse(toggleSettings["FTPVisibility"])
	m.TLSVisibility = defaultBoolFalse(toggleSettings["TLSVisibility"])
	m.EmailProtocolVisibility = defaultBoolFalse(toggleSettings["EmailProtocolVisibility"])
	m.SensorTamperingProtection = defaultBoolFalse(toggleSettings["SensorTamperingProtection"])
	m.MemoryVisibility = defaultBoolFalse(toggleSettings["MemoryVisibility"])
	m.OnWriteScriptFileVisibility = defaultBoolFalse(
		toggleSettings["OnWriteScriptFileVisibility"],
	)
	m.ExtendedCommandLineVisibility = defaultBoolFalse(
		toggleSettings["ExtendedCommandLineVisibility"],
	)

	// mlslider settings
	if slider, ok := mlSliderSettings["CloudAntiMalware"]; ok {
		objValue, diagsObj := types.ObjectValueFrom(ctx, mlSlider{}.AttributeTypes(), slider)
		diags.Append(diagsObj...)
		if diags.HasError() {
			return diags
		}
		m.CloudAntiMalware = objValue
	}

	if slider, ok := mlSliderSettings["OnSensorMLSlider"]; ok {
		objValue, diagsObj := types.ObjectValueFrom(ctx, mlSlider{}.AttributeTypes(), slider)
		diags.Append(diagsObj...)
		if diags.HasError() {
			return diags
		}
		m.OnSensorMLSlider = objValue
	}

	return diags
}

func (r *defaultPreventionPolicyLinuxResource) Configure(
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

func (r *defaultPreventionPolicyLinuxResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_default_prevention_policy_linux"
}

func (r *defaultPreventionPolicyLinuxResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = generateLinuxSchema(true)
}

func (r *defaultPreventionPolicyLinuxResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan defaultPreventionPolicyLinuxResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := getDefaultPolicy(ctx, r.client, linuxPlatformName)
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

	preventionSettings, diagsGen := plan.generatePreventionSettings(ctx)
	resp.Diagnostics.Append(diagsGen...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags = updatePreventionPolicy(
		ctx,
		r.client,
		preventionSettings,
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

func (r *defaultPreventionPolicyLinuxResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state defaultPreventionPolicyLinuxResourceModel
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

func (r *defaultPreventionPolicyLinuxResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan defaultPreventionPolicyLinuxResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state defaultPreventionPolicyLinuxResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		syncRuleGroups(ctx, r.client, plan.RuleGroups, state.RuleGroups, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	preventionSettings, diagsGen := plan.generatePreventionSettings(ctx)
	resp.Diagnostics.Append(diagsGen...)
	if resp.Diagnostics.HasError() {
		return
	}

	preventionPolicy, diags := updatePreventionPolicy(
		ctx,
		r.client,
		preventionSettings,
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

func (r *defaultPreventionPolicyLinuxResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
}

func (r *defaultPreventionPolicyLinuxResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *defaultPreventionPolicyLinuxResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {

	var config defaultPreventionPolicyLinuxResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

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
