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
	_ resource.Resource                   = &defaultPreventionPolicyWindowsResource{}
	_ resource.ResourceWithConfigure      = &defaultPreventionPolicyWindowsResource{}
	_ resource.ResourceWithImportState    = &defaultPreventionPolicyWindowsResource{}
	_ resource.ResourceWithValidateConfig = &defaultPreventionPolicyWindowsResource{}
)

func NewDefaultPreventionPolicyWindowsResource() resource.Resource {
	return &defaultPreventionPolicyWindowsResource{}
}

type defaultPreventionPolicyWindowsResource struct {
	client *client.CrowdStrikeAPISpecification
}

type defaultPreventionPolicyWindowsResourceModel struct {
	ID          types.String `tfsdk:"id"`
	LastUpdated types.String `tfsdk:"last_updated"`

	Description                               types.String       `tfsdk:"description"`
	RuleGroups                                types.Set          `tfsdk:"ioa_rule_groups"`
	CloudAntiMalwareForMicrosoftOfficeFiles   *mlSlider          `tfsdk:"cloud_anti_malware_microsoft_office_files"`
	ExtendedUserModeDataSlider                *detectionMlSlider `tfsdk:"extended_user_mode_data"`
	CloudAntiMalware                          *mlSlider          `tfsdk:"cloud_anti_malware"`
	AdwarePUP                                 *mlSlider          `tfsdk:"adware_and_pup"`
	OnSensorMLSlider                          *mlSlider          `tfsdk:"sensor_anti_malware"`
	OnSensorMLSliderForSensorEndUserScans     *mlSlider          `tfsdk:"sensor_anti_malware_user_initiated"`
	OnSensorMLSliderForCloudEndUserScans      *mlSlider          `tfsdk:"cloud_anti_malware_user_initiated"`
	AdditionalUserModeData                    types.Bool         `tfsdk:"additional_user_mode_data"`
	EndUserNotifications                      types.Bool         `tfsdk:"notify_end_users"`
	UnknownDetectionRelatedExecutables        types.Bool         `tfsdk:"upload_unknown_detection_related_executables"`
	UnknownExecutables                        types.Bool         `tfsdk:"upload_unknown_executables"`
	SensorTamperingProtection                 types.Bool         `tfsdk:"sensor_tampering_protection"`
	InterpreterProtection                     types.Bool         `tfsdk:"interpreter_only"`
	EngineProtectionV2                        types.Bool         `tfsdk:"engine_full_visibility"`
	ScriptBasedExecutionMonitoring            types.Bool         `tfsdk:"script_based_execution_monitoring"`
	HTTPDetections                            types.Bool         `tfsdk:"http_detections"`
	RedactHTTPDetectionDetails                types.Bool         `tfsdk:"redact_http_detection_details"`
	HardwareEnhancedExploitDetection          types.Bool         `tfsdk:"hardware_enhanced_exploit_detection"`
	EnhancedExploitationVisibility            types.Bool         `tfsdk:"enhanced_exploitation_visibility"`
	DLLLoadVisibility                         types.Bool         `tfsdk:"enhanced_dll_load_visibility"`
	MemoryScan                                types.Bool         `tfsdk:"memory_scanning"`
	CPUMemoryScan                             types.Bool         `tfsdk:"memory_scanning_scan_with_cpu"`
	FirmwareAnalysisExtraction                types.Bool         `tfsdk:"bios_deep_visibility"`
	MLLargeFileHandling                       types.Bool         `tfsdk:"enhanced_ml_for_larger_files"`
	USBInsertionTriggeredScan                 types.Bool         `tfsdk:"usb_insertion_triggered_scan"`
	DetectOnWrite                             types.Bool         `tfsdk:"detect_on_write"`
	QuarantineOnWrite                         types.Bool         `tfsdk:"quarantine_on_write"`
	OnWriteScriptFileVisibility               types.Bool         `tfsdk:"on_write_script_file_visibility"`
	NextGenAV                                 types.Bool         `tfsdk:"quarantine_and_security_center_registration"`
	NextGenAVQuarantineOnRemovableMedia       types.Bool         `tfsdk:"quarantine_on_removable_media"`
	MicrosoftOfficeFileSuspiciousMacroRemoval types.Bool         `tfsdk:"microsoft_office_file_suspicious_macro_removal"`
	CustomBlacklisting                        types.Bool         `tfsdk:"custom_blocking"`
	PreventSuspiciousProcesses                types.Bool         `tfsdk:"prevent_suspicious_processes"`
	SuspiciousRegistryOperations              types.Bool         `tfsdk:"suspicious_registry_operations"`
	MaliciousPowershell                       types.Bool         `tfsdk:"suspicious_scripts_and_commands"`
	IntelPrevention                           types.Bool         `tfsdk:"intelligence_sourced_threats"`
	SuspiciousKernelDrivers                   types.Bool         `tfsdk:"driver_load_prevention"`
	VulnerableDriverProtection                types.Bool         `tfsdk:"vulnerable_driver_protection"`
	ForceASLR                                 types.Bool         `tfsdk:"force_aslr"`
	ForceDEP                                  types.Bool         `tfsdk:"force_dep"`
	HeapSprayPreallocation                    types.Bool         `tfsdk:"heap_spray_preallocation"`
	NullPageAllocation                        types.Bool         `tfsdk:"null_page_allocation"`
	SEHOverwriteProtection                    types.Bool         `tfsdk:"seh_overwrite_protection"`
	BackupDeletion                            types.Bool         `tfsdk:"backup_deletion"`
	Cryptowall                                types.Bool         `tfsdk:"cryptowall"`
	FileEncryption                            types.Bool         `tfsdk:"file_encryption"`
	Locky                                     types.Bool         `tfsdk:"locky"`
	FileSystemAccess                          types.Bool         `tfsdk:"file_system_access"`
	VolumeShadowCopyAudit                     types.Bool         `tfsdk:"volume_shadow_copy_audit"`
	VolumeShadowCopyProtect                   types.Bool         `tfsdk:"volume_shadow_copy_protect"`
	ApplicationExploitationActivity           types.Bool         `tfsdk:"application_exploitation_activity"`
	ChopperWebshell                           types.Bool         `tfsdk:"chopper_webshell"`
	DriveByDownload                           types.Bool         `tfsdk:"drive_by_download"`
	ProcessHollowing                          types.Bool         `tfsdk:"code_injection"`
	JavaScriptViaRundll32                     types.Bool         `tfsdk:"javascript_via_rundll32"`
	WindowsLogonBypassStickyKeys              types.Bool         `tfsdk:"windows_logon_bypass_sticky_keys"`
	CredentialDumping                         types.Bool         `tfsdk:"credential_dumping"`
	AutomatedRemediation                      types.Bool         `tfsdk:"advanced_remediation"`
	FileSystemContainmentEnabled              types.Bool         `tfsdk:"file_system_containment"`
}

// wrap transforms Go values to their terraform wrapped values.
func (m *defaultPreventionPolicyWindowsResourceModel) wrap(
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
func (m *defaultPreventionPolicyWindowsResourceModel) generatePreventionSettings() []*models.PreventionSettingReqV1 {
	preventionSettings := []*models.PreventionSettingReqV1{}

	toggleSettings := map[string]types.Bool{
		"AdditionalUserModeData":                    m.AdditionalUserModeData,
		"EndUserNotifications":                      m.EndUserNotifications,
		"UnknownDetectionRelatedExecutables":        m.UnknownDetectionRelatedExecutables,
		"UnknownExecutables":                        m.UnknownExecutables,
		"SensorTamperingProtection":                 m.SensorTamperingProtection,
		"InterpreterProtection":                     m.InterpreterProtection,
		"EngineProtectionV2":                        m.EngineProtectionV2,
		"ScriptBasedExecutionMonitoring":            m.ScriptBasedExecutionMonitoring,
		"HTTPDetections":                            m.HTTPDetections,
		"RedactHTTPDetectionDetails":                m.RedactHTTPDetectionDetails,
		"HardwareEnhancedExploitDetection":          m.HardwareEnhancedExploitDetection,
		"EnhancedExploitationVisibility":            m.EnhancedExploitationVisibility,
		"DLLLoadVisibility":                         m.DLLLoadVisibility,
		"MemoryScan":                                m.MemoryScan,
		"CPUMemoryScan":                             m.CPUMemoryScan,
		"FirmwareAnalysisExtraction":                m.FirmwareAnalysisExtraction,
		"ML Large File Handling":                    m.MLLargeFileHandling,
		"USBInsertionTriggeredScan":                 m.USBInsertionTriggeredScan,
		"DetectOnWrite":                             m.DetectOnWrite,
		"QuarantineOnWrite":                         m.QuarantineOnWrite,
		"OnWriteScriptFileVisibility":               m.OnWriteScriptFileVisibility,
		"NextGenAV":                                 m.NextGenAV,
		"NextGenAVQuarantineOnRemovableMedia":       m.NextGenAVQuarantineOnRemovableMedia,
		"MicrosoftOfficeFileSuspiciousMacroRemoval": m.MicrosoftOfficeFileSuspiciousMacroRemoval,
		"CustomBlacklisting":                        m.CustomBlacklisting,
		"PreventSuspiciousProcesses":                m.PreventSuspiciousProcesses,
		"SuspiciousRegistryOperations":              m.SuspiciousRegistryOperations,
		"MaliciousPowershell":                       m.MaliciousPowershell,
		"IntelPrevention":                           m.IntelPrevention,
		"SuspiciousKernelDrivers":                   m.SuspiciousKernelDrivers,
		"VulnerableDriverProtection":                m.VulnerableDriverProtection,
		"ForceASLR":                                 m.ForceASLR,
		"ForceDEP":                                  m.ForceDEP,
		"HeapSprayPreallocation":                    m.HeapSprayPreallocation,
		"NullPageAllocation":                        m.NullPageAllocation,
		"SEHOverwriteProtection":                    m.SEHOverwriteProtection,
		"BackupDeletion":                            m.BackupDeletion,
		"Cryptowall":                                m.Cryptowall,
		"FileEncryption":                            m.FileEncryption,
		"Locky":                                     m.Locky,
		"FileSystemAccess":                          m.FileSystemAccess,
		"VolumeShadowCopyAudit":                     m.VolumeShadowCopyAudit,
		"VolumeShadowCopyProtect":                   m.VolumeShadowCopyProtect,
		"ApplicationExploitationActivity":           m.ApplicationExploitationActivity,
		"ChopperWebshell":                           m.ChopperWebshell,
		"DriveByDownload":                           m.DriveByDownload,
		"ProcessHollowing":                          m.ProcessHollowing,
		"JavaScriptViaRundll32":                     m.JavaScriptViaRundll32,
		"WindowsLogonBypassStickyKeys":              m.WindowsLogonBypassStickyKeys,
		"CredentialDumping":                         m.CredentialDumping,
		"AutomatedRemediation":                      m.AutomatedRemediation,
		"FileSystemContainmentEnabled":              m.FileSystemContainmentEnabled,
	}

	mlSliderSettings := map[string]mlSlider{
		"CloudAntiMalwareForMicrosoftOfficeFiles": *m.CloudAntiMalwareForMicrosoftOfficeFiles,
		"CloudAntiMalware":                        *m.CloudAntiMalware,
		"AdwarePUP":                               *m.AdwarePUP,
		"OnSensorMLSlider":                        *m.OnSensorMLSlider,
		"OnSensorMLSliderForSensorEndUserScans":   *m.OnSensorMLSliderForSensorEndUserScans,
		"OnSensorMLSliderForCloudEndUserScans":    *m.OnSensorMLSliderForCloudEndUserScans,
	}
	detectionMlSliderSettings := map[string]detectionMlSlider{
		"ExtendedUserModeDataSlider": *m.ExtendedUserModeDataSlider,
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

	for k, v := range detectionMlSliderSettings {
		kCopy := k
		vCopy := v
		preventionSettings = append(preventionSettings, &models.PreventionSettingReqV1{
			ID: &kCopy,
			Value: apiMlSlider{
				Detection: vCopy.Detection.ValueString(),
			},
		})
	}

	return preventionSettings
}

// assignPreventionSettings assigns the prevention settings returned from the api into the resource model.
func (m *defaultPreventionPolicyWindowsResourceModel) assignPreventionSettings(
	categories []*models.PreventionCategoryRespV1,
) {
	toggleSettings, mlSliderSettings, detectionMlSliderSettings := mapPreventionSettings(categories)

	// toggle settings
	m.AdditionalUserModeData = defaultBoolFalse(toggleSettings["AdditionalUserModeData"])
	m.EndUserNotifications = defaultBoolFalse(toggleSettings["EndUserNotifications"])
	m.UnknownDetectionRelatedExecutables = defaultBoolFalse(
		toggleSettings["UnknownDetectionRelatedExecutables"],
	)
	m.UnknownExecutables = defaultBoolFalse(toggleSettings["UnknownExecutables"])
	m.SensorTamperingProtection = defaultBoolFalse(toggleSettings["SensorTamperingProtection"])
	m.InterpreterProtection = defaultBoolFalse(toggleSettings["InterpreterProtection"])
	m.EngineProtectionV2 = defaultBoolFalse(toggleSettings["EngineProtectionV2"])
	m.ScriptBasedExecutionMonitoring = defaultBoolFalse(
		toggleSettings["ScriptBasedExecutionMonitoring"],
	)
	m.HTTPDetections = defaultBoolFalse(toggleSettings["HTTPDetections"])
	m.RedactHTTPDetectionDetails = defaultBoolFalse(
		toggleSettings["RedactHTTPDetectionDetails"],
	)
	m.HardwareEnhancedExploitDetection = defaultBoolFalse(
		toggleSettings["HardwareEnhancedExploitDetection"],
	)
	m.EnhancedExploitationVisibility = defaultBoolFalse(
		toggleSettings["EnhancedExploitationVisibility"],
	)
	m.DLLLoadVisibility = defaultBoolFalse(toggleSettings["DLLLoadVisibility"])
	m.MemoryScan = defaultBoolFalse(toggleSettings["MemoryScan"])
	m.CPUMemoryScan = defaultBoolFalse(toggleSettings["CPUMemoryScan"])
	m.FirmwareAnalysisExtraction = defaultBoolFalse(
		toggleSettings["FirmwareAnalysisExtraction"],
	)
	m.MLLargeFileHandling = defaultBoolFalse(toggleSettings["ML Large File Handling"])
	m.USBInsertionTriggeredScan = defaultBoolFalse(toggleSettings["USBInsertionTriggeredScan"])
	m.DetectOnWrite = defaultBoolFalse(toggleSettings["DetectOnWrite"])
	m.QuarantineOnWrite = defaultBoolFalse(toggleSettings["QuarantineOnWrite"])
	m.OnWriteScriptFileVisibility = defaultBoolFalse(
		toggleSettings["OnWriteScriptFileVisibility"],
	)
	m.NextGenAV = defaultBoolFalse(toggleSettings["NextGenAV"])
	m.NextGenAVQuarantineOnRemovableMedia = defaultBoolFalse(
		toggleSettings["NextGenAVQuarantineOnRemovableMedia"],
	)
	m.MicrosoftOfficeFileSuspiciousMacroRemoval = defaultBoolFalse(
		toggleSettings["MicrosoftOfficeFileSuspiciousMacroRemoval"],
	)
	m.CustomBlacklisting = defaultBoolFalse(toggleSettings["CustomBlacklisting"])
	m.PreventSuspiciousProcesses = defaultBoolFalse(
		toggleSettings["PreventSuspiciousProcesses"],
	)
	m.SuspiciousRegistryOperations = defaultBoolFalse(
		toggleSettings["SuspiciousRegistryOperations"],
	)
	m.MaliciousPowershell = defaultBoolFalse(toggleSettings["MaliciousPowershell"])
	m.IntelPrevention = defaultBoolFalse(toggleSettings["IntelPrevention"])
	m.SuspiciousKernelDrivers = defaultBoolFalse(toggleSettings["SuspiciousKernelDrivers"])
	m.VulnerableDriverProtection = defaultBoolFalse(
		toggleSettings["VulnerableDriverProtection"],
	)
	m.ForceASLR = defaultBoolFalse(toggleSettings["ForceASLR"])
	m.ForceDEP = defaultBoolFalse(toggleSettings["ForceDEP"])
	m.HeapSprayPreallocation = defaultBoolFalse(toggleSettings["HeapSprayPreallocation"])
	m.NullPageAllocation = defaultBoolFalse(toggleSettings["NullPageAllocation"])
	m.SEHOverwriteProtection = defaultBoolFalse(toggleSettings["SEHOverwriteProtection"])
	m.BackupDeletion = defaultBoolFalse(toggleSettings["BackupDeletion"])
	m.Cryptowall = defaultBoolFalse(toggleSettings["Cryptowall"])
	m.FileEncryption = defaultBoolFalse(toggleSettings["FileEncryption"])
	m.Locky = defaultBoolFalse(toggleSettings["Locky"])
	m.FileSystemAccess = defaultBoolFalse(toggleSettings["FileSystemAccess"])
	m.VolumeShadowCopyAudit = defaultBoolFalse(toggleSettings["VolumeShadowCopyAudit"])
	m.VolumeShadowCopyProtect = defaultBoolFalse(toggleSettings["VolumeShadowCopyProtect"])
	m.ApplicationExploitationActivity = defaultBoolFalse(
		toggleSettings["ApplicationExploitationActivity"],
	)
	m.ChopperWebshell = defaultBoolFalse(toggleSettings["ChopperWebshell"])
	m.DriveByDownload = defaultBoolFalse(toggleSettings["DriveByDownload"])
	m.ProcessHollowing = defaultBoolFalse(toggleSettings["ProcessHollowing"])
	m.JavaScriptViaRundll32 = defaultBoolFalse(toggleSettings["JavaScriptViaRundll32"])
	m.WindowsLogonBypassStickyKeys = defaultBoolFalse(
		toggleSettings["WindowsLogonBypassStickyKeys"],
	)
	m.CredentialDumping = defaultBoolFalse(toggleSettings["CredentialDumping"])
	m.AutomatedRemediation = defaultBoolFalse(toggleSettings["AutomatedRemediation"])
	m.FileSystemContainmentEnabled = defaultBoolFalse(
		toggleSettings["FileSystemContainmentEnabled"],
	)

	// mlslider settings
	m.ExtendedUserModeDataSlider = detectionMlSliderSettings["ExtendedUserModeDataSlider"]
	m.CloudAntiMalwareForMicrosoftOfficeFiles = mlSliderSettings["CloudAntiMalwareForMicrosoftOfficeFiles"]
	m.CloudAntiMalware = mlSliderSettings["CloudAntiMalware"]
	m.AdwarePUP = mlSliderSettings["AdwarePUP"]
	m.OnSensorMLSlider = mlSliderSettings["OnSensorMLSlider"]
	m.OnSensorMLSliderForSensorEndUserScans = mlSliderSettings["OnSensorMLSliderForSensorEndUserScans"]
	m.OnSensorMLSliderForCloudEndUserScans = mlSliderSettings["OnSensorMLSliderForCloudEndUserScans"]
}

func (r *defaultPreventionPolicyWindowsResource) Configure(
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

func (r *defaultPreventionPolicyWindowsResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_default_prevention_policy_windows"
}

func (r *defaultPreventionPolicyWindowsResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = generateWindowsSchema(true)
}

func (r *defaultPreventionPolicyWindowsResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan defaultPreventionPolicyWindowsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := getDefaultPolicy(ctx, r.client, windowsPlatformName)
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

	emptySet, diags := types.SetValueFrom(ctx, types.StringType, []string{})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		syncRuleGroups(ctx, r.client, plan.RuleGroups, emptySet, plan.ID.ValueString())...)
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

func (r *defaultPreventionPolicyWindowsResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state defaultPreventionPolicyWindowsResourceModel
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

func (r *defaultPreventionPolicyWindowsResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan defaultPreventionPolicyWindowsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state defaultPreventionPolicyWindowsResourceModel
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

func (r *defaultPreventionPolicyWindowsResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	// we can not delete a default resource so we do nothing.
}

func (r *defaultPreventionPolicyWindowsResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *defaultPreventionPolicyWindowsResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config defaultPreventionPolicyWindowsResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(utils.ValidateEmptyIDs(ctx, config.RuleGroups, "ioa_rule_groups")...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.ProcessHollowing.ValueBool(),
			config.AdditionalUserModeData.ValueBool(),
			"code_injection",
			"additional_user_mode_data",
		)...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.ForceASLR.ValueBool(),
			config.AdditionalUserModeData.ValueBool(),
			"force_aslr",
			"additional_user_mode_data",
		)...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.ForceDEP.ValueBool(),
			config.AdditionalUserModeData.ValueBool(),
			"force_dep",
			"additional_user_mode_data",
		)...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.HeapSprayPreallocation.ValueBool(),
			config.AdditionalUserModeData.ValueBool(),
			"heap_spray_preallocation",
			"additional_user_mode_data",
		)...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.NullPageAllocation.ValueBool(),
			config.AdditionalUserModeData.ValueBool(),
			"null_page_allocation",
			"additional_user_mode_data",
		)...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.CredentialDumping.ValueBool(),
			config.AdditionalUserModeData.ValueBool(),
			"credential_dumping",
			"additional_user_mode_data",
		)...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.SEHOverwriteProtection.ValueBool(),
			config.AdditionalUserModeData.ValueBool(),
			"seh_overwrite_protection",
			"additional_user_mode_data",
		)...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.EngineProtectionV2.ValueBool(),
			config.InterpreterProtection.ValueBool(),
			"engine_full_visibility",
			"interpreter_only",
		)...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.CPUMemoryScan.ValueBool(),
			config.MemoryScan.ValueBool(),
			"memory_scanning_scan_with_cpu",
			"memory_scanning",
		)...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.VolumeShadowCopyProtect.ValueBool(),
			config.VolumeShadowCopyAudit.ValueBool(),
			"volume_shadow_copy_protect",
			"volume_shadow_copy_audit",
		)...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.VulnerableDriverProtection.ValueBool(),
			config.SuspiciousKernelDrivers.ValueBool(),
			"vulnerable_driver_protection",
			"driver_load_prevention",
		)...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.QuarantineOnWrite.ValueBool(),
			(config.NextGenAV.ValueBool() && config.DetectOnWrite.ValueBool()),
			"quarantine_on_write",
			"quarantine_and_security_center_registration and detect_on_write",
		)...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.ScriptBasedExecutionMonitoring.ValueBool(),
			config.NextGenAV.ValueBool(),
			"script_based_execution_monitoring",
			"quarantine_and_security_center_registration",
		)...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.MaliciousPowershell.ValueBool(),
			(config.InterpreterProtection.ValueBool() || config.ScriptBasedExecutionMonitoring.ValueBool()),
			"suspicious_scripts_and_commands",
			"interpreter_only or script_based_execution_monitoring",
		)...)

	if config.USBInsertionTriggeredScan.ValueBool() {
		sensorDetection := "DISABLED"
		cloudDetection := "DISABLED"

		if config.OnSensorMLSliderForCloudEndUserScans != nil {
			sensorDetection = config.OnSensorMLSliderForCloudEndUserScans.Detection.ValueString()
		}

		if config.OnSensorMLSliderForCloudEndUserScans != nil {
			cloudDetection = config.OnSensorMLSliderForCloudEndUserScans.Detection.ValueString()
		}

		if sensorDetection == "DISABLED" && cloudDetection == "DISABLED" {
			resp.Diagnostics.AddAttributeError(
				path.Root("usb_insertion_triggered_scan"),
				"requirements not met to enable usb_insertion_triggered_scan",
				"Either sensor_anti_malware_user_initiated or cloud_anti_malware_user_initiated detection must be a level higher than DISABLED to enable usb_insertion_triggered_scan",
			)
		}
	}

	if config.CloudAntiMalwareForMicrosoftOfficeFiles != nil {
		resp.Diagnostics.Append(
			validateMlSlider(
				"cloud_anti_malware_microsoft_office_files",
				*config.CloudAntiMalwareForMicrosoftOfficeFiles,
			)...)
	}

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
				"adware_and_pup",
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

	if config.OnSensorMLSliderForSensorEndUserScans != nil {
		resp.Diagnostics.Append(
			validateMlSlider(
				"sensor_anti_malware_user_initiated",
				*config.OnSensorMLSliderForSensorEndUserScans,
			)...)
	}

	if config.OnSensorMLSliderForCloudEndUserScans != nil {
		resp.Diagnostics.Append(
			validateMlSlider(
				"cloud_anti_malware_user_initiated",
				*config.OnSensorMLSliderForCloudEndUserScans,
			)...)
	}

}
