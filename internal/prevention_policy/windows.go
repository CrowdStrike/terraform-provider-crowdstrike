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
	_ resource.Resource                   = &preventionPolicyWindowsResource{}
	_ resource.ResourceWithConfigure      = &preventionPolicyWindowsResource{}
	_ resource.ResourceWithImportState    = &preventionPolicyWindowsResource{}
	_ resource.ResourceWithValidateConfig = &preventionPolicyWindowsResource{}
)

// NewPreventionPolicyWindowsResource is a helper function to simplify the provider implementation.
func NewPreventionPolicyWindowsResource() resource.Resource {
	return &preventionPolicyWindowsResource{}
}

// preventionPolicyWindowsResource is the resource implementation.
type preventionPolicyWindowsResource struct {
	client *client.CrowdStrikeAPISpecification
}

// preventionPolicyWindowsResourceModel is the resource implementation.
type preventionPolicyWindowsResourceModel struct {
	ID                                         types.String `tfsdk:"id"`
	Enabled                                    types.Bool   `tfsdk:"enabled"`
	Name                                       types.String `tfsdk:"name"`
	Description                                types.String `tfsdk:"description"`
	HostGroups                                 types.Set    `tfsdk:"host_groups"`
	RuleGroups                                 types.Set    `tfsdk:"ioa_rule_groups"`
	LastUpdated                                types.String `tfsdk:"last_updated"`
	CloudAntiMalwareForMicrosoftOfficeFiles    types.Object `tfsdk:"cloud_anti_malware_microsoft_office_files"`
	ExtendedUserModeDataSlider                 types.Object `tfsdk:"extended_user_mode_data"`
	CloudAntiMalware                           types.Object `tfsdk:"cloud_anti_malware"`
	AdwarePUP                                  types.Object `tfsdk:"adware_and_pup"`
	OnSensorMLSlider                           types.Object `tfsdk:"sensor_anti_malware"`
	OnSensorMLSliderForSensorEndUserScans      types.Object `tfsdk:"sensor_anti_malware_user_initiated"`
	OnSensorMLSliderForCloudEndUserScans       types.Object `tfsdk:"cloud_anti_malware_user_initiated"`
	CloudMLSliderForPupAdwareCloudEndUserScans types.Object `tfsdk:"cloud_adware_pup_user_initiated"`
	AdditionalUserModeData                     types.Bool   `tfsdk:"additional_user_mode_data"`
	EndUserNotifications                       types.Bool   `tfsdk:"notify_end_users"`
	UnknownDetectionRelatedExecutables         types.Bool   `tfsdk:"upload_unknown_detection_related_executables"`
	UnknownExecutables                         types.Bool   `tfsdk:"upload_unknown_executables"`
	SensorTamperingProtection                  types.Bool   `tfsdk:"sensor_tampering_protection"`
	InterpreterProtection                      types.Bool   `tfsdk:"interpreter_only"`
	EngineProtectionV2                         types.Bool   `tfsdk:"engine_full_visibility"`
	ScriptBasedExecutionMonitoring             types.Bool   `tfsdk:"script_based_execution_monitoring"`
	HTTPDetections                             types.Bool   `tfsdk:"http_detections"`
	RedactHTTPDetectionDetails                 types.Bool   `tfsdk:"redact_http_detection_details"`
	HardwareEnhancedExploitDetection           types.Bool   `tfsdk:"hardware_enhanced_exploit_detection"`
	EnhancedExploitationVisibility             types.Bool   `tfsdk:"enhanced_exploitation_visibility"`
	DLLLoadVisibility                          types.Bool   `tfsdk:"enhanced_dll_load_visibility"`
	MemoryScan                                 types.Bool   `tfsdk:"memory_scanning"`
	CPUMemoryScan                              types.Bool   `tfsdk:"memory_scanning_scan_with_cpu"`
	FirmwareAnalysisExtraction                 types.Bool   `tfsdk:"bios_deep_visibility"`
	MLLargeFileHandling                        types.Bool   `tfsdk:"enhanced_ml_for_larger_files"`
	USBInsertionTriggeredScan                  types.Bool   `tfsdk:"usb_insertion_triggered_scan"`
	DetectOnWrite                              types.Bool   `tfsdk:"detect_on_write"`
	QuarantineOnWrite                          types.Bool   `tfsdk:"quarantine_on_write"`
	OnWriteScriptFileVisibility                types.Bool   `tfsdk:"on_write_script_file_visibility"`
	NextGenAV                                  types.Bool   `tfsdk:"quarantine_and_security_center_registration"`
	NextGenAVQuarantineOnRemovableMedia        types.Bool   `tfsdk:"quarantine_on_removable_media"`
	MicrosoftOfficeFileSuspiciousMacroRemoval  types.Bool   `tfsdk:"microsoft_office_file_suspicious_macro_removal"`
	CustomBlacklisting                         types.Bool   `tfsdk:"custom_blocking"`
	PreventSuspiciousProcesses                 types.Bool   `tfsdk:"prevent_suspicious_processes"`
	SuspiciousRegistryOperations               types.Bool   `tfsdk:"suspicious_registry_operations"`
	MaliciousPowershell                        types.Bool   `tfsdk:"suspicious_scripts_and_commands"`
	IntelPrevention                            types.Bool   `tfsdk:"intelligence_sourced_threats"`
	SuspiciousKernelDrivers                    types.Bool   `tfsdk:"driver_load_prevention"`
	VulnerableDriverProtection                 types.Bool   `tfsdk:"vulnerable_driver_protection"`
	ForceASLR                                  types.Bool   `tfsdk:"force_aslr"`
	ForceDEP                                   types.Bool   `tfsdk:"force_dep"`
	HeapSprayPreallocation                     types.Bool   `tfsdk:"heap_spray_preallocation"`
	NullPageAllocation                         types.Bool   `tfsdk:"null_page_allocation"`
	SEHOverwriteProtection                     types.Bool   `tfsdk:"seh_overwrite_protection"`
	BackupDeletion                             types.Bool   `tfsdk:"backup_deletion"`
	Cryptowall                                 types.Bool   `tfsdk:"cryptowall"`
	FileEncryption                             types.Bool   `tfsdk:"file_encryption"`
	Locky                                      types.Bool   `tfsdk:"locky"`
	FileSystemAccess                           types.Bool   `tfsdk:"file_system_access"`
	VolumeShadowCopyAudit                      types.Bool   `tfsdk:"volume_shadow_copy_audit"`
	VolumeShadowCopyProtect                    types.Bool   `tfsdk:"volume_shadow_copy_protect"`
	ApplicationExploitationActivity            types.Bool   `tfsdk:"application_exploitation_activity"`
	ChopperWebshell                            types.Bool   `tfsdk:"chopper_webshell"`
	DriveByDownload                            types.Bool   `tfsdk:"drive_by_download"`
	ProcessHollowing                           types.Bool   `tfsdk:"code_injection"`
	JavaScriptViaRundll32                      types.Bool   `tfsdk:"javascript_via_rundll32"`
	WindowsLogonBypassStickyKeys               types.Bool   `tfsdk:"windows_logon_bypass_sticky_keys"`
	CredentialDumping                          types.Bool   `tfsdk:"credential_dumping"`
	AutomatedRemediation                       types.Bool   `tfsdk:"advanced_remediation"`
	FileSystemContainmentEnabled               types.Bool   `tfsdk:"file_system_containment"`
	BootConfigurationDatabaseProtection        types.Bool   `tfsdk:"boot_configuration_database_protection"`
	WSL2Visibility                             types.Bool   `tfsdk:"wsl2_visibility"`
}

// Configure adds the provider configured client to the resource.
func (r *preventionPolicyWindowsResource) Configure(
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
func (r *preventionPolicyWindowsResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_prevention_policy_windows"
}

// Schema defines the schema for the resource.
func (r *preventionPolicyWindowsResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = generateWindowsSchema(false)
}

// Create creates the resource and sets the initial Terraform state.
func (r *preventionPolicyWindowsResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {

	var plan preventionPolicyWindowsResourceModel
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
		windowsPlatformName,
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
func (r *preventionPolicyWindowsResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state preventionPolicyWindowsResourceModel
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
func (r *preventionPolicyWindowsResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	// Retrieve values from plan
	var plan preventionPolicyWindowsResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Retrieve values from state
	var state preventionPolicyWindowsResourceModel
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
func (r *preventionPolicyWindowsResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state preventionPolicyWindowsResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := state.ID.ValueString()

	resp.Diagnostics.Append(deletePreventionPolicy(ctx, r.client, id)...)
}

// ImportState implements the logic to support resource imports.
func (r *preventionPolicyWindowsResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	// Retrieve import ID and save to id attribute
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ValidateConfig runs during validate, plan, and apply
// validate resource is configured as expected.
func (r *preventionPolicyWindowsResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config preventionPolicyWindowsResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(utils.ValidateEmptyIDs(ctx, config.HostGroups, "host_groups")...)
	resp.Diagnostics.Append(utils.ValidateEmptyIDs(ctx, config.RuleGroups, "ioa_rule_groups")...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.ProcessHollowing,
			config.AdditionalUserModeData,
			"code_injection",
			"additional_user_mode_data",
		)...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.ForceASLR,
			config.AdditionalUserModeData,
			"force_aslr",
			"additional_user_mode_data",
		)...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.ForceDEP,
			config.AdditionalUserModeData,
			"force_dep",
			"additional_user_mode_data",
		)...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.HeapSprayPreallocation,
			config.AdditionalUserModeData,
			"heap_spray_preallocation",
			"additional_user_mode_data",
		)...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.NullPageAllocation,
			config.AdditionalUserModeData,
			"null_page_allocation",
			"additional_user_mode_data",
		)...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.CredentialDumping,
			config.AdditionalUserModeData,
			"credential_dumping",
			"additional_user_mode_data",
		)...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.SEHOverwriteProtection,
			config.AdditionalUserModeData,
			"seh_overwrite_protection",
			"additional_user_mode_data",
		)...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.EngineProtectionV2,
			config.InterpreterProtection,
			"engine_full_visibility",
			"interpreter_only",
		)...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.CPUMemoryScan,
			config.MemoryScan,
			"memory_scanning_scan_with_cpu",
			"memory_scanning",
		)...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.VolumeShadowCopyProtect,
			config.VolumeShadowCopyAudit,
			"volume_shadow_copy_protect",
			"volume_shadow_copy_audit",
		)...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.VulnerableDriverProtection,
			config.SuspiciousKernelDrivers,
			"vulnerable_driver_protection",
			"driver_load_prevention",
		)...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.QuarantineOnWrite,
			config.NextGenAV,
			"quarantine_on_write",
			"quarantine_and_security_center_registration",
		)...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.QuarantineOnWrite,
			config.DetectOnWrite,
			"quarantine_on_write",
			"detect_on_write",
		)...)

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.ScriptBasedExecutionMonitoring,
			config.NextGenAV,
			"script_based_execution_monitoring",
			"quarantine_and_security_center_registration",
		)...)

	interpDiags := validateRequiredAttribute(
		config.MaliciousPowershell,
		config.InterpreterProtection,
		"suspicious_scripts_and_commands",
		"interpreter_only",
	)

	scriptDiags := validateRequiredAttribute(
		config.MaliciousPowershell,
		config.ScriptBasedExecutionMonitoring,
		"suspicious_scripts_and_commands",
		"script_based_execution_monitoring",
	)

	if interpDiags.HasError() && scriptDiags.HasError() {
		resp.Diagnostics.Append(validateRequiredAttribute(
			config.MaliciousPowershell,
			types.BoolValue(false),
			"suspicious_scripts_and_commands",
			"interpreter_only or script_based_execution_monitoring",
		)...)
	}

	if utils.IsKnown(config.USBInsertionTriggeredScan) && config.USBInsertionTriggeredScan.ValueBool() {
		sensorDetection := "DISABLED"
		cloudDetection := "DISABLED"

		if utils.IsKnown(config.OnSensorMLSliderForSensorEndUserScans) {
			var slider mlSlider
			if diagsSlider := config.OnSensorMLSliderForSensorEndUserScans.As(ctx, &slider, basetypes.ObjectAsOptions{}); !diagsSlider.HasError() {
				sensorDetection = slider.Detection.ValueString()
			}
		}

		if utils.IsKnown(config.OnSensorMLSliderForCloudEndUserScans) {
			var slider mlSlider
			if diagsSlider := config.OnSensorMLSliderForCloudEndUserScans.As(ctx, &slider, basetypes.ObjectAsOptions{}); !diagsSlider.HasError() {
				cloudDetection = slider.Detection.ValueString()
			}
		}

		if sensorDetection == "DISABLED" && cloudDetection == "DISABLED" {
			resp.Diagnostics.AddAttributeError(
				path.Root("usb_insertion_triggered_scan"),
				"requirements not met to enable usb_insertion_triggered_scan",
				"Either sensor_anti_malware_user_initiated or cloud_anti_malware_user_initiated detection must be a level higher than DISABLED to enable usb_insertion_triggered_scan",
			)
		}
	}

	resp.Diagnostics.Append(
		validateRequiredAttribute(
			config.BootConfigurationDatabaseProtection,
			config.SuspiciousRegistryOperations,
			"boot_configuration_database_protection",
			"suspicious_registry_operations",
		)...)

	if utils.IsKnown(config.CloudAntiMalwareForMicrosoftOfficeFiles) {
		var slider mlSlider
		if diagsSlider := config.CloudAntiMalwareForMicrosoftOfficeFiles.As(ctx, &slider, basetypes.ObjectAsOptions{}); !diagsSlider.HasError() {
			resp.Diagnostics.Append(
				validateMlSlider(
					"cloud_anti_malware_microsoft_office_files",
					slider,
				)...)
		}
	}

	if utils.IsKnown(config.CloudAntiMalware) {
		var slider mlSlider
		if diagsSlider := config.CloudAntiMalware.As(ctx, &slider, basetypes.ObjectAsOptions{}); !diagsSlider.HasError() {
			resp.Diagnostics.Append(
				validateMlSlider(
					"cloud_anti_malware",
					slider,
				)...)
		}
	}

	if utils.IsKnown(config.AdwarePUP) {
		var slider mlSlider
		if diagsSlider := config.AdwarePUP.As(ctx, &slider, basetypes.ObjectAsOptions{}); !diagsSlider.HasError() {
			resp.Diagnostics.Append(
				validateMlSlider(
					"adware_and_pup",
					slider,
				)...)
		}
	}

	if utils.IsKnown(config.OnSensorMLSlider) {
		var slider mlSlider
		if diagsSlider := config.OnSensorMLSlider.As(ctx, &slider, basetypes.ObjectAsOptions{}); !diagsSlider.HasError() {
			resp.Diagnostics.Append(
				validateMlSlider(
					"sensor_anti_malware",
					slider,
				)...)
		}
	}

	if utils.IsKnown(config.OnSensorMLSliderForSensorEndUserScans) {
		var slider mlSlider
		if diagsSlider := config.OnSensorMLSliderForSensorEndUserScans.As(ctx, &slider, basetypes.ObjectAsOptions{}); !diagsSlider.HasError() {
			resp.Diagnostics.Append(
				validateMlSlider(
					"sensor_anti_malware_user_initiated",
					slider,
				)...)
		}
	}

	if utils.IsKnown(config.OnSensorMLSliderForCloudEndUserScans) {
		var slider mlSlider
		if diagsSlider := config.OnSensorMLSliderForCloudEndUserScans.As(ctx, &slider, basetypes.ObjectAsOptions{}); !diagsSlider.HasError() {
			resp.Diagnostics.Append(
				validateMlSlider(
					"cloud_anti_malware_user_initiated",
					slider,
				)...)
		}
	}

	if utils.IsKnown(config.CloudMLSliderForPupAdwareCloudEndUserScans) {
		var slider mlSlider
		if diagsSlider := config.CloudMLSliderForPupAdwareCloudEndUserScans.As(ctx, &slider, basetypes.ObjectAsOptions{}); !diagsSlider.HasError() {
			resp.Diagnostics.Append(
				validateMlSlider(
					"cloud_adware_pup_user_initiated",
					slider,
				)...)
		}
	}
}

// assignRuleGroups assigns the rule groups returned from the api into the resource model.
func (r *preventionPolicyWindowsResource) assignRuleGroups(
	ctx context.Context,
	config *preventionPolicyWindowsResourceModel,
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
func (r *preventionPolicyWindowsResource) assignHostGroups(
	ctx context.Context,
	config *preventionPolicyWindowsResourceModel,
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
func (r *preventionPolicyWindowsResource) assignPreventionSettings(
	ctx context.Context,
	state *preventionPolicyWindowsResourceModel,
	categories []*models.PreventionCategoryRespV1,
) diag.Diagnostics {
	var diags diag.Diagnostics
	toggleSettings, mlSliderSettings, detectionMlSliderSettings := mapPreventionSettings(categories)

	// toggle settings
	state.AdditionalUserModeData = defaultBoolFalse(toggleSettings["AdditionalUserModeData"])
	state.EndUserNotifications = defaultBoolFalse(toggleSettings["EndUserNotifications"])
	state.UnknownDetectionRelatedExecutables = defaultBoolFalse(
		toggleSettings["UnknownDetectionRelatedExecutables"],
	)
	state.UnknownExecutables = defaultBoolFalse(toggleSettings["UnknownExecutables"])
	state.SensorTamperingProtection = defaultBoolFalse(toggleSettings["SensorTamperingProtection"])
	state.InterpreterProtection = defaultBoolFalse(toggleSettings["InterpreterProtection"])
	state.EngineProtectionV2 = defaultBoolFalse(toggleSettings["EngineProtectionV2"])
	state.ScriptBasedExecutionMonitoring = defaultBoolFalse(
		toggleSettings["ScriptBasedExecutionMonitoring"],
	)
	state.HTTPDetections = defaultBoolFalse(toggleSettings["HTTPDetections"])
	state.RedactHTTPDetectionDetails = defaultBoolFalse(
		toggleSettings["RedactHTTPDetectionDetails"],
	)
	state.HardwareEnhancedExploitDetection = defaultBoolFalse(
		toggleSettings["HardwareEnhancedExploitDetection"],
	)
	state.EnhancedExploitationVisibility = defaultBoolFalse(
		toggleSettings["EnhancedExploitationVisibility"],
	)
	state.DLLLoadVisibility = defaultBoolFalse(toggleSettings["DLLLoadVisibility"])
	state.MemoryScan = defaultBoolFalse(toggleSettings["MemoryScan"])
	state.CPUMemoryScan = defaultBoolFalse(toggleSettings["CPUMemoryScan"])
	state.FirmwareAnalysisExtraction = defaultBoolFalse(
		toggleSettings["FirmwareAnalysisExtraction"],
	)
	state.MLLargeFileHandling = defaultBoolFalse(toggleSettings["ML Large File Handling"])
	state.USBInsertionTriggeredScan = defaultBoolFalse(toggleSettings["USBInsertionTriggeredScan"])
	state.DetectOnWrite = defaultBoolFalse(toggleSettings["DetectOnWrite"])
	state.QuarantineOnWrite = defaultBoolFalse(toggleSettings["QuarantineOnWrite"])
	state.OnWriteScriptFileVisibility = defaultBoolFalse(
		toggleSettings["OnWriteScriptFileVisibility"],
	)
	state.NextGenAV = defaultBoolFalse(toggleSettings["NextGenAV"])
	state.NextGenAVQuarantineOnRemovableMedia = defaultBoolFalse(
		toggleSettings["NextGenAVQuarantineOnRemovableMedia"],
	)
	state.MicrosoftOfficeFileSuspiciousMacroRemoval = defaultBoolFalse(
		toggleSettings["MicrosoftOfficeFileSuspiciousMacroRemoval"],
	)
	state.CustomBlacklisting = defaultBoolFalse(toggleSettings["CustomBlacklisting"])
	state.PreventSuspiciousProcesses = defaultBoolFalse(
		toggleSettings["PreventSuspiciousProcesses"],
	)
	state.SuspiciousRegistryOperations = defaultBoolFalse(
		toggleSettings["SuspiciousRegistryOperations"],
	)
	state.MaliciousPowershell = defaultBoolFalse(toggleSettings["MaliciousPowershell"])
	state.IntelPrevention = defaultBoolFalse(toggleSettings["IntelPrevention"])
	state.SuspiciousKernelDrivers = defaultBoolFalse(toggleSettings["SuspiciousKernelDrivers"])
	state.VulnerableDriverProtection = defaultBoolFalse(
		toggleSettings["VulnerableDriverProtection"],
	)
	state.ForceASLR = defaultBoolFalse(toggleSettings["ForceASLR"])
	state.ForceDEP = defaultBoolFalse(toggleSettings["ForceDEP"])
	state.HeapSprayPreallocation = defaultBoolFalse(toggleSettings["HeapSprayPreallocation"])
	state.NullPageAllocation = defaultBoolFalse(toggleSettings["NullPageAllocation"])
	state.SEHOverwriteProtection = defaultBoolFalse(toggleSettings["SEHOverwriteProtection"])
	state.BackupDeletion = defaultBoolFalse(toggleSettings["BackupDeletion"])
	state.Cryptowall = defaultBoolFalse(toggleSettings["Cryptowall"])
	state.FileEncryption = defaultBoolFalse(toggleSettings["FileEncryption"])
	state.Locky = defaultBoolFalse(toggleSettings["Locky"])
	state.FileSystemAccess = defaultBoolFalse(toggleSettings["FileSystemAccess"])
	state.VolumeShadowCopyAudit = defaultBoolFalse(toggleSettings["VolumeShadowCopyAudit"])
	state.VolumeShadowCopyProtect = defaultBoolFalse(toggleSettings["VolumeShadowCopyProtect"])
	state.ApplicationExploitationActivity = defaultBoolFalse(
		toggleSettings["ApplicationExploitationActivity"],
	)
	state.ChopperWebshell = defaultBoolFalse(toggleSettings["ChopperWebshell"])
	state.DriveByDownload = defaultBoolFalse(toggleSettings["DriveByDownload"])
	state.ProcessHollowing = defaultBoolFalse(toggleSettings["ProcessHollowing"])
	state.JavaScriptViaRundll32 = defaultBoolFalse(toggleSettings["JavaScriptViaRundll32"])
	state.WindowsLogonBypassStickyKeys = defaultBoolFalse(
		toggleSettings["WindowsLogonBypassStickyKeys"],
	)
	state.CredentialDumping = defaultBoolFalse(toggleSettings["CredentialDumping"])
	state.AutomatedRemediation = defaultBoolFalse(toggleSettings["AutomatedRemediation"])
	state.FileSystemContainmentEnabled = defaultBoolFalse(
		toggleSettings["FileSystemContainmentEnabled"],
	)
	state.BootConfigurationDatabaseProtection = defaultBoolFalse(
		toggleSettings["BootConfigurationDatabaseProtection"],
	)
	state.WSL2Visibility = defaultBoolFalse(toggleSettings["WSL2Visibility"])

	// mlslider settings
	if detectionSlider, ok := detectionMlSliderSettings["ExtendedUserModeDataSlider"]; ok {
		extendedUserModeData, diagsExt := types.ObjectValueFrom(
			ctx,
			detectionMlSlider{}.AttributeTypes(),
			detectionSlider,
		)
		diags.Append(diagsExt...)
		if diags.HasError() {
			return diags
		}
		state.ExtendedUserModeDataSlider = extendedUserModeData
	}

	if slider, ok := mlSliderSettings["CloudAntiMalwareForMicrosoftOfficeFiles"]; ok {
		objValue, diagsObj := types.ObjectValueFrom(ctx, mlSlider{}.AttributeTypes(), slider)
		diags.Append(diagsObj...)
		if diags.HasError() {
			return diags
		}
		state.CloudAntiMalwareForMicrosoftOfficeFiles = objValue
	}

	if slider, ok := mlSliderSettings["CloudAntiMalware"]; ok {
		objValue, diagsObj := types.ObjectValueFrom(ctx, mlSlider{}.AttributeTypes(), slider)
		diags.Append(diagsObj...)
		if diags.HasError() {
			return diags
		}
		state.CloudAntiMalware = objValue
	}

	if slider, ok := mlSliderSettings["AdwarePUP"]; ok {
		objValue, diagsObj := types.ObjectValueFrom(ctx, mlSlider{}.AttributeTypes(), slider)
		diags.Append(diagsObj...)
		if diags.HasError() {
			return diags
		}
		state.AdwarePUP = objValue
	}

	if slider, ok := mlSliderSettings["OnSensorMLSlider"]; ok {
		objValue, diagsObj := types.ObjectValueFrom(ctx, mlSlider{}.AttributeTypes(), slider)
		diags.Append(diagsObj...)
		if diags.HasError() {
			return diags
		}
		state.OnSensorMLSlider = objValue
	}

	if slider, ok := mlSliderSettings["OnSensorMLSliderForSensorEndUserScans"]; ok {
		objValue, diagsObj := types.ObjectValueFrom(ctx, mlSlider{}.AttributeTypes(), slider)
		diags.Append(diagsObj...)
		if diags.HasError() {
			return diags
		}
		state.OnSensorMLSliderForSensorEndUserScans = objValue
	}

	if slider, ok := mlSliderSettings["OnSensorMLSliderForCloudEndUserScans"]; ok {
		objValue, diagsObj := types.ObjectValueFrom(ctx, mlSlider{}.AttributeTypes(), slider)
		diags.Append(diagsObj...)
		if diags.HasError() {
			return diags
		}
		state.OnSensorMLSliderForCloudEndUserScans = objValue
	}

	if slider, ok := mlSliderSettings["CloudMLSliderForPupAdwareCloudEndUserScans"]; ok {
		objValue, diagsObj := types.ObjectValueFrom(ctx, mlSlider{}.AttributeTypes(), slider)
		diags.Append(diagsObj...)
		if diags.HasError() {
			return diags
		}
		state.CloudMLSliderForPupAdwareCloudEndUserScans = objValue
	}

	return diags
}

// generatePreventionSettings maps plan prevention settings to api params for create and update.
func (r *preventionPolicyWindowsResource) generatePreventionSettings(
	ctx context.Context,
	config preventionPolicyWindowsResourceModel,
) ([]*models.PreventionSettingReqV1, diag.Diagnostics) {
	preventionSettings := []*models.PreventionSettingReqV1{}
	var diags diag.Diagnostics

	toggleSettings := map[string]types.Bool{
		"AdditionalUserModeData":                    config.AdditionalUserModeData,
		"EndUserNotifications":                      config.EndUserNotifications,
		"UnknownDetectionRelatedExecutables":        config.UnknownDetectionRelatedExecutables,
		"UnknownExecutables":                        config.UnknownExecutables,
		"SensorTamperingProtection":                 config.SensorTamperingProtection,
		"InterpreterProtection":                     config.InterpreterProtection,
		"EngineProtectionV2":                        config.EngineProtectionV2,
		"ScriptBasedExecutionMonitoring":            config.ScriptBasedExecutionMonitoring,
		"HTTPDetections":                            config.HTTPDetections,
		"RedactHTTPDetectionDetails":                config.RedactHTTPDetectionDetails,
		"HardwareEnhancedExploitDetection":          config.HardwareEnhancedExploitDetection,
		"EnhancedExploitationVisibility":            config.EnhancedExploitationVisibility,
		"DLLLoadVisibility":                         config.DLLLoadVisibility,
		"MemoryScan":                                config.MemoryScan,
		"CPUMemoryScan":                             config.CPUMemoryScan,
		"FirmwareAnalysisExtraction":                config.FirmwareAnalysisExtraction,
		"ML Large File Handling":                    config.MLLargeFileHandling,
		"USBInsertionTriggeredScan":                 config.USBInsertionTriggeredScan,
		"DetectOnWrite":                             config.DetectOnWrite,
		"QuarantineOnWrite":                         config.QuarantineOnWrite,
		"OnWriteScriptFileVisibility":               config.OnWriteScriptFileVisibility,
		"NextGenAV":                                 config.NextGenAV,
		"NextGenAVQuarantineOnRemovableMedia":       config.NextGenAVQuarantineOnRemovableMedia,
		"MicrosoftOfficeFileSuspiciousMacroRemoval": config.MicrosoftOfficeFileSuspiciousMacroRemoval,
		"CustomBlacklisting":                        config.CustomBlacklisting,
		"PreventSuspiciousProcesses":                config.PreventSuspiciousProcesses,
		"SuspiciousRegistryOperations":              config.SuspiciousRegistryOperations,
		"MaliciousPowershell":                       config.MaliciousPowershell,
		"IntelPrevention":                           config.IntelPrevention,
		"SuspiciousKernelDrivers":                   config.SuspiciousKernelDrivers,
		"VulnerableDriverProtection":                config.VulnerableDriverProtection,
		"ForceASLR":                                 config.ForceASLR,
		"ForceDEP":                                  config.ForceDEP,
		"HeapSprayPreallocation":                    config.HeapSprayPreallocation,
		"NullPageAllocation":                        config.NullPageAllocation,
		"SEHOverwriteProtection":                    config.SEHOverwriteProtection,
		"BackupDeletion":                            config.BackupDeletion,
		"Cryptowall":                                config.Cryptowall,
		"FileEncryption":                            config.FileEncryption,
		"Locky":                                     config.Locky,
		"FileSystemAccess":                          config.FileSystemAccess,
		"VolumeShadowCopyAudit":                     config.VolumeShadowCopyAudit,
		"VolumeShadowCopyProtect":                   config.VolumeShadowCopyProtect,
		"ApplicationExploitationActivity":           config.ApplicationExploitationActivity,
		"ChopperWebshell":                           config.ChopperWebshell,
		"DriveByDownload":                           config.DriveByDownload,
		"ProcessHollowing":                          config.ProcessHollowing,
		"JavaScriptViaRundll32":                     config.JavaScriptViaRundll32,
		"WindowsLogonBypassStickyKeys":              config.WindowsLogonBypassStickyKeys,
		"CredentialDumping":                         config.CredentialDumping,
		"AutomatedRemediation":                      config.AutomatedRemediation,
		"FileSystemContainmentEnabled":              config.FileSystemContainmentEnabled,
		"BootConfigurationDatabaseProtection":       config.BootConfigurationDatabaseProtection,
		"WSL2Visibility":                            config.WSL2Visibility,
	}

	mlSliderSettings := map[string]mlSlider{}

	// Handle CloudAntiMalwareForMicrosoftOfficeFiles
	if !config.CloudAntiMalwareForMicrosoftOfficeFiles.IsNull() {
		var slider mlSlider
		diagsSlider := config.CloudAntiMalwareForMicrosoftOfficeFiles.As(ctx, &slider, basetypes.ObjectAsOptions{})
		diags.Append(diagsSlider...)
		if diags.HasError() {
			return preventionSettings, diags
		}
		mlSliderSettings["CloudAntiMalwareForMicrosoftOfficeFiles"] = slider
	}

	// Handle CloudAntiMalware
	if !config.CloudAntiMalware.IsNull() {
		var slider mlSlider
		diagsSlider := config.CloudAntiMalware.As(ctx, &slider, basetypes.ObjectAsOptions{})
		diags.Append(diagsSlider...)
		if diags.HasError() {
			return preventionSettings, diags
		}
		mlSliderSettings["CloudAntiMalware"] = slider
	}

	// Handle AdwarePUP
	if !config.AdwarePUP.IsNull() {
		var slider mlSlider
		diagsSlider := config.AdwarePUP.As(ctx, &slider, basetypes.ObjectAsOptions{})
		diags.Append(diagsSlider...)
		if diags.HasError() {
			return preventionSettings, diags
		}
		mlSliderSettings["AdwarePUP"] = slider
	}

	// Handle OnSensorMLSlider
	if !config.OnSensorMLSlider.IsNull() {
		var slider mlSlider
		diagsSlider := config.OnSensorMLSlider.As(ctx, &slider, basetypes.ObjectAsOptions{})
		diags.Append(diagsSlider...)
		if diags.HasError() {
			return preventionSettings, diags
		}
		mlSliderSettings["OnSensorMLSlider"] = slider
	}

	// Handle OnSensorMLSliderForSensorEndUserScans
	if !config.OnSensorMLSliderForSensorEndUserScans.IsNull() {
		var slider mlSlider
		diagsSlider := config.OnSensorMLSliderForSensorEndUserScans.As(ctx, &slider, basetypes.ObjectAsOptions{})
		diags.Append(diagsSlider...)
		if diags.HasError() {
			return preventionSettings, diags
		}
		mlSliderSettings["OnSensorMLSliderForSensorEndUserScans"] = slider
	}

	// Handle OnSensorMLSliderForCloudEndUserScans
	if !config.OnSensorMLSliderForCloudEndUserScans.IsNull() {
		var slider mlSlider
		diagsSlider := config.OnSensorMLSliderForCloudEndUserScans.As(ctx, &slider, basetypes.ObjectAsOptions{})
		diags.Append(diagsSlider...)
		if diags.HasError() {
			return preventionSettings, diags
		}
		mlSliderSettings["OnSensorMLSliderForCloudEndUserScans"] = slider
	}

	// Handle CloudMLSliderForPupAdwareCloudEndUserScans
	if !config.CloudMLSliderForPupAdwareCloudEndUserScans.IsNull() {
		var slider mlSlider
		diagsSlider := config.CloudMLSliderForPupAdwareCloudEndUserScans.As(ctx, &slider, basetypes.ObjectAsOptions{})
		diags.Append(diagsSlider...)
		if diags.HasError() {
			return preventionSettings, diags
		}
		mlSliderSettings["CloudMLSliderForPupAdwareCloudEndUserScans"] = slider
	}

	detectionMlSliderSettings := map[string]detectionMlSlider{}
	if !config.ExtendedUserModeDataSlider.IsNull() {
		var extendedSlider detectionMlSlider
		diagsExt := config.ExtendedUserModeDataSlider.As(ctx, &extendedSlider, basetypes.ObjectAsOptions{})
		diags.Append(diagsExt...)
		if diags.HasError() {
			return preventionSettings, diags
		}
		detectionMlSliderSettings["ExtendedUserModeDataSlider"] = extendedSlider
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

	return preventionSettings, diags
}
