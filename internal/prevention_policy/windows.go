package preventionpolicy

import (
	"context"
	"fmt"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
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
	ID                                        types.String       `tfsdk:"id"`
	Enabled                                   types.Bool         `tfsdk:"enabled"`
	Name                                      types.String       `tfsdk:"name"`
	Description                               types.String       `tfsdk:"description"`
	HostGroups                                types.Set          `tfsdk:"host_groups"`
	RuleGroups                                types.Set          `tfsdk:"ioa_rule_groups"`
	LastUpdated                               types.String       `tfsdk:"last_updated"`
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
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf(
			"Prevention Policy --- This resource allows you to manage CrowdStrike Falcon prevention policies for Windows hosts. Prevention policies allow you to manage what activity will trigger detections and preventions on your hosts.\n\n%s",
			scopes.GenerateScopeDescription(apiScopes),
		),
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
				Required:    true,
				ElementType: types.StringType,
				Description: "Host Group ids to attach to the prevention policy.",
			},
			"ioa_rule_groups": schema.SetAttribute{
				Required:    true,
				ElementType: types.StringType,
				Description: "IOA Rule Group to attach to the prevention policy.",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description of the prevention policy.",
			},
			"cloud_anti_malware_microsoft_office_files": mlSLiderAttribute(
				"Identifies potentially malicious macros in Microsoft Office files and, if prevention is enabled, either quarantines the file or removes the malicious macros before releasing the file back to the host",
			),
			"extended_user_mode_data": mlSLiderAttribute(
				"Allows the sensor to get more data from a user-mode component it loads into all eligible processes, which augments online machine learning and turns on additional detections. Recommend testing with critical applications before full deployment.",
				withPrevention(false),
			),
			"cloud_anti_malware": mlSLiderAttribute(
				"Use cloud-based machine learning informed by global analysis of executables to detect and prevent known malware for your online hosts.",
			),
			"adware_and_pup": mlSLiderAttribute(
				"Use cloud-based machine learning informed by global analysis of executables to detect and prevent adware and potentially unwanted programs (PUP) for your online hosts.",
			),
			"sensor_anti_malware": mlSLiderAttribute(
				"For offline and online hosts, use sensor-based machine learning to identify and analyze unknown executables as they run to detect and prevent malware.",
			),
			"sensor_anti_malware_user_initiated": mlSLiderAttribute(
				"For offline and online hosts running on-demand scans initiated by end users, use sensor-based machine learning to identify and analyze unknown executables to detect and prevent malware.",
			),
			"cloud_anti_malware_user_initiated": mlSLiderAttribute(
				"For online hosts running on-demand scans initiated by end users, use cloud-based machine learning informed by global analysis of executables to detect and prevent known malware.",
			),
			"additional_user_mode_data": toggleAttribute(
				"Allows the sensor to get more data from a user-mode component it loads into all eligible processes, which augments online machine learning and turns on additional detections. Recommend testing with critical applications before full deployment.",
			),
			"notify_end_users": toggleAttribute(
				"Show a pop-up notification to the end user when the Falcon sensor blocks, kills, or quarantines. These messages also show up in the Windows Event Viewer under Applications and Service Logs.",
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
			"interpreter_only": toggleAttribute(
				"Provides visibility into malicious PowerShell interpreter usage. For hosts running Windows 10, Script-Based Execution Monitoring may be used instead.",
			),
			"engine_full_visibility": toggleAttribute(
				"Provides visibility into malicious System Management Automation engine usage by any application. Requires interpreter_only to be enabled.",
			),
			"script_based_execution_monitoring": toggleAttribute(
				"For hosts running Windows 10 and Servers 2016 and later, provides visibility into suspicious scripts and VBA macros in Office documents. Requires Quarantine & Security Center Registration toggle to be enabled.",
			),
			"http_detections": toggleAttribute(
				"Allows the sensor to monitor unencrypted HTTP traffic and certain encrypted HTTPS traffic on the sensor for malicious patterns and generate detection events on non-Server systems.",
			),
			"redact_http_detection_details": toggleAttribute(
				"Remove certain information from HTTP Detection events, including URL, raw HTTP header and POST bodies if they were present. This does not affect the generation of HTTP Detections, only additional details that would be included and may include personal information (depending on the malware in question). When disabled, the information is used to improve the response to detection events. Has no effect unless HTTP Detections is also enabled.",
				withEnabled(true),
			),
			"hardware_enhanced_exploit_detection": toggleAttribute(
				"Provides additional visibility into application exploits by using CPU hardware features that detect suspicious control flows. Available only for hosts running Windows 10 (RS4) or Windows Server 2016 Version 1803 or later and Skylake or later CPU.",
			),
			"enhanced_exploitation_visibility": toggleAttribute(
				"For hosts running Windows 10 1809 and Server 2019 and later, provides additional visibility into common exploitation techniques used to weaken or circumvent application security.",
			),
			"enhanced_dll_load_visibility": toggleAttribute(
				"For hosts running Windows Server, increases sensor visibility of loaded DLLs. Improves detection coverage and telemetry, but may cause a small performance impact. Recommend testing with critical applications before full deployment.",
			),
			"memory_scanning": toggleAttribute(
				"Provides visibility into in-memory attacks by scanning for suspicious artifacts on hosts with the following: an integrated GPU and supporting OS libraries, Windows 10 v1607 (RS1) or later, and a Skylake or newer Intel CPU.",
			),
			"memory_scanning_scan_with_cpu": toggleAttribute(
				"Allows memory scanning to use the CPU or virtual CPU when an integrated GPU is not available. All Intel processors supported, requires Windows 8.1/2012 R2 or later.",
			),
			"bios_deep_visibility": toggleAttribute(
				"Provides visibility into BIOS. Detects suspicious and unexpected images. Recommend testing to monitor system startup performance before full deployment.",
			),
			"enhanced_ml_for_larger_files": toggleAttribute(
				"Expand ML file size coverage. Existing ML level settings apply.",
			),
			"usb_insertion_triggered_scan": toggleAttribute(
				"Start an on-demand scan when an end user inserts a USB device. To adjust detection sensitivity, change Anti-malware Detection levels in On-Demand Scans Machine Learning.",
			),
			"detect_on_write": toggleAttribute(
				"Use machine learning to analyze suspicious files when they're written to disk. To adjust detection sensitivity, change Anti-malware Detection levels in Sensor Machine Learning and Cloud Machine Learning.",
			),
			"quarantine_on_write": toggleAttribute(
				"Use machine learning to quarantine suspicious files when they're written to disk. To adjust quarantine sensitivity, change Anti-malware Prevention levels in Sensor Machine Learning and Cloud Machine Learning.",
			),
			"on_write_script_file_visibility": toggleAttribute(
				"Provides improved visibility into various script files being written to disk in addition to clouding a portion of their content.",
			),
			"quarantine_and_security_center_registration": toggleAttribute(
				"Quarantine executable files after they’re prevented by NGAV. When this is enabled, we recommend setting anti-malware prevention levels to Moderate or higher and not using other antivirus solutions. CrowdStrike Falcon registers with Windows Security Center, disabling Windows Defender.",
			),
			"quarantine_on_removable_media": toggleAttribute(
				"Quarantine executable files after they’re prevented by NGAV.",
			),
			"microsoft_office_file_suspicious_macro_removal": toggleAttribute(
				"Identifies potentially malicious macros in Microsoft Office files and, if prevention is enabled, either quarantines the file or removes the malicious macros before releasing the file back to the host",
			),
			"custom_blocking": toggleAttribute(
				"Block processes matching hashes that you add to IOC Management with the action set to \"Block\" or \"Block, hide detection\".",
			),
			"prevent_suspicious_processes": toggleAttribute(
				"Block processes that CrowdStrike analysts classify as suspicious. These are focused on dynamic IOAs, such as malware, exploits and other threats.",
			),
			"suspicious_registry_operations": toggleAttribute(
				"Block registry operations that CrowdStrike analysts classify as suspicious. Focuses on dynamic IOAs, such as ASEPs and security config changes. The associated process may be killed.",
			),
			"suspicious_scripts_and_commands": toggleAttribute(
				"Block execution of scripts and commands that CrowdStrike analysts classify as suspicious. Requires Interpreter-Only and/or Script-Based Execution Monitoring.",
			),
			"intelligence_sourced_threats": toggleAttribute(
				"Block processes that CrowdStrike Intelligence analysts classify as malicious. These are focused on static hash-based IOCs.",
			),
			"driver_load_prevention": toggleAttribute(
				"Block the loading of kernel drivers that CrowdStrike analysts have identified as malicious. Available on Windows 10 and Windows Server 2016 and later.",
			),
			"vulnerable_driver_protection": toggleAttribute(
				"Quarantine and block the loading of newly written kernel drivers that CrowdStrike analysts have identified as vulnerable. Available on Windows 10 and Windows 2016 and later. Requires driver_load_prevention.",
			),
			"force_aslr": toggleAttribute(
				"An Address Space Layout Randomization (ASLR) bypass attempt was detected and blocked. This may have been part of an attempted exploit. Requires additional_user_mode_data to be enabled.",
			),
			"force_dep": toggleAttribute(
				"A process that had Force Data Execution Prevention (Force DEP) applied tried to execute non-executable memory and was blocked. Requires additional_user_mode_data to be enabled.",
			),
			"heap_spray_preallocation": toggleAttribute(
				"A heap spray attempt was detected and blocked. This may have been part of an attempted exploit. Requires additional_user_mode_data to be enabled.",
			),
			"null_page_allocation": toggleAttribute(
				"Allocating memory to the NULL (0) memory page was detected and blocked. This may have been part of an attempted exploit. Requires additional_user_mode_data to be enabled.",
			),
			"seh_overwrite_protection": toggleAttribute(
				"Overwriting a Structured Exception Handler (SEH) was detected and may have been blocked. This may have been part of an attempted exploit. Requires additional_user_mode_data to be enabled.",
			),
			"backup_deletion": toggleAttribute(
				"Deletion of backups often indicative of ransomware activity.",
			),
			"cryptowall": toggleAttribute(
				"A process associated with Cryptowall was blocked.",
			),
			"file_encryption": toggleAttribute(
				"A process that created a file with a known ransomware extension was terminated.",
			),
			"locky": toggleAttribute(
				"A process determined to be associated with Locky was blocked.",
			),
			"file_system_access": toggleAttribute(
				"A process associated with a high volume of file system operations typical of ransomware behavior was terminated.",
			),
			"volume_shadow_copy_audit": toggleAttribute(
				"Create an alert when a suspicious process deletes volume shadow copies. Recommended: Use audit mode with a test group to try allowlisting trusted software before turning on Protect.",
			),
			"volume_shadow_copy_protect": toggleAttribute(
				"Prevent suspicious processes from deleting volume shadow copies. Requires volume_shadow_copy_audit.",
			),
			"application_exploitation_activity": toggleAttribute(
				"Creation of a process, such as a command prompt, from an exploited browser or browser flash plugin was blocked.",
			),
			"chopper_webshell": toggleAttribute(
				"Execution of a command shell was blocked and is indicative of the system hosting a Chopper web page.",
			),
			"drive_by_download": toggleAttribute(
				"A suspicious file written by a browser attempted to execute and was blocked.",
			),
			"code_injection": toggleAttribute(
				"Kill processes that unexpectedly injected code into another process. Requires additional_user_mode_data to be enabled.",
			),
			"javascript_via_rundll32": toggleAttribute(
				"JavaScript executing from a command line via rundll32.exe was prevented.",
			),
			"windows_logon_bypass_sticky_keys": toggleAttribute(
				"A command line process associated with Windows logon bypass was prevented from executing.",
			),
			"credential_dumping": toggleAttribute(
				"Kill suspicious processes determined to be stealing logins and passwords. Requires additional_user_mode_data to be enabled.",
			),
			"advanced_remediation": toggleAttribute(
				"Perform advanced remediation for IOA detections to kill processes, quarantine files, remove scheduled tasks, and clear and delete ASEP registry values.",
			),
		},
	}
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

	preventionSettings := r.generatePreventionSettings(plan)
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

	resp.Diagnostics.Append(validateHostGroups(ctx, config.HostGroups)...)
	resp.Diagnostics.Append(validateIOARuleGroups(ctx, config.RuleGroups)...)

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
	state *preventionPolicyWindowsResourceModel,
	categories []*models.PreventionCategoryRespV1,
) {
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

	// mlslider settings
	state.ExtendedUserModeDataSlider = detectionMlSliderSettings["ExtendedUserModeDataSlider"]
	state.CloudAntiMalwareForMicrosoftOfficeFiles = mlSliderSettings["CloudAntiMalwareForMicrosoftOfficeFiles"]
	state.CloudAntiMalware = mlSliderSettings["CloudAntiMalware"]
	state.AdwarePUP = mlSliderSettings["AdwarePUP"]
	state.OnSensorMLSlider = mlSliderSettings["OnSensorMLSlider"]
	state.OnSensorMLSliderForSensorEndUserScans = mlSliderSettings["OnSensorMLSliderForSensorEndUserScans"]
	state.OnSensorMLSliderForCloudEndUserScans = mlSliderSettings["OnSensorMLSliderForCloudEndUserScans"]
}

// generatePreventionSettings maps plan prevention settings to api params for create and update.
func (r *preventionPolicyWindowsResource) generatePreventionSettings(
	config preventionPolicyWindowsResourceModel,
) []*models.PreventionSettingReqV1 {
	preventionSettings := []*models.PreventionSettingReqV1{}

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
	}

	mlSliderSettings := map[string]mlSlider{
		"CloudAntiMalwareForMicrosoftOfficeFiles": *config.CloudAntiMalwareForMicrosoftOfficeFiles,
		"CloudAntiMalware":                        *config.CloudAntiMalware,
		"AdwarePUP":                               *config.AdwarePUP,
		"OnSensorMLSlider":                        *config.OnSensorMLSlider,
		"OnSensorMLSliderForSensorEndUserScans":   *config.OnSensorMLSliderForSensorEndUserScans,
		"OnSensorMLSliderForCloudEndUserScans":    *config.OnSensorMLSliderForCloudEndUserScans,
	}
	detectionMlSliderSettings := map[string]detectionMlSlider{
		"ExtendedUserModeDataSlider": *config.ExtendedUserModeDataSlider,
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
