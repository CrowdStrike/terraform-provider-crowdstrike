package preventionpolicy

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// convertRuleGroupToSet converts a slice of IoaRuleGroupsRuleGroupV1 to a set.
func convertRuleGroupToSet(
	ctx context.Context,
	groups []*models.IoaRuleGroupsRuleGroupV1,
) (basetypes.SetValue, diag.Diagnostics) {
	ruleGroups := make([]types.String, 0, len(groups))
	for _, ruleGroup := range groups {
		ruleGroups = append(ruleGroups, types.StringValue(*ruleGroup.ID))
	}

	ruleGroupIDs, diags := types.SetValueFrom(ctx, types.StringType, ruleGroups)

	return ruleGroupIDs, diags
}

// validateMlSlider returns whether or not the mlslider is valid.
func validateMlSlider(attribute string, slider mlSlider) diag.Diagnostics {
	diags := diag.Diagnostics{}

	detectionLevel := slider.Detection.ValueString()
	preventionLevel := slider.Prevention.ValueString()

	if mapMlSliderLevels[detectionLevel] < mapMlSliderLevels[preventionLevel] {
		diags.AddAttributeError(
			path.Root(attribute),
			"Invalid ml slider setting.",
			fmt.Sprintf(
				"Prevention level: %s must the same or less restrictive than Detection level: %s. Ml detection levels are: %s",
				detectionLevel,
				preventionLevel,
				strings.Join(mlSliderLevels, ", "),
			),
		)
	}

	return diags
}

// validateRequiredAttribute validates that a required attribute is set.
func validateRequiredAttribute(
	attrValue bool,
	otherAttrValue bool,
	attr string,
	otherAttr string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if attrValue && !otherAttrValue {
		diags.AddAttributeError(
			path.Root(attr),
			fmt.Sprint("requirements not met to enable ", attr),
			fmt.Sprintf("%s requires %s to be enabled", attr, otherAttr),
		)
	}
	return diags
}

// toggleOptions holds the options for toggleAttribute function.
type toggleOptions struct {
	enabled bool
}

// toggleOption is a functional option to configure toggleOption.
type toggleOption func(*toggleOptions)

// withEnabled sets the enabled field for toggleAttribute.
func withEnabled(enabled bool) toggleOption {
	return func(o *toggleOptions) {
		o.enabled = enabled
	}
}

func toggleAttribute(description string, opts ...toggleOption) schema.BoolAttribute {
	options := toggleOptions{
		enabled: false,
	}

	for _, opt := range opts {
		opt(&options)
	}

	return schema.BoolAttribute{
		Optional:    true,
		Computed:    true,
		Description: fmt.Sprintf("Whether to enable the setting. %s", description),
		Default:     booldefault.StaticBool(options.enabled),
	}
}

var mlSliderLevels = []string{"DISABLED", "CAUTIOUS", "MODERATE", "AGGRESSIVE", "EXTRA_AGGRESSIVE"}
var mapMlSliderLevels = map[string]int{
	"DISABLED":         0,
	"CAUTIOUS":         1,
	"MODERATE":         2,
	"AGGRESSIVE":       3,
	"EXTRA_AGGRESSIVE": 4,
}

// mlSliderOptions holds the options for mlSLiderAttribute function.
type mlSliderOptions struct {
	description string
	prevention  bool
	detection   bool
}

// mlSliderOption is a functional option to configure mlSliderOptions.
type mlSliderOption func(*mlSliderOptions)

// withPrevention the description whether prevention should be included in the mlSliderAttribute.
func withPrevention(prevention bool) mlSliderOption {
	return func(o *mlSliderOptions) {
		o.prevention = prevention
	}
}

// generateMLSliderAttribute generates a mlslider attribute with a custom description.
// Includes prevention or detection slider settings if set to true.
func mlSLiderAttribute(description string, opts ...mlSliderOption) schema.SingleNestedAttribute {
	options := mlSliderOptions{
		description: "ml slider setting.",
		prevention:  true,
		detection:   true,
	}

	if description != "" {
		options.description = description
	}

	for _, opt := range opts {
		opt(&options)
	}

	attributeTypes := map[string]attr.Type{}
	attributeValues := map[string]attr.Value{}

	mlSliderAttribute := schema.SingleNestedAttribute{
		Optional:    true,
		Computed:    true,
		Description: description,
		Attributes:  map[string]schema.Attribute{},
	}

	if options.prevention {
		mlSliderAttribute.Attributes["prevention"] = schema.StringAttribute{
			Required:    true,
			Description: "Machine learning level for prevention.",
			Validators:  []validator.String{stringvalidator.OneOf(mlSliderLevels...)},
		}
		attributeTypes["prevention"] = types.StringType
		attributeValues["prevention"] = types.StringValue(mlSliderLevels[0])
	}

	if options.detection {
		mlSliderAttribute.Attributes["detection"] = schema.StringAttribute{
			Required:    true,
			Description: "Machine learning level for detection.",
			Validators:  []validator.String{stringvalidator.OneOf(mlSliderLevels...)},
		}
		attributeTypes["detection"] = types.StringType
		attributeValues["detection"] = types.StringValue(mlSliderLevels[0])
	}

	mlSliderAttribute.Default = objectdefault.StaticValue(
		types.ObjectValueMust(attributeTypes, attributeValues),
	)

	return mlSliderAttribute
}

// mlSlider a mlslider setting for a prevention policy.
type mlSlider struct {
	Detection  types.String `tfsdk:"detection"`
	Prevention types.String `tfsdk:"prevention"`
}

// detectionMlSlider a mlsider setting with only detection for a prevention policy.
type detectionMlSlider struct {
	Detection types.String `tfsdk:"detection"`
}

// apiToggle a toggle setting type used for calling CrowdStrike APIs.
type apiToggle struct {
	Enabled bool `json:"enabled"`
}

// apiMlSlider mlslider setting type used for calling CrowdStrike APIs.
type apiMlSlider struct {
	Detection  string `json:"detection,omitempty"`
	Prevention string `json:"prevention,omitempty"`
}

// generateWindowsSchema generates the schema.Schema for the windows prevention policy
func generateWindowsSchema(defaultPolicy bool) schema.Schema {
	windowsSchema := schema.Schema{
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
			"file_system_containment": toggleAttribute(
				"File System Containment will be enabled, this will allow prevention capabilities to automatically contain file system activity.  When disabled each user under active containment will be released and the File System Containment will enter a disabled mode",
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

	if defaultPolicy {
		windowsSchema.MarkdownDescription = fmt.Sprintf(
			"Prevention Policy --- This resource allows you to manage the default prevention policy for Windows hosts. Prevention policies allow you to manage what activity will trigger detections and preventions on your hosts.\n\n%s",
			scopes.GenerateScopeDescription(apiScopes),
		)
	} else {
		windowsSchema.MarkdownDescription = fmt.Sprintf(
			"Prevention Policy --- This resource allows you to manage prevention policies for Windows hosts. Prevention policies allow you to manage what activity will trigger detections and preventions on your hosts.\n\n%s",
			scopes.GenerateScopeDescription(apiScopes),
		)

		windowsSchema.Attributes["name"] = schema.StringAttribute{
			Required:    true,
			Description: "Name of the prevention policy.",
		}

		windowsSchema.Attributes["enabled"] = schema.BoolAttribute{
			Optional:    true,
			Computed:    true,
			Description: "Enable the prevention policy.",
			Default:     booldefault.StaticBool(true),
		}

		windowsSchema.Attributes["host_groups"] = schema.SetAttribute{
			Required:    true,
			ElementType: types.StringType,
			Description: "Host Group ids to attach to the prevention policy.",
		}
	}

	return windowsSchema
}

// generateMacSchema generates the schema.Schema for the mac prevention policy
func generateMacSchema(defaultPolicy bool) schema.Schema {
	macSchema := schema.Schema{
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
			"ioa_rule_groups": schema.SetAttribute{
				Required:    true,
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

	if defaultPolicy {
		macSchema.MarkdownDescription = fmt.Sprintf(
			"Prevention Policy --- This resource allows you to manage the default prevention policy for Mac hosts. Prevention policies allow you to manage what activity will trigger detections and preventions on your hosts.\n\n%s",
			scopes.GenerateScopeDescription(apiScopes),
		)
	} else {
		macSchema.MarkdownDescription = fmt.Sprintf(
			"Prevention Policy --- This resource allows you to manage prevention policies for Mac hosts. Prevention policies allow you to manage what activity will trigger detections and preventions on your hosts.\n\n%s",
			scopes.GenerateScopeDescription(apiScopes),
		)

		macSchema.Attributes["name"] = schema.StringAttribute{
			Required:    true,
			Description: "Name of the prevention policy.",
		}

		macSchema.Attributes["enabled"] = schema.BoolAttribute{
			Optional:    true,
			Computed:    true,
			Description: "Enable the prevention policy.",
			Default:     booldefault.StaticBool(true),
		}

		macSchema.Attributes["host_groups"] = schema.SetAttribute{
			Required:    true,
			ElementType: types.StringType,
			Description: "Host Group ids to attach to the prevention policy.",
		}
	}

	return macSchema
}

// generateLinuxSchema generates the schema.Schema for the linux prevention policy
func generateLinuxSchema(defaultPolicy bool) schema.Schema {
	linuxSchema := schema.Schema{
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
			"ioa_rule_groups": schema.SetAttribute{
				Required:    true,
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
			"sensor_anti_malware": mlSLiderAttribute(
				"For offline and online hosts, use sensor-based machine learning to identify and analyze unknown executables as they run to detect and prevent malware.",
			),
			"quarantine": toggleAttribute(
				"Quarantine executable files after they’re prevented by NGAV. When this is enabled, we recommend setting anti-malware prevention levels to Moderate or higher and not using other antivirus solutions.",
			),
			"upload_unknown_detection_related_executables": toggleAttribute(
				"Upload all unknown detection-related executables for advanced analysis in the cloud.",
			),
			"upload_unknown_executables": toggleAttribute(
				"Upload all unknown executables for advanced analysis in the cloud.",
			),
			"script_based_execution_monitoring": toggleAttribute(
				"Provides visibility into suspicious scripts, including shell and other scripting languages.",
			),
			"custom_blocking": toggleAttribute(
				"Block processes matching hashes that you add to IOC Management with the action set to \"Block\" or \"Block, hide detection\".",
			),
			"prevent_suspicious_processes": toggleAttribute(
				"Block processes that CrowdStrike analysts classify as suspicious. These are focused on dynamic IOAs, such as malware, exploits and other threats.",
			),
			"drift_prevention": toggleAttribute(
				"Block new processes originating from files written in a container. This prevents a container from drifting from its immutable runtime state.",
			),
			"filesystem_visibility": toggleAttribute(
				"Allows the sensor to monitor filesystem activity for additional telemetry and improved detections.",
			),
			"network_visibility": toggleAttribute(
				"Allows the sensor to monitor network activity for additional telemetry and improved detections.",
			),
			"http_visibility": toggleAttribute(
				"Allows the sensor to monitor unencrypted HTTP traffic for malicious patterns and improved detections.",
			),
			"ftp_visibility": toggleAttribute(
				"Allows the sensor to monitor unencrypted FTP traffic for malicious patterns and improved detections.",
			),
			"tls_visibility": toggleAttribute(
				"Allows the sensor to monitor TLS traffic for malicious patterns and improved detections.",
			),
			"email_protocol_visibility": toggleAttribute(
				"Allows the sensor to monitor SMTP, IMAP, and POP3 traffic for malicious patterns and improved detections.",
			),
			"sensor_tampering_protection": toggleAttribute(
				"Block attempts to tamper with the sensor by protecting critical components and resources. If disabled, the sensor still creates detections for tampering attempts but will not prevent the activity from occurring. Disabling is not recommended.",
			),
			"memory_visibility": toggleAttribute(
				"When enabled, the sensor will inspect memory-related operations: mmap, mprotect, ptrace and reading/writing remote process memory and produce events.",
			),
			"on_write_script_file_visibility": toggleAttribute(
				"Provides improved visibility into various script files being written to disk in addition to clouding a portion of their content.",
			),
			"extended_command_line_visibility": toggleAttribute(
				"Allows the sensor to monitor full CLI commands that include pipes and redirects. This is applicable only for User mode.",
			),
		},
	}

	if defaultPolicy {
		linuxSchema.MarkdownDescription = fmt.Sprintf(
			"Prevention Policy --- This resource allows you to manage the default prevention policy for Linux hosts. Prevention policies allow you to manage what activity will trigger detections and preventions on your hosts.\n\n%s",
			scopes.GenerateScopeDescription(apiScopes),
		)
	} else {
		linuxSchema.MarkdownDescription = fmt.Sprintf(
			"Prevention Policy --- This resource allows you to manage prevention policies for Linux hosts. Prevention policies allow you to manage what activity will trigger detections and preventions on your hosts.\n\n%s",
			scopes.GenerateScopeDescription(apiScopes),
		)

		linuxSchema.Attributes["name"] = schema.StringAttribute{
			Required:    true,
			Description: "Name of the prevention policy.",
		}

		linuxSchema.Attributes["enabled"] = schema.BoolAttribute{
			Optional:    true,
			Computed:    true,
			Description: "Enable the prevention policy.",
			Default:     booldefault.StaticBool(true),
		}

		linuxSchema.Attributes["host_groups"] = schema.SetAttribute{
			Required:    true,
			ElementType: types.StringType,
			Description: "Host Group ids to attach to the prevention policy.",
		}
	}

	return linuxSchema
}
