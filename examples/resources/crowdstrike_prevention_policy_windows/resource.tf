terraform {
  required_providers {
    crowdstrike = {
      source = "registry.terraform.io/crowdstrike/crowdstrike"
    }
  }
}

provider "crowdstrike" {
  cloud = "us-2"
}


resource "crowdstrike_prevention_policy_windows" "example" {
  name            = "example_prevention_policy"
  enabled         = true
  description     = "made with terraform"
  host_groups     = []
  ioa_rule_groups = []
  adware_and_pup = {
    "detection"  = "MODERATE"
    "prevention" = "CAUTIOUS"
  }
  cloud_anti_malware_microsoft_office_files = {
    detection  = "MODERATE"
    prevention = "DISABLED"
  }
  cloud_anti_malware = {
    "detection"  = "MODERATE"
    "prevention" = "CAUTIOUS"
  }
  cloud_anti_malware_user_initiated = {
    "detection"  = "MODERATE"
    "prevention" = "CAUTIOUS"
  }
  sensor_anti_malware = {
    "detection"  = "MODERATE"
    "prevention" = "CAUTIOUS"
  }
  sensor_anti_malware_user_initiated = {
    "detection"  = "MODERATE"
    "prevention" = "CAUTIOUS"
  }
  extended_user_mode_data = {
    "detection" = "MODERATE"
  }
  usb_insertion_triggered_scan                   = true
  application_exploitation_activity              = true
  additional_user_mode_data                      = true
  notify_end_users                               = true
  advanced_remediation                           = true
  backup_deletion                                = true
  bios_deep_visibility                           = true
  chopper_webshell                               = true
  code_injection                                 = true
  credential_dumping                             = true
  cryptowall                                     = true
  custom_blocking                                = true
  detect_on_write                                = true
  drive_by_download                              = true
  driver_load_prevention                         = true
  interpreter_only                               = true
  engine_full_visibility                         = true
  enhanced_exploitation_visibility               = true
  enhanced_dll_load_visibility                   = true
  enhanced_ml_for_larger_files                   = true
  file_encryption                                = true
  file_system_access                             = true
  force_aslr                                     = true
  force_dep                                      = true
  heap_spray_preallocation                       = true
  null_page_allocation                           = true
  seh_overwrite_protection                       = true
  hardware_enhanced_exploit_detection            = true
  http_detections                                = true
  redact_http_detection_details                  = true
  intelligence_sourced_threats                   = true
  javascript_via_rundll32                        = true
  locky                                          = true
  memory_scanning                                = true
  memory_scanning_scan_with_cpu                  = true
  microsoft_office_file_suspicious_macro_removal = true
  on_write_script_file_visibility                = true
  prevent_suspicious_processes                   = true
  quarantine_and_security_center_registration    = true
  quarantine_on_removable_media                  = true
  quarantine_on_write                            = true
  script_based_execution_monitoring              = true
  sensor_tampering_protection                    = true
  suspicious_registry_operations                 = true
  suspicious_scripts_and_commands                = true
  upload_unknown_executables                     = true
  upload_unknown_detection_related_executables   = true
  volume_shadow_copy_audit                       = true
  volume_shadow_copy_protect                     = true
  vulnerable_driver_protection                   = true
  windows_logon_bypass_sticky_keys               = true
}

output "prevention_policy_windows" {
  value = crowdstrike_prevention_policy_windows.example
}
