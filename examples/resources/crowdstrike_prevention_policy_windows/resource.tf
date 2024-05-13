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
  name        = "example_prevention_policy"
  enabled     = false
  description = "made with terraform"
  # host_groups     = ["d6e3c1e1b3d0467da0fowc96a5e6ecb5"]
  # ioa_rule_groups = ["ed334b3243bc4b6bb8e7d40a2ecd86fa"]
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
  usb_insertion_triggered_scan                   = false
  application_exploitation_activity              = false
  additional_user_mode_data                      = false
  notify_end_users                               = false
  advanced_remediation                           = false
  backup_deletion                                = false
  bios_deep_visibility                           = false
  chopper_webshell                               = false
  code_injection                                 = false
  credential_dumping                             = false
  cryptowall                                     = false
  custom_blocking                                = false
  detect_on_write                                = false
  drive_by_download                              = false
  driver_load_prevention                         = false
  interpreter_only                               = false
  engine_full_visibility                         = false
  enhanced_exploitation_visibility               = false
  enhanced_ml_for_larger_files                   = false
  file_encryption                                = false
  file_system_access                             = false
  force_aslr                                     = false
  force_dep                                      = false
  heap_spray_preallocation                       = false
  null_page_allocation                           = false
  seh_overwrite_protection                       = false
  hardware_enhanced_exploit_detection            = false
  http_detections                                = false
  redact_http_detection_details                  = false
  intelligence_sourced_threats                   = false
  javascript_via_rundll32                        = false
  locky                                          = false
  memory_scanning                                = false
  memory_scanning_scan_with_cpu                  = false
  microsoft_office_file_suspicious_macro_removal = false
  on_write_script_file_visibility                = false
  prevent_suspicious_processes                   = false
  quarantine_and_security_center_registration    = false
  quarantine_on_removable_media                  = false
  quarantine_on_write                            = false
  script_based_execution_monitoring              = false
  sensor_tampering_protection                    = false
  suspicious_registry_operations                 = false
  suspicious_scripts_and_commands                = false
  upload_unknown_executables                     = false
  upload_unknown_detection_related_executables   = false
  volume_shadow_copy_audit                       = false
  volume_shadow_copy_protect                     = false
  vulnerable_driver_protection                   = false
  windows_logon_bypass_sticky_keys               = false
}

output "sensor_policy" {
  value = crowdstrike_prevention_policy_windows.example
}
