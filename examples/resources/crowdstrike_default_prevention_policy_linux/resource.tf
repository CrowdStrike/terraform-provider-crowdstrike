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


resource "crowdstrike_default_prevention_policy_linux" "default" {
  description     = "managed by terraform"
  ioa_rule_groups = []
  cloud_anti_malware = {
    "detection"  = "MODERATE"
    "prevention" = "CAUTIOUS"
  }
  sensor_anti_malware = {
    "detection"  = "MODERATE"
    "prevention" = "CAUTIOUS"
  }
  quarantine                                   = true
  custom_blocking                              = true
  prevent_suspicious_processes                 = true
  script_based_execution_monitoring            = true
  upload_unknown_executables                   = true
  upload_unknown_detection_related_executables = true
  drift_prevention                             = true
  email_protocol_visibility                    = true
  filesystem_visibility                        = true
  ftp_visibility                               = true
  http_visibility                              = true
  network_visibility                           = true
  tls_visibility                               = true
  sensor_tampering_protection                  = true
  on_write_script_file_visibility              = true
  memory_visibility                            = true
  extended_command_line_visibility             = true
  dbus_visibility                              = true
  enhance_php_visibility                       = true
  enhance_environment_variable_visibility      = true
  suspicious_file_analysis                     = true
}

output "default_prevention_policy_linux" {
  value = crowdstrike_default_prevention_policy_linux.default
}
