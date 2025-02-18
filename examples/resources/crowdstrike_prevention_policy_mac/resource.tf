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


resource "crowdstrike_prevention_policy_mac" "example" {
  name            = "example_prevention_policy"
  enabled         = false
  description     = "made with terraform"
  host_groups     = []
  ioa_rule_groups = []
  cloud_adware_and_pup = {
    "detection"  = "MODERATE"
    "prevention" = "CAUTIOUS"
  }
  cloud_anti_malware = {
    "detection"  = "MODERATE"
    "prevention" = "CAUTIOUS"
  }
  sensor_anti_malware = {
    "detection"  = "MODERATE"
    "prevention" = "CAUTIOUS"
  }
  sensor_adware_and_pup = {
    "detection"  = "MODERATE"
    "prevention" = "CAUTIOUS"
  }
  notify_end_users                             = true
  custom_blocking                              = true
  detect_on_write                              = true
  intelligence_sourced_threats                 = true
  prevent_suspicious_processes                 = true
  quarantine                                   = true
  quarantine_on_write                          = true
  script_based_execution_monitoring            = true
  sensor_tampering_protection                  = true
  upload_unknown_executables                   = true
  upload_unknown_detection_related_executables = true
  xpcom_shell                                  = true
  kc_password_decoded                          = true
  hash_collector                               = true
  empyre_backdoor                              = true
  chopper_webshell                             = true
}

output "prevention_policy_mac" {
  value = crowdstrike_prevention_policy_mac.example
}
