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


resource "crowdstrike_prevention_policy_linux" "example" {
  name            = "example_prevention_policy"
  enabled         = true
  description     = "made with terraform"
  host_groups     = ["d6e3c1e1b3d0467da0fowc96a5e6ecb5"]
  ioa_rule_groups = ["ed334b3243bc4b6bb8e7d40a2ecd86fa"]
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
}

output "sensor_policy" {
  value = crowdstrike_prevention_policy_linux.example
}
