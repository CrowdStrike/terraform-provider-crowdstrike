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

resource "crowdstrike_default_content_update_policy" "default" {
  description = "Default content update policy for CrowdStrike environment"

  sensor_operations = {
    ring_assignment = "ga"
    delay_hours     = 0
  }

  system_critical = {
    ring_assignment = "ga"
    delay_hours     = 24
  }

  vulnerability_management = {
    ring_assignment = "ga"
    delay_hours     = 0
  }

  rapid_response = {
    ring_assignment = "ga"
    delay_hours     = 0
  }
}


output "default_content_policy" {
  value       = crowdstrike_default_content_update_policy.default
  description = "The default content update policy configuration"
}
