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

# Basic default content update policy
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

resource "crowdstrike_default_content_update_policy" "default" {
  description = "Default content update policy"

  sensor_operations = {
    ring_assignment = "ga"
    delay_hours     = 72
  }

  system_critical = {
    ring_assignment        = "ga"
    delay_hours            = 48
    pinned_content_version = data.crowdstrike_content_category_versions.available.system_critical[0]
  }

  vulnerability_management = {
    ring_assignment = "ga"
    delay_hours     = 24
  }

  rapid_response = {
    ring_assignment        = "ea"
    pinned_content_version = data.crowdstrike_content_category_versions.available.rapid_response[0]
  }
}

output "default_content_policy" {
  value       = crowdstrike_default_content_update_policy.default
  description = "The default content update policy configuration"
}
