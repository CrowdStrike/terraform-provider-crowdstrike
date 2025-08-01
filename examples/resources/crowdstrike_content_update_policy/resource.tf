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

# # Basic content update policy
# resource "crowdstrike_content_update_policy" "example" {
#   name        = "Example Content Policy"
#   description = "Example content update policy for production hosts"
#   enabled     = true
#
#   sensor_operations = {
#     ring_assignment = "ga"
#     delay_hours     = 0
#   }
#
#   system_critical = {
#     ring_assignment = "ga"
#     delay_hours     = 24
#   }
#
#   vulnerability_management = {
#     ring_assignment = "ea"
#   }
#
#   rapid_response = {
#     ring_assignment = "pause"
#   }
# }
#
# # Host groups for examples
# resource "crowdstrike_host_group" "production" {
#   name        = "Production Servers"
#   description = "Production server host group"
#   type        = "static"
#   hostnames   = ["host1"]
# }
#
# resource "crowdstrike_host_group" "staging" {
#   name        = "Staging Servers"
#   description = "Staging server host group"
#   type        = "static"
#   hostnames   = ["host1"]
# }
#
# resource "crowdstrike_host_group" "test" {
#   name        = "Test Servers"
#   description = "Test server host group"
#   type        = "static"
#   hostnames   = ["host1"]
# }
#
# # Content update policy with host groups and different ring configurations
# resource "crowdstrike_content_update_policy" "with_host_groups" {
#   name        = "Content Policy with Host Groups"
#   description = "Content update policy assigned to specific host groups"
#   enabled     = false
#
#   sensor_operations = {
#     ring_assignment = "ga"
#     delay_hours     = 12
#   }
#
#   system_critical = {
#     ring_assignment = "ga"
#     delay_hours     = 24
#   }
#
#   vulnerability_management = {
#     ring_assignment = "ga"
#     delay_hours     = 0
#   }
#
#   rapid_response = {
#     ring_assignment = "ea"
#   }
#
#   host_groups = [
#     crowdstrike_host_group.production.id,
#     crowdstrike_host_group.staging.id
#   ]
# }
#
# # Conservative content update policy for critical systems
# resource "crowdstrike_content_update_policy" "conservative" {
#   name        = "Conservative Content Policy"
#   description = "Conservative policy with longer delays for critical systems"
#   enabled     = true
#
#   sensor_operations = {
#     ring_assignment = "ga"
#     delay_hours     = 72 # 3 day delay
#   }
#
#   system_critical = {
#     ring_assignment = "ga"
#     delay_hours     = 48 # 2 day delay
#   }
#
#   vulnerability_management = {
#     ring_assignment = "ga"
#     delay_hours     = 24 # 1 day delay
#   }
#
#   rapid_response = {
#     ring_assignment = "ga"
#     delay_hours     = 0 # No delay for rapid response
#   }
# }
#
# # Early access content update policy for test environments
# resource "crowdstrike_content_update_policy" "early_access" {
#   name        = "Early Access Test Policy"
#   description = "Early access policy for testing environments"
#   enabled     = true
#
#   sensor_operations = {
#     ring_assignment = "ea"
#   }
#
#   system_critical = {
#     ring_assignment = "ea"
#   }
#
#   vulnerability_management = {
#     ring_assignment = "ea"
#   }
#
#   rapid_response = {
#     ring_assignment = "ea"
#   }
#
#   host_groups = [
#     crowdstrike_host_group.test.id
#   ]
# }

# Data source to fetch available content category versions
data "crowdstrike_content_category_versions" "available" {}

# Content update policy with pinned content versions for stability
resource "crowdstrike_content_update_policy" "pinned_versions" {
  name        = "Pinned Content Versions Policy"
  description = "Policy with specific content versions pinned for stability"
  enabled     = true

  sensor_operations = {
    ring_assignment        = "ea"
    pinned_content_version = data.crowdstrike_content_category_versions.available.sensor_operations[0]
  }

  system_critical = {
    ring_assignment = "ga"
    delay_hours     = 24
  }

  vulnerability_management = {
    ring_assignment        = "ga"
    delay_hours            = 12
    pinned_content_version = data.crowdstrike_content_category_versions.available.vulnerability_management[0]
  }

  rapid_response = {
    ring_assignment        = "ga"
    pinned_content_version = data.crowdstrike_content_category_versions.available.rapid_response[0]
  }
}
