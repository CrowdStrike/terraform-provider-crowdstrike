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

# Create a sensor visibility exclusion for specific host groups
resource "crowdstrike_sensor_visibility_exclusion" "group_exclusion" {
  value       = "C:\\MyApp\\*"
  comment     = "Exclude MyApp directory for development hosts"
  host_groups = []
  apply_globally = true
}
