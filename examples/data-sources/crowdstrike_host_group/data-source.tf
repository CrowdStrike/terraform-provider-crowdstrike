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

# Look up a host group by name
data "crowdstrike_host_group" "fc_alpha" {
  name = "FC - Alpha"
}

# Look up a host group by ID
data "crowdstrike_host_group" "by_id" {
  id = "dbe9c1fabd024fafaf44adf4df5f0f0f"
}

data "crowdstrike_sensor_update_policy_builds" "all" {}

# Use the host group ID in a sensor update policy
resource "crowdstrike_sensor_update_policy" "mac_latest" {
  name          = "Mac Sensor Update - Latest"
  platform_name = "Mac"
  enabled       = true
  build         = data.crowdstrike_sensor_update_policy_builds.all.mac.latest.build
  host_groups   = [data.crowdstrike_host_group.fc_alpha.id]
  schedule = {
    enabled = false
  }
}
