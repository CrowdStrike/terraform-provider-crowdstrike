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

data "crowdstrike_sensor_update_policy_builds" "builds" {}


output "latest_windows_build" {
  value = data.crowdstrike_sensor_update_policy_builds.builds.windows.latest
}

output "n1_linux_build" {
  value = data.crowdstrike_sensor_update_policy_builds.builds.linux.n1
}

output "n2_mac_build" {
  value = data.crowdstrike_sensor_update_policy_builds.builds.mac.n2
}

output "latest_linux_arm64_build" {
  value = data.crowdstrike_sensor_update_policy_builds.builds.linux_arm64.latest
}
