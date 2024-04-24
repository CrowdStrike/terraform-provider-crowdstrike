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

data "crowdstrike_sensor_update_policy_builds" "test" {}

output "test_sensor_update_policy_builds" {
  value = data.crowdstrike_sensor_update_policy_builds.test
}
