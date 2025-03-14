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

data "crowdstrike_sensor_update_policy_builds" "all" {}

resource "crowdstrike_sensor_update_policy" "example" {
  name          = "example_prevention_policy"
  enabled       = false
  description   = "made with terraform"
  platform_name = "Windows"
  build         = data.crowdstrike_sensor_update_policy_builds.all.windows.n1.build
  # build                = "1"
  uninstall_protection = false
  host_groups          = ["host_group_id"]
  schedule = {
    enabled  = true
    timezone = "Etc/UTC"
    time_blocks = [
      {
        days       = ["sunday", "wednesday"]
        start_time = "12:40"
        end_time   = "16:40"
      }
    ]
  }
}

output "sensor_policy" {
  value = crowdstrike_sensor_update_policy.example
}
