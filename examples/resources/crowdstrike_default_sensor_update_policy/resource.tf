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

resource "crowdstrike_default_sensor_update_policy" "default" {
  platform_name        = "windows"
  build                = data.crowdstrike_sensor_update_policy_builds.all.windows.n1.build
  uninstall_protection = true
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
  value = crowdstrike_default_sensor_update_policy.default
}
