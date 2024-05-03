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


resource "crowdstrike_sensor_update_policy" "test" {
  name                 = "tf-test-update"
  enabled              = true
  description          = "made with terraform"
  platform_name        = "Windows"
  build                = "18110"
  uninstall_protection = false
  # host_groups        = ["host_group_id"]
  schedule = {
    enabled = false
    # timezone = "Etc/UTC"
    # time_blocks = [
    #   {
    #     days       = ["sunday", "wednesday"]
    #     start_time = "12:40"
    #     end_time   = "16:40"
    #   }
    # ]
  }
}

output "sensor_policy" {
  value = crowdstrike_sensor_update_policy.test
}
