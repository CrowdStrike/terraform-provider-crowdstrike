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
  uninstall_protection = true
}

output "sensor_policy" {
  value = crowdstrike_sensor_update_policy.test
}
