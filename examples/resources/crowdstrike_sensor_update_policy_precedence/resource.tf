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


resource "crowdstrike_sensor_update_policy_precedence" "example" {}

output "sensor_update_policy_precedence" {
  value = crowdstrike_sensor_update_policy_precedence.example
}
