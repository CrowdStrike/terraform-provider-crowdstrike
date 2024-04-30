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


resource "crowdstrike_host_group" "test" {
  name            = "example_host_group"
  description     = "made with terraform"
  type            = "dynamic"
  assignment_rule = "tags:'SensorGroupingTags/cloud-lab'+os_version:'Amazon Linux 2'"
}

output "host_group" {
  value = crowdstrike_host_group.test
}
