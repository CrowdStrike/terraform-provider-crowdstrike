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


resource "crowdstrike_host_group" "dynamic" {
  assignment_rule = "tags:'SensorGroupingTags/molecule'+os_version:'Debian GNU 11'"
  description     = "Made with terraform"
  name            = "Dyanmic Host Group"
  type            = "dynamic"
}

resource "crowdstrike_host_group" "static" {
  description = "Made with terraform"
  name        = "Dyanmic Host Group"
  type        = "static"
  hostnames   = ["host1", "host2"]
}

resource "crowdstrike_host_group" "staticByID" {
  description = "Made with terraform"
  name        = "Dyanmic Host Group"
  type        = "staticByID"
  host_ids    = ["123123", "124124"]
}

output "host_group" {
  value = crowdstrike_host_group.dynamic
}
