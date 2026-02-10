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

resource "crowdstrike_ioa_rule_group" "example" {
  name        = "My IOA Rule Group"
  description = "A rule group for custom IOA rules"
  platform    = "linux"
  comment     = "Created with terraform"
}

resource "crowdstrike_ioa_rule_group" "minimal" {
  name     = "Minimal IOA Rule Group"
  platform = "windows"
}

output "ioa_rule_group" {
  value = crowdstrike_ioa_rule_group.example
}
