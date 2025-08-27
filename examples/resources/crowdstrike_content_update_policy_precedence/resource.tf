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


resource "crowdstrike_content_update_policy_precedence" "example" {
  ids = [
    "1234567890abcdef1234567890abcdef",
    "abcdef1234567890abcdef1234567890",
  ]
  enforcement = "dynamic"
}
