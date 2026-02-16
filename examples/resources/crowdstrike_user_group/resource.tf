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

resource "crowdstrike_user_group" "example" {
  name        = "Engineering Team"
  description = "User group for engineering team members"

  user_uuids = [
    "12345678-1234-1234-1234-123456789012",
    "87654321-4321-4321-4321-210987654321"
  ]
}
