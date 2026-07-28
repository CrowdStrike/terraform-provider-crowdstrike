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

variable "user_uuid" {
  description = "UUID of the existing Falcon user to assign roles to."
  type        = string
}

data "crowdstrike_cid" "current" {}

resource "crowdstrike_user_role_assignment" "example" {
  user_uuid = var.user_uuid
  cid       = data.crowdstrike_cid.current.cid

  role_ids = [
    "event_viewer",
    "help_desk",
  ]
}
