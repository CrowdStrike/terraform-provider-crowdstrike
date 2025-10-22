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

locals {
  // Get all read and guest roles
  read_guest_roles = [for role in data.crowdstrike_user_roles.all.role_ids : role if can(regex("(read|guest)", role))]
}

data "crowdstrike_user_roles" "all" {}

resource "crowdstrike_user" "example" {
  uid        = "username@example.com"
  first_name = "FirstName"
  last_name  = "LastName"
  cid        = "ABCDEF0123456789ABCDEF0123456789"
}

resource "crowdstrike_user_role_assignments" "example" {
  uuid              = crowdstrike_user.example.uuid
  assigned_role_ids = local.read_guest_roles
  depends_on        = [crowdstrike_user.example]
}

output "user_role_assignments" {
  value = crowdstrike_user_role_grant.example
}
