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


data "crowdstrike_user_roles" "all" {}

# Filter all roles that contain read or guest
output "user_data_source" {
  value = [for role in data.crowdstrike_user_roles.all.role_ids : role if can(regex("(read|guest)", role))]
}
