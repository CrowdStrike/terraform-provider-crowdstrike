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

# Retrieve every user role available for the CID authenticated by the provider.
data "crowdstrike_user_roles" "example" {}

# Retrieve the roles available to a specific user in a specific child CID.
data "crowdstrike_user_roles" "by_user" {
  user_uuid = "abcdef12-3456-7890-abcd-ef1234567890"
  cid       = "abcdef1234567890abcdef1234567890"
}

output "roles" {
  value = data.crowdstrike_user_roles.example.roles
}
