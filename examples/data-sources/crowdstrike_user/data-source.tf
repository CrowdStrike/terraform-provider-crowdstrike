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

# Look up a user by email
data "crowdstrike_user" "by_email" {
  email = "jane.doe@example.com"
}

# Look up a user by UUID
data "crowdstrike_user" "by_uuid" {
  user_uuid = "654534c5-2565-43b1-89f6-a9230c0de6ba"
}

output "user_full_name" {
  value = "${data.crowdstrike_user.by_email.first_name} ${data.crowdstrike_user.by_email.last_name}"
}
