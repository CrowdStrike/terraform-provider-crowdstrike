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


data "crowdstrike_user" "example" {
  uuid = "2db50655-9b58-4d63-9ddd-3edd6499f087"
}

output "user_data_source_uuid" {
  value = data.crowdstrike_user.example.uuid
}
output "user_data_source_uid" {
  value = data.crowdstrike_user.example.uid
}
output "user_data_source_cid" {
  value = data.crowdstrike_user.example.cid
}
output "user_data_source_first_name" {
  value = data.crowdstrike_user.example.first_name
}
output "user_data_source_last_name" {
  value = data.crowdstrike_user.example.last_name
}
