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


resource "crowdstrike_user" "example" {
  uid        = "username@example.com"
  first_name = "FirstName"
  last_name  = "LastName"
  cid        = "ABCDEF0123456789ABCDEF0123456789"
}

output "user_uuid" {
  value = crowdstrike_user.example.uuid
}
output "user_uid" {
  value = crowdstrike_user.example.uid
}
output "user_cid" {
  value = crowdstrike_user.example.cid
}
output "user_first_name" {
  value = crowdstrike_user.example.first_name
}
output "user_last_name" {
  value = crowdstrike_user.example.last_name
}
