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

output "user" {
  value = crowdstrike_user.example
}
