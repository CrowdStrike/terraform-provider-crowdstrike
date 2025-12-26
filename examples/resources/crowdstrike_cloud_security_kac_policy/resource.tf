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


resource "crowdstrike_cloud_security_kac_policy" "example" {}

output "cloud_security_kac_policy" {
  value = crowdstrike_cloud_security_kac_policy.example
}
