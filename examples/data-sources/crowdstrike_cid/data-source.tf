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

data "crowdstrike_cid" "current" {}

output "ccid" {
  value = data.crowdstrike_cid.current.ccid
}

output "cid" {
  value = data.crowdstrike_cid.current.cid
}
