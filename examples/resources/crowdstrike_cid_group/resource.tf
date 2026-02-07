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

resource "crowdstrike_cid_group" "example" {
  name        = "Production Tenants"
  description = "Group for all production customer CIDs"

}
