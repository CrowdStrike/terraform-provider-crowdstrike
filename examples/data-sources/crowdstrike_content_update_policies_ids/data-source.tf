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

# Get specific content update policies by IDs
data "crowdstrike_content_update_policies" "specific" {
  ids = [
    "policy-id-1",
    "policy-id-2"
  ]
}
