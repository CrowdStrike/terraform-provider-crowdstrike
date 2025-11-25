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

# Get all content update policies
data "crowdstrike_content_update_policies" "all" {}

# Get enabled policies
data "crowdstrike_content_update_policies" "enabled" {
  enabled = true
}

# Use FQL filter with sorting
data "crowdstrike_content_update_policies" "filtered_and_sorted" {
  filter = "enabled:true+name:'*prod*'"
  sort   = "name.asc"
}

data "crowdstrike_content_update_policies" "specific" {
  ids = [
    "policy-id-1",
    "policy-id-2"
  ]
}
