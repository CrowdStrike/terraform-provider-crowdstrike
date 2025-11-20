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

# Get enabled Windows policies
data "crowdstrike_content_update_policies" "enabled_windows" {
  platform = "windows"
  enabled  = true
}

# Use FQL filter with sorting
data "crowdstrike_content_update_policies" "filtered_and_sorted" {
  filter = "enabled:true+platform_name:'linux'"
  sort   = "name.asc"
}

# Get specific content update policies by IDs
data "crowdstrike_content_update_policies" "specific" {
  ids = [
    "policy-id-1",
    "policy-id-2"
  ]
}
