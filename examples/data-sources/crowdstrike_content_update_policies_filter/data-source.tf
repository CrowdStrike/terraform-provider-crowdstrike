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

# Use FQL filter with sorting
data "crowdstrike_content_update_policies" "filtered_and_sorted" {
  filter = "enabled:true+platform_name:'linux'"
  sort   = "name.asc"
}
