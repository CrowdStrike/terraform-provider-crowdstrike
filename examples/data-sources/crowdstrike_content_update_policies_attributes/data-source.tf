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

# Get enabled Windows policies
data "crowdstrike_content_update_policies" "enabled_windows" {
  platform = "windows"
  enabled  = true
}
