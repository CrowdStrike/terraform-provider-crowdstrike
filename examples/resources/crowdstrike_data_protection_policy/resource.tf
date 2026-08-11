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

resource "crowdstrike_data_protection_policy" "example" {
  platform_name = "Windows" # Valid values: "Windows", "Mac"
  name          = "engineering-endpoints"
  description   = "Data protection for engineering workstations"
  enabled       = true

  host_groups     = [crowdstrike_host_group.engineering.id]
  classifications = ["3a1b5c7d9e0f42a8b6c4d2e0f8a6b4c2"]

  content_inspection    = true
  context_inspection    = true
  clipboard_inspection  = true
  inspection_depth      = "balanced"
  inspection_confidence = "medium"
}
