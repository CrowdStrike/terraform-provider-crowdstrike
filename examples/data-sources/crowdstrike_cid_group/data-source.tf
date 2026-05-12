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

# Look up a CID group by name
data "crowdstrike_cid_group" "production" {
  name = "Production"
}

# Look up a CID group by ID
data "crowdstrike_cid_group" "by_id" {
  id = "dbe9c1fabd024fafaf44adf4df5f0f0f"
}
