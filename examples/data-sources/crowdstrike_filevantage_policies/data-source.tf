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

# Get all FileVantage policies
data "crowdstrike_filevantage_policies" "all" {}

# Get only enabled Windows and Linux policies
data "crowdstrike_filevantage_policies" "enabled" {
  platform_names = ["Windows", "Linux"]
  enabled        = true
}

# Get policies sorted by precedence
data "crowdstrike_filevantage_policies" "sorted" {
  sort = "precedence.desc"
}

# Get specific policies by ID
data "crowdstrike_filevantage_policies" "specific" {
  ids = [
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
    "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7"
  ]
}
