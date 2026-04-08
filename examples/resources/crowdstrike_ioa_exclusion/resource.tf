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

resource "crowdstrike_ioa_exclusion" "example" {
  name        = "example-ioa-exclusion"
  description = "Exclude an approved administrative workflow"
  pattern_id  = "12345"

  cl_regex    = ".*--approved-operation.*"
  ifn_regex   = ".*approved-tool\\.exe"
  host_groups = ["all"]
}
