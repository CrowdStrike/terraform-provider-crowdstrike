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

resource "crowdstrike_ml_file_path_exclusion" "example" {
  pattern            = "/tmp/build_artifacts/*"
  host_groups        = ["all"]
  exclude_detections = true
}
