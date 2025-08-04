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
resource "crowdstrike_sensor_visibility_exclusion" "group_exclusion" {
  value          = "/tmp/test-transition-1/*"
  apply_globally = true
}
