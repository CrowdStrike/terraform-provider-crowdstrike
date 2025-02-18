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

resource "crowdstrike_cloud_aws_account" "org" {
  account_id                         = "123456789012"
  organization_id                    = "o-1234567890"
  is_organization_management_account = true

  realtime_visibility = {
    enabled           = true
    cloudtrail_region = "us-east-1"
  }

  dspm = {
    enabled = true
  }

  idp = {
    enabled = true
  }

  sensor_management = {
    enabled = true
  }
}
