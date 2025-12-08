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

# validate the integrated AWS account
data "crowdstrike_cloud_aws_account_validation" "this" {
  account_id = "123456789012"
}
