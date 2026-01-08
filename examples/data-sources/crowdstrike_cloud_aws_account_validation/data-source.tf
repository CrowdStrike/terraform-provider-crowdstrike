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

# validate the integrated standalone/child AWS account
data "crowdstrike_cloud_aws_account_validation" "account" {
  account_id = "123456789012"
}

# validate the integrated AWS organization management account
data "crowdstrike_cloud_aws_account_validation" "org_account" {
  organization_id = "o-1122aabbcc"
}
