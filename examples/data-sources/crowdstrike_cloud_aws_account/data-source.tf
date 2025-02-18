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

# return all registered AWS accounts
data "crowdstrike_cloud_aws_account" "all" {}

# return a specific AWS accounts
data "crowdstrike_cloud_aws_account" "specific" {
  account_id = "123456789012"
}

# return all accounts associated with an AWS Organizaiton
data "crowdstrike_cloud_aws_account" "org" {
  organization_id = "o-123456789012"
}
