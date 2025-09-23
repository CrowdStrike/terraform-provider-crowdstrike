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

# return all rules for a single cloud provider
data "crowdstrike_cloud_posture_rules" "all" {
  cloud_provider = "AWS"
}

# return a single rule within a cloud provider
data "crowdstrike_cloud_posture_rules" "specific" {
  cloud_provider = "AWS"
  rule_name      = "NLB/ALB configured publicly with TLS/SSL disabled"
}
