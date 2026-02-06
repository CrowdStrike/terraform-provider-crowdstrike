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

# Get all suppression rules
data "crowdstrike_cloud_security_suppression_rules" "all" {}

# Use FQL for advanced filtering
data "crowdstrike_cloud_security_suppression_rules" "fql_advanced" {
  fql = "name:*'Production*'+suppression_reason:'false-positive'"
}

# Combine multiple filters (logical AND)
data "crowdstrike_cloud_security_suppression_rules" "combined" {
  type   = "IOM"
  reason = "compensating-control"
  name   = "Security Exception*"
}
