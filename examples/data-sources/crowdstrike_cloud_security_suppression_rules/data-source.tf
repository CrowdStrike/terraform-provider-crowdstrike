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
data "crowdstrike_cloud_security_suppression_rules" "all" {
}

# Filter by suppression rule type
data "crowdstrike_cloud_security_suppression_rules" "by_type" {
  type = "IOM"
}

# Filter by suppression reason
data "crowdstrike_cloud_security_suppression_rules" "by_reason" {
  reason = "false-positive"
}

# Filter by name with wildcard pattern
data "crowdstrike_cloud_security_suppression_rules" "by_name" {
  name = "Production*"
}

# Filter by description
data "crowdstrike_cloud_security_suppression_rules" "by_description" {
  description = "*load balancer*"
}

# Filter by comment text
data "crowdstrike_cloud_security_suppression_rules" "by_comment" {
  comment = "*approved by security team*"
}

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