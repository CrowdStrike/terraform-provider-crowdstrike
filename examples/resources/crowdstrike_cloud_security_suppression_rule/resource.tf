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

# Example 1: Simple suppression rule with rule name filter
resource "crowdstrike_cloud_security_suppression_rule" "example" {
  name        = "Suppression Rule"
  type        = "IOM"
  reason      = "false-positive"
  description = "Suppress findings for IAM root user access key rule"
  comment     = "This is a known false positive in our development environment"

  rule_selection_filter = {
    names = ["IAM root user has an active access key"]
  }

  asset_filter = {
    regions = ["us-east-2"]
  }
}

# Example 2: More complex suppression rule with multiple filters
resource "crowdstrike_cloud_security_suppression_rule" "multi_filter" {
  name        = "Multi-filter Suppression Rule"
  type        = "IOM"
  reason      = "accept-risk"
  description = "Suppress high and critical findings for specific cloud providers and regions"

  rule_selection_filter = {
    severities = ["critical", "high"]
    providers  = ["AWS", "Azure"]
  }

  asset_filter = {
    cloud_providers = ["aws", "azure"]
    regions         = ["us-west-1", "eastus"]
    tags            = ["environment=dev", "team=security"]
  }
}

# Example 3: Temporary suppression with expiration
resource "crowdstrike_cloud_security_suppression_rule" "temporary" {
  name            = "Temporary Suppression"
  type            = "IOM"
  reason          = "compensating-control"
  expiration_date = "2025-12-31T23:59:59Z"

  rule_selection_filter = {
    origins = ["Default"]
  }

  asset_filter = {
    account_ids = ["123456789012"]
  }
}

output "suppression_rule" {
  value = crowdstrike_cloud_security_suppression_rule.example
}
