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

# List every compliance framework, built-in and custom.
data "crowdstrike_cloud_compliance_frameworks" "all" {}

# Narrow the set with an FQL filter. List all CIS benchmarks.
data "crowdstrike_cloud_compliance_frameworks" "cis" {
  filter = "compliance_framework_authority:'CIS'"
}

# Look up a specific set of frameworks by identifier. Cannot be combined with filter.
data "crowdstrike_cloud_compliance_frameworks" "by_ids" {
  ids = [
    "3d67d331-d697-42f2-a3e1-e5db2e5f5f0f",
    "8f2b1c4a-1234-4a5b-9c8d-0e1f2a3b4c5d",
  ]
}

# Reference the returned frameworks elsewhere.
output "cis_framework_names" {
  value = data.crowdstrike_cloud_compliance_frameworks.cis.frameworks[*].name
}
