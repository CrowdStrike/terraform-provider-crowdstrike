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

# Look up a compliance framework by ID, built-in or custom.
data "crowdstrike_cloud_compliance_framework" "by_id" {
  id = "3d67d331-d697-42f2-a3e1-e5db2e5f5f0f"
}

# Look up by name. Name equality is case sensitive and matches the whole name;
# framework names are unique, so this resolves a single framework.
data "crowdstrike_cloud_compliance_framework" "by_name" {
  filter = "compliance_framework_name:'PCI DSS Internal'"
}

# Match part of a name with a case-insensitive wildcard. Keep it narrow: matching
# more than one framework is an error.
data "crowdstrike_cloud_compliance_framework" "by_name_prefix" {
  filter = "compliance_framework_name:*'pci dss internal*'"
}

# Combine properties with "+" to pin a specific built-in benchmark release.
data "crowdstrike_cloud_compliance_framework" "by_name_authority_version" {
  filter = "compliance_framework_name:'CIS Amazon Web Services Foundations Benchmark'+compliance_framework_authority:'CIS'+compliance_framework_version:'1.4.0'"
}

# Reference the data source's attributes elsewhere
output "framework_id" {
  value = data.crowdstrike_cloud_compliance_framework.by_name.id
}

output "framework_authority" {
  value = data.crowdstrike_cloud_compliance_framework.by_name.authority
}

output "framework_version" {
  value = data.crowdstrike_cloud_compliance_framework.by_name.version
}
