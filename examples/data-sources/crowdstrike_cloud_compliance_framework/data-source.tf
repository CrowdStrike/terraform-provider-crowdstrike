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

# Look up a compliance framework by ID, built-in or custom
data "crowdstrike_cloud_compliance_framework" "by_id" {
  id = "3d67d331d69742f2a3e1e5db2e5f5f0f"
}

# Look up a compliance framework with an FQL filter. The filter must match
# exactly one framework, otherwise the lookup fails.
#
# Only compliance_framework_name, compliance_framework_version, and
# compliance_framework_authority are filterable. The framework ID is not
# filterable at all, so use the id argument above to look a framework up by ID.
#
# The default FQL operator is "equal to", which compares the whole name and is
# case sensitive. Framework names are unique, so name equality is the reliable
# way to resolve a single framework.
data "crowdstrike_cloud_compliance_framework" "by_name" {
  filter = "compliance_framework_name:'PCI DSS Internal'"
}

# Equality does no partial matching, so reach for an operator when you only know
# part of the name. Wildcards need both the operator asterisk after the colon and
# a wildcard asterisk in the value, and they ignore case. Partial matches happily
# cover several frameworks, and matching more than one is an error, so keep the
# pattern narrow.
data "crowdstrike_cloud_compliance_framework" "by_name_prefix" {
  filter = "compliance_framework_name:*'pci dss internal*'"
}

# Reference the data source's attributes elsewhere
output "framework_sections" {
  value = data.crowdstrike_cloud_compliance_framework.by_name.sections
}

output "framework_control_ids" {
  value = flatten([
    for section in values(data.crowdstrike_cloud_compliance_framework.by_name.sections) : [
      for control in values(section.controls) : control.id
    ]
  ])
}
