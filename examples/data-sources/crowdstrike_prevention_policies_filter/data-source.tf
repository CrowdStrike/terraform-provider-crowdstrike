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

# Get enabled Linux prevention policies using FQL filter
data "crowdstrike_prevention_policies" "enabled_linux" {
  filter = "platform_name:'Linux'+enabled:true"
  sort   = "name.asc"
}

# Output enabled Linux policy details
output "enabled_linux_policies" {
  description = "Details of enabled Linux prevention policies"
  value = {
    for policy in data.crowdstrike_prevention_policies.enabled_linux.policies : policy.id => {
      name        = policy.name
      description = policy.description
      enabled     = policy.enabled
      created_by  = policy.created_by
      modified_by = policy.modified_by
    }
  }
}
