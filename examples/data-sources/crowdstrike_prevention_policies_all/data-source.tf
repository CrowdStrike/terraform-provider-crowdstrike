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

# Get all prevention policies
data "crowdstrike_prevention_policies" "all" {
  sort = "name.asc"
}

# Output policy summary by platform
output "policy_summary" {
  description = "Summary of all prevention policies by platform"
  value = {
    for platform in distinct([for policy in data.crowdstrike_prevention_policies.all.policies : policy.platform_name]) :
    platform => {
      total    = length([for policy in data.crowdstrike_prevention_policies.all.policies : policy if policy.platform_name == platform])
      enabled  = length([for policy in data.crowdstrike_prevention_policies.all.policies : policy if policy.platform_name == platform && policy.enabled])
      disabled = length([for policy in data.crowdstrike_prevention_policies.all.policies : policy if policy.platform_name == platform && !policy.enabled])
    }
  }
}
