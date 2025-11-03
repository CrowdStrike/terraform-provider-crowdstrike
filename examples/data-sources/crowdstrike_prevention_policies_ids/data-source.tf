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

# Get specific prevention policies by their IDs
data "crowdstrike_prevention_policies" "specific_policies" {
  ids = [
    "037a1708a8504b3a9cdbfdefba05f932", # Windows platform default
    "4979a243c0d84342a66692f4810348ef", # Mac platform default
    "9913bc2788a449678ab1269f44942463"  # Linux platform default
  ]
}

# Output specific policy details
output "specific_policy_details" {
  description = "Details of the specified prevention policies"
  value = {
    for policy in data.crowdstrike_prevention_policies.specific_policies.policies : policy.id => {
      name         = policy.name
      platform     = policy.platform_name
      description  = policy.description
      enabled      = policy.enabled
      group_count  = policy.group_count
      created_by   = policy.created_by
      modified_by  = policy.modified_by
    }
  }
}
