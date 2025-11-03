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

# Get enabled Windows prevention policies using individual attributes
data "crowdstrike_prevention_policies" "windows_enabled" {
  platform = "Windows"
  enabled  = true
  sort     = "name.asc"
}

# Output enabled Windows policy list
output "windows_enabled_policies" {
  description = "List of enabled Windows prevention policies"
  value = [
    for policy in data.crowdstrike_prevention_policies.windows_enabled.policies : {
      id          = policy.id
      name        = policy.name
      platform    = policy.platform_name
      enabled     = policy.enabled
      description = policy.description
    }
  ]
}
