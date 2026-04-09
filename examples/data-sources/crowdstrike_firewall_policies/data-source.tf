terraform {
  required_providers {
    crowdstrike = {
      source = "registry.terraform.io/crowdstrike/crowdstrike"
    }
  }
}

provider "crowdstrike" {}

# Get all firewall policies
data "crowdstrike_firewall_policies" "all" {}

# Get firewall policies filtered by platform
data "crowdstrike_firewall_policies" "windows" {
  platform_name = "Windows"
}

# Get firewall policies filtered by name (supports wildcards)
data "crowdstrike_firewall_policies" "production" {
  name = "Production*"
}

# Get specific firewall policies by ID
data "crowdstrike_firewall_policies" "specific" {
  ids = ["policy_id_1", "policy_id_2"]
}

# Get enabled firewall policies
data "crowdstrike_firewall_policies" "enabled" {
  enabled = true
}

# Use FQL filter for advanced queries
data "crowdstrike_firewall_policies" "fql" {
  filter = "platform_name:'Windows'+enabled:true"
}

output "all_policy_names" {
  value = [for p in data.crowdstrike_firewall_policies.all.policies : p.name]
}

output "windows_policy_ids" {
  value = [for p in data.crowdstrike_firewall_policies.windows.policies : p.id]
}
