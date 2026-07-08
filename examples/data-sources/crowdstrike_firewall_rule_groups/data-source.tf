terraform {
  required_providers {
    crowdstrike = {
      source = "registry.terraform.io/crowdstrike/crowdstrike"
    }
  }
}

provider "crowdstrike" {}

# Get all firewall rule groups
data "crowdstrike_firewall_rule_groups" "all" {}

# Get firewall rule groups filtered by platform
data "crowdstrike_firewall_rule_groups" "windows" {
  platform = "Windows"
}

# Get firewall rule groups filtered by name (supports wildcards)
data "crowdstrike_firewall_rule_groups" "web_rules" {
  name = "Web*"
}

# Get specific firewall rule groups by ID
data "crowdstrike_firewall_rule_groups" "specific" {
  ids = ["rule_group_id_1", "rule_group_id_2"]
}

# Get enabled firewall rule groups
data "crowdstrike_firewall_rule_groups" "enabled" {
  enabled = true
}

# Use FQL filter for advanced queries
data "crowdstrike_firewall_rule_groups" "fql" {
  filter = "platform:'windows'+enabled:true"
}

output "all_rule_group_names" {
  value = [for rg in data.crowdstrike_firewall_rule_groups.all.rule_groups : rg.name]
}

output "windows_rule_group_ids" {
  value = [for rg in data.crowdstrike_firewall_rule_groups.windows.rule_groups : rg.id]
}
