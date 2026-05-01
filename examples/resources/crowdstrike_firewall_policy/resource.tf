terraform {
  required_providers {
    crowdstrike = {
      source = "registry.terraform.io/crowdstrike/crowdstrike"
    }
  }
}

provider "crowdstrike" {}

# Basic firewall policy for Windows
resource "crowdstrike_firewall_policy" "windows_basic" {
  name          = "Windows Firewall Policy"
  description   = "Basic firewall policy for Windows endpoints"
  platform_name = "Windows"
  enabled       = true

  # Policy settings
  default_inbound  = "DENY"
  default_outbound = "ALLOW"
  enforce          = false
  test_mode        = false
  local_logging    = false
}

# Firewall policy with rule groups attached
resource "crowdstrike_firewall_policy" "windows_with_rules" {
  name          = "Windows Web Server Policy"
  description   = "Firewall policy for Windows web servers with rule groups"
  platform_name = "Windows"
  enabled       = true

  rule_group_ids = [
    crowdstrike_firewall_rule_group.web_servers.id,
  ]
}

# Firewall policy with host groups attached
resource "crowdstrike_firewall_policy" "linux_servers" {
  name          = "Linux Server Policy"
  description   = "Firewall policy for Linux servers"
  platform_name = "Linux"
  enabled       = true

  host_groups = [
    "abc123def456", # Replace with actual host group ID
  ]

  rule_group_ids = [
    crowdstrike_firewall_rule_group.linux_rules.id,
  ]
}

# Mac firewall policy
resource "crowdstrike_firewall_policy" "mac_endpoints" {
  name          = "Mac Endpoint Policy"
  description   = "Firewall policy for Mac endpoints"
  platform_name = "Mac"
  enabled       = false # Disabled by default
}

# Example rule group to attach to policy
resource "crowdstrike_firewall_rule_group" "web_servers" {
  name        = "Web Server Rules"
  description = "Rules for web server traffic"
  platform    = "Windows"
  enabled     = true

  rules = [
    {
      name        = "Allow HTTPS"
      description = "Allow inbound HTTPS traffic"
      enabled     = true
      action      = "ALLOW"
      direction   = "IN"
      protocol    = "TCP"
      local_port  = [{ start = 443, end = 0 }]
    }
  ]
}

resource "crowdstrike_firewall_rule_group" "linux_rules" {
  name        = "Linux Server Rules"
  description = "Rules for Linux servers"
  platform    = "Linux"
  enabled     = true

  rules = [
    {
      name        = "Allow SSH"
      description = "Allow inbound SSH traffic"
      enabled     = true
      action      = "ALLOW"
      direction   = "IN"
      protocol    = "TCP"
      local_port  = [{ start = 22, end = 0 }]
    }
  ]
}

output "windows_policy_id" {
  value = crowdstrike_firewall_policy.windows_basic.id
}

output "linux_policy_id" {
  value = crowdstrike_firewall_policy.linux_servers.id
}
