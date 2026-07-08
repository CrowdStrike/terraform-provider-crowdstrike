terraform {
  required_providers {
    crowdstrike = {
      source = "registry.terraform.io/crowdstrike/crowdstrike"
    }
  }
}

provider "crowdstrike" {}

# Basic firewall rule group with a single rule
resource "crowdstrike_firewall_rule_group" "web_servers" {
  name        = "Web Server Rules"
  description = "Firewall rules for web servers"
  platform    = "Windows"
  enabled     = true

  rules = [
    {
      name        = "Allow HTTPS Inbound"
      description = "Allow inbound HTTPS traffic"
      enabled     = true
      action      = "ALLOW"
      direction   = "IN"
      protocol    = "TCP"

      remote_port = [
        {
          start = 443
          end   = 0
        }
      ]
    },
    {
      name        = "Allow HTTP Inbound"
      description = "Allow inbound HTTP traffic"
      enabled     = true
      action      = "ALLOW"
      direction   = "IN"
      protocol    = "TCP"

      remote_port = [
        {
          start = 80
          end   = 0
        }
      ]
    },
    {
      name        = "Block All Other Inbound"
      description = "Block all other inbound traffic"
      enabled     = true
      action      = "DENY"
      direction   = "IN"
      protocol    = "ANY"
    }
  ]
}

# Firewall rule group with IP restrictions
resource "crowdstrike_firewall_rule_group" "database_servers" {
  name        = "Database Server Rules"
  description = "Firewall rules for database servers"
  platform    = "Linux"
  enabled     = true

  rules = [
    {
      name        = "Allow PostgreSQL from App Servers"
      description = "Allow PostgreSQL connections from application server subnet"
      enabled     = true
      action      = "ALLOW"
      direction   = "IN"
      protocol    = "TCP"

      remote_address = [
        {
          address = "10.0.1.0"
          netmask = 24
        }
      ]

      local_port = [
        {
          start = 5432
          end   = 0
        }
      ]
    },
    {
      name        = "Allow MySQL from App Servers"
      description = "Allow MySQL connections from application server subnet"
      enabled     = true
      action      = "ALLOW"
      direction   = "IN"
      protocol    = "TCP"

      remote_address = [
        {
          address = "10.0.1.0"
          netmask = 24
        }
      ]

      local_port = [
        {
          start = 3306
          end   = 0
        }
      ]
    }
  ]
}

# Firewall rule group with FQDN-based rules (outbound only)
resource "crowdstrike_firewall_rule_group" "outbound_rules" {
  name        = "Outbound Access Rules"
  description = "Control outbound access to specific domains"
  platform    = "Windows"
  enabled     = true

  rules = [
    {
      name        = "Allow Updates"
      description = "Allow outbound HTTPS to update servers"
      enabled     = true
      action      = "ALLOW"
      direction   = "OUT"
      protocol    = "TCP"
      fqdn        = "update.microsoft.com;download.windowsupdate.com"

      remote_port = [
        {
          start = 443
          end   = 0
        }
      ]
    }
  ]
}

# Mac platform example (note: executable_path and service_name not supported on Mac)
resource "crowdstrike_firewall_rule_group" "mac_rules" {
  name        = "Mac Workstation Rules"
  description = "Firewall rules for Mac workstations"
  platform    = "Mac"
  enabled     = true

  rules = [
    {
      name        = "Allow Outbound HTTPS"
      description = "Allow outbound HTTPS traffic"
      enabled     = true
      action      = "ALLOW"
      direction   = "OUT"
      protocol    = "TCP"

      remote_port = [
        {
          start = 443
          end   = 0
        }
      ]
    }
  ]
}

output "firewall_rule_group" {
  value = crowdstrike_firewall_rule_group.web_servers
}
