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

# "Any" values. An omitted address list, icmp_type or icmp_code means "any", which the
# provider stores as "*" because that is what the Falcon API reports. Writing "*" out
# means the same thing, so both of the rules below produce identical state.
resource "crowdstrike_firewall_rule_group" "icmp_rules" {
  name        = "ICMP Rules"
  description = "Allow ping, matching any address and any ICMP type or code"
  platform    = "Windows"
  enabled     = true

  rules = [
    {
      name      = "Allow Any ICMP"
      enabled   = true
      action    = "ALLOW"
      direction = "IN"
      protocol  = "ICMPV4"
      # local_address, remote_address, icmp_type and icmp_code all default to "*".
    },
    {
      name      = "Allow Any ICMP Spelled Out"
      enabled   = true
      action    = "ALLOW"
      direction = "IN"
      protocol  = "ICMPV4"

      icmp_type = "*"
      icmp_code = "*"

      local_address = [
        {
          address = "*"
        }
      ]
      remote_address = [
        {
          address = "*"
        }
      ]
    },
    {
      # A specific ICMP type with any code: echo request from any address.
      name      = "Allow Echo Request"
      enabled   = true
      action    = "ALLOW"
      direction = "IN"
      protocol  = "ICMPV4"

      icmp_type = "8"
    }
  ]
}
