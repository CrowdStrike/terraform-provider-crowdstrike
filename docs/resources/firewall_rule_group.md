---
page_title: "crowdstrike_firewall_rule_group Resource - crowdstrike"
subcategory: "Firewall Management"
description: |-
  This resource allows management of CrowdStrike Firewall rule groups. A rule group is a collection of firewall rules that can be assigned to firewall policies.
  API Scopes
  The following API scopes are required:
  Firewall management | Read & Write
---

# crowdstrike_firewall_rule_group (Resource)

This resource allows management of CrowdStrike Firewall rule groups. A rule group is a collection of firewall rules that can be assigned to firewall policies.

## API Scopes

The following API scopes are required:

- Firewall management | Read & Write


## Example Usage

```terraform
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
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `enabled` (Boolean) Whether the rule group is enabled.
- `name` (String) Name of the firewall rule group.
- `platform` (String) Platform for the rule group. One of: `Windows`, `Mac`, `Linux`.

### Optional

- `description` (String) Description of the firewall rule group.
- `rules` (Attributes List) List of firewall rules in this rule group. Rule precedence is determined by the order in the list. (see [below for nested schema](#nestedatt--rules))

### Read-Only

- `id` (String) Identifier for the firewall rule group.

<a id="nestedatt--rules"></a>
### Nested Schema for `rules`

Required:

- `action` (String) Action to take when the rule matches. One of: `ALLOW`, `DENY`.
- `direction` (String) Traffic direction for the rule. One of: `IN`, `OUT`, `BOTH`.
- `name` (String) Name of the firewall rule.
- `protocol` (String) Protocol for the rule. Named protocols: `TCP`, `UDP`, `ICMPV4`, `ICMPV6`, `IPV6 ENCAPSULATION`, `ANY`. Additional protocols reachable via the console's Advanced (numeric protocol) option: `GRE`, `ESP`, `IGMP`, `IP-IN-IP`. Note: Some protocols have platform restrictions (see platform documentation).

Optional:

- `address_family` (String) Address family for the rule. One of: `IP4`, `IP6`, `ANY` (`ANY` matches any address family and clears any configured addresses). Must be `IP6` or `ANY` on an `ICMPV6` rule, and `IP4` or `ANY` on an `ICMPV4` rule, because each ICMP protocol runs over only its own address family. Defaults to `IP4`.
- `description` (String) Description of the firewall rule.
- `enabled` (Boolean) Whether the rule is enabled. Defaults to `true`.
- `executable_path` (String) Path to executable that this rule applies to.
- `fqdn` (String) Fully qualified domain name for the rule. Only valid for outbound rules. Multiple FQDNs can be separated by semicolons. Wildcard (`*.example.com`) and glob syntax are supported. Removing this attribute turns the rule back into an IP address rule; the API has no way to erase the stored domain, so it remains on the rule server-side without effect.
- `icmp_code` (String) ICMP code for ICMP protocol rules. Omit it, or use `*`, to match any ICMP code. Only valid for `ICMPV4` and `ICMPV6`; it is null on every other protocol. Defaults to `*` on `ICMPV4` and `ICMPV6` rules.
- `icmp_type` (String) ICMP type for ICMP protocol rules. Omit it, or use `*`, to match any ICMP type. Only valid for `ICMPV4` and `ICMPV6`; it is null on every other protocol. Defaults to `*` on `ICMPV4` and `ICMPV6` rules.
- `local_address` (Attributes List) Local IP addresses for the rule. Omit it, or use a single entry whose `address` is `*`, to match any local address. Defaults to a single entry with `address` `*` and `netmask` 0. (see [below for nested schema](#nestedatt--rules--local_address))
- `local_port` (Attributes List) Local ports for the rule. Only applicable for TCP/UDP protocols. Omit it to match any port. (see [below for nested schema](#nestedatt--rules--local_port))
- `network_location` (String) Network location restriction. One of the built-in values `ANY`, `DOMAIN`, `PRIVATE`, `PUBLIC`, or a custom network location ID. Only `ANY` is valid on Linux. Defaults to `ANY`.
- `remote_address` (Attributes List) Remote IP addresses for the rule. Omit it, or use a single entry whose `address` is `*`, to match any remote address. Defaults to a single entry with `address` `*` and `netmask` 0. (see [below for nested schema](#nestedatt--rules--remote_address))
- `remote_port` (Attributes List) Remote ports for the rule. Only applicable for TCP/UDP protocols. Omit it to match any port. (see [below for nested schema](#nestedatt--rules--remote_port))
- `service_name` (String) Windows service name that this rule applies to. Only valid for Windows platform.
- `watch_mode` (Boolean) Enable watch mode (monitoring) for this rule instead of enforcing. Defaults to `false`.

Read-Only:

- `id` (String) Identifier for the firewall rule. This is the Rule ID shown in the Falcon console and in firewall events. Falcon assigns it when the rule is created and the rule keeps it for its lifetime: editing the rule's settings, renaming it, and moving it within the group all preserve it. Renaming a rule and changing its settings in the same apply replaces the rule, which assigns a new identifier.

<a id="nestedatt--rules--local_address"></a>
### Nested Schema for `rules.local_address`

Required:

- `address` (String) IP address for the rule, or `*` to match any address.

Optional:

- `netmask` (Number) CIDR netmask. Use 0 for a single IP, and for the `*` address. Defaults to `0`.


<a id="nestedatt--rules--local_port"></a>
### Nested Schema for `rules.local_port`

Required:

- `start` (Number) Start port (1-65535).

Optional:

- `end` (Number) End port for a range. Must be greater than `start`. Omit it, or use 0, for a single port. Defaults to `0`.


<a id="nestedatt--rules--remote_address"></a>
### Nested Schema for `rules.remote_address`

Required:

- `address` (String) IP address for the rule, or `*` to match any address.

Optional:

- `netmask` (Number) CIDR netmask. Use 0 for a single IP, and for the `*` address. Defaults to `0`.


<a id="nestedatt--rules--remote_port"></a>
### Nested Schema for `rules.remote_port`

Required:

- `start` (Number) Start port (1-65535).

Optional:

- `end` (Number) End port for a range. Must be greater than `start`. Omit it, or use 0, for a single port. Defaults to `0`.

## Import

Import is supported using the following syntax:

```shell
#!/bin/bash
# Import an existing firewall rule group by its ID
terraform import crowdstrike_firewall_rule_group.web_servers <rule_group_id>
```
