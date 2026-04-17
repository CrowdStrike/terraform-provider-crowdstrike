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

# Manage precedence of Windows firewall policies (dynamic mode)
# Policies listed here will be prioritized in order, other policies retain their relative ordering
resource "crowdstrike_firewall_policy_precedence" "example" {
  platform_name = "Windows"
  enforcement   = "dynamic"
  ids = [
    "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
    "b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7",
    "c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8",
  ]
}

output "firewall_policy_precedence" {
  value = crowdstrike_firewall_policy_precedence.example
}
