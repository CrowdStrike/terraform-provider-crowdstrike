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

data "crowdstrike_network_containment_allowlist_rules" "all" {}

output "dns_servers" {
  value = [
    for r in data.crowdstrike_network_containment_allowlist_rules.all.rules : r.rule
    if r.type == "ip_dns"
  ]
}
