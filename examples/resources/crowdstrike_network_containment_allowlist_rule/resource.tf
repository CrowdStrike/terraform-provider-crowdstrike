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

# Allow contained hosts to reach an internal remediation subnet.
resource "crowdstrike_network_containment_allowlist_rule" "remediation_subnet" {
  type = "ip_range"
  rule = "10.20.0.0/16"
  name = "Remediation subnet"
}

# FQDN rules need a DNS server rule so contained hosts can resolve the domain.
resource "crowdstrike_network_containment_allowlist_rule" "dns" {
  type = "ip_dns"
  rule = "10.0.0.53"
  name = "Corporate DNS"
}

resource "crowdstrike_network_containment_allowlist_rule" "updates" {
  type             = "fqdn"
  rule             = "updates.example.com"
  name             = "Patch server"
  allow_subdomains = true

  # Create the DNS rule first and destroy it last; the API rejects an fqdn
  # rule when no ip_dns rule exists.
  depends_on = [crowdstrike_network_containment_allowlist_rule.dns]
}
