# Network containment allowlist rules can be imported by their id: containment|<rule>
# for ip_range and fqdn rules, or containment|dns|<rule> for ip_dns rules.
terraform import crowdstrike_network_containment_allowlist_rule.example 'containment|10.20.0.0/16'
terraform import crowdstrike_network_containment_allowlist_rule.dns 'containment|dns|10.0.0.53'
