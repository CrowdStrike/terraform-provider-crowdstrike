package networkcontainment_test

import (
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
)

func TestAccNetworkContainmentAllowlistRulesDataSource_basic(t *testing.T) {
	rName := acctest.RandomResourceName()
	dnsServer := randomTestIPv4(t)
	domain := rName + ".example.com"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckAllowlistRuleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAllowlistRulesDataSourceConfig_basic(rName, dnsServer, domain),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownOutputValue("dns_rule", knownvalue.ObjectExact(map[string]knownvalue.Check{
						"id":               knownvalue.StringExact("containment|dns|" + dnsServer),
						"type":             knownvalue.StringExact("ip_dns"),
						"rule":             knownvalue.StringExact(dnsServer),
						"name":             knownvalue.StringExact(rName + "-dns"),
						"allow_subdomains": knownvalue.Bool(false),
					})),
					statecheck.ExpectKnownOutputValue("fqdn_rule", knownvalue.ObjectExact(map[string]knownvalue.Check{
						"id":               knownvalue.StringExact("containment|" + domain),
						"type":             knownvalue.StringExact("fqdn"),
						"rule":             knownvalue.StringExact(domain),
						"name":             knownvalue.StringExact(rName),
						"allow_subdomains": knownvalue.Bool(true),
					})),
				},
			},
		},
	})
}

func testAccAllowlistRulesDataSourceConfig_basic(name, dnsServer, domain string) string {
	return acctest.ConfigCompose(
		testAccAllowlistRuleConfig_fqdn(name, dnsServer, domain, true),
		`
data "crowdstrike_network_containment_allowlist_rules" "test" {
  depends_on = [
    crowdstrike_network_containment_allowlist_rule.dns,
    crowdstrike_network_containment_allowlist_rule.test,
  ]
}

output "dns_rule" {
  value = one([
    for r in data.crowdstrike_network_containment_allowlist_rules.test.rules : r
    if r.id == crowdstrike_network_containment_allowlist_rule.dns.id
  ])
}

output "fqdn_rule" {
  value = one([
    for r in data.crowdstrike_network_containment_allowlist_rules.test.rules : r
    if r.id == crowdstrike_network_containment_allowlist_rule.test.id
  ])
}
`)
}
