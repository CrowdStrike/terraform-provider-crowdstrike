package firewall_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccFirewallRuleGroup_basic(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platform"), knownvalue.StringExact("Windows")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("name"), knownvalue.StringExact("Allow HTTPS")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("action"), knownvalue.StringExact("ALLOW")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("direction"), knownvalue.StringExact("OUT")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("protocol"), knownvalue.StringExact("TCP")),
					// Rule-level computed defaults round-trip (none set explicitly in the basic config).
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("address_family"), knownvalue.StringExact("IP4")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("network_location"), knownvalue.StringExact("ANY")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("watch_mode"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("executable_path"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("service_name"), knownvalue.Null()),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccFirewallRuleGroup_multipleRules(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupConfig_multipleRules(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(3)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("name"), knownvalue.StringExact("Rule 1")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(1).AtMapKey("name"), knownvalue.StringExact("Rule 2")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(2).AtMapKey("name"), knownvalue.StringExact("Rule 3")),
					// Per-index protocol + remote_port checks verify the UDP round-trip.
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("protocol"), knownvalue.StringExact("TCP")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("remote_port").AtSliceIndex(0).AtMapKey("start"), knownvalue.Int64Exact(443)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("remote_port").AtSliceIndex(0).AtMapKey("end"), knownvalue.Int64Exact(0)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(1).AtMapKey("protocol"), knownvalue.StringExact("UDP")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(1).AtMapKey("remote_port").AtSliceIndex(0).AtMapKey("start"), knownvalue.Int64Exact(53)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(2).AtMapKey("protocol"), knownvalue.StringExact("TCP")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(2).AtMapKey("remote_port").AtSliceIndex(0).AtMapKey("start"), knownvalue.Int64Exact(80)),
				},
			},
			{
				Config: testAccFirewallRuleGroupConfig_addRule(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(4)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("name"), knownvalue.StringExact("Rule 1")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(1).AtMapKey("name"), knownvalue.StringExact("Rule 2")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(2).AtMapKey("name"), knownvalue.StringExact("Rule 3")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(3).AtMapKey("name"), knownvalue.StringExact("Rule 4")),
				},
			},
			{
				Config: testAccFirewallRuleGroupConfig_multipleRules(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(3)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("name"), knownvalue.StringExact("Rule 1")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(1).AtMapKey("name"), knownvalue.StringExact("Rule 2")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(1).AtMapKey("protocol"), knownvalue.StringExact("UDP")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(2).AtMapKey("name"), knownvalue.StringExact("Rule 3")),
				},
			},
			{
				// Reorder the same three rules (Rule 3, Rule 1, Rule 2) to exercise
				// hasRuleOrderChanged's name-comparison loop on a same-count change.
				Config: testAccFirewallRuleGroupConfig_reordered(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(3)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("name"), knownvalue.StringExact("Rule 3")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(1).AtMapKey("name"), knownvalue.StringExact("Rule 1")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(2).AtMapKey("name"), knownvalue.StringExact("Rule 2")),
				},
			},
			{
				// Insert a new rule in the middle and verify ordering matches plan.
				Config: testAccFirewallRuleGroupConfig_insertMiddle(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(4)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("name"), knownvalue.StringExact("Rule 1")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(1).AtMapKey("name"), knownvalue.StringExact("Inserted Rule")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(2).AtMapKey("name"), knownvalue.StringExact("Rule 2")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(3).AtMapKey("name"), knownvalue.StringExact("Rule 3")),
				},
			},
			{
				// Clear all rules on update and verify the list resets to null.
				Config: testAccFirewallRuleGroupConfig_emptyRules(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.Null()),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				// Rule order cannot round-trip on import: with no prior config to
				// order against, rules are stored in the API's native order (the
				// reverse of submission order), so a multi-rule list differs from
				// the configured order after import.
				ImportStateVerifyIgnore: []string{"rules"},
			},
		},
	})
}

func TestAccFirewallRuleGroup_mac(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupConfig_mac(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platform"), knownvalue.StringExact("Mac")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccFirewallRuleGroup_emptyRules(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupConfig_emptyRules(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platform"), knownvalue.StringExact("Windows")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.Null()),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccFirewallRuleGroup_enabled verifies the group can be created disabled,
// enabled on update, and disabled again. The final disable also exercises the
// delete path for an already-disabled group (Delete skips the pre-delete disable
// call when enabled is false).
func TestAccFirewallRuleGroup_enabled(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupConfig_enabled(rName, false),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccFirewallRuleGroupConfig_enabled(rName, true),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccFirewallRuleGroupConfig_enabled(rName, false),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
				},
			},
		},
	})
}

func TestAccFirewallRuleGroup_linux(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupConfig_linux(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platform"), knownvalue.StringExact("Linux")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccFirewallRuleGroup_portRange(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupConfig_portRange(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("local_port").AtSliceIndex(0).AtMapKey("start"), knownvalue.Int64Exact(8000)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("local_port").AtSliceIndex(0).AtMapKey("end"), knownvalue.Int64Exact(9000)),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccFirewallRuleGroup_ipAddresses(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupConfig_ipAddresses(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("remote_address").AtSliceIndex(0).AtMapKey("address"), knownvalue.StringExact("10.0.0.0")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("remote_address").AtSliceIndex(0).AtMapKey("netmask"), knownvalue.Int64Exact(8)),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccFirewallRuleGroup_singlePortNormalization writes {start = 443, end = 443}
// and asserts state reads back as {start = 443, end = 443} (covers single-port
// normalization: buildPortPayload sends end=0 for start==end, wrapFirewallPortRanges
// restores end from plan when planStart==planEnd).
func TestAccFirewallRuleGroup_singlePortNormalization(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupConfig_singlePort(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("remote_port").AtSliceIndex(0).AtMapKey("start"), knownvalue.Int64Exact(443)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("remote_port").AtSliceIndex(0).AtMapKey("end"), knownvalue.Int64Exact(443)),
				},
			},
			{
				// Re-apply with the same config to assert no spurious diff.
				Config:   testAccFirewallRuleGroupConfig_singlePort(rName),
				PlanOnly: true,
			},
		},
	})
}

// TestAccFirewallRuleGroup_icmpWildcards verifies that "*" wildcard for icmp_type / icmp_code is preserved.
func TestAccFirewallRuleGroup_icmpWildcards(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupConfig_icmpWildcards(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("protocol"), knownvalue.StringExact("ICMPV4")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("icmp_type"), knownvalue.StringExact("*")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("icmp_code"), knownvalue.StringExact("*")),
				},
			},
		},
	})
}

// TestAccFirewallRuleGroup_fqdn verifies a valid FQDN rule (OUT direction on
// Windows) is created and round-trips through state.
func TestAccFirewallRuleGroup_fqdn(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupConfig_fqdn(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("fqdn"), knownvalue.StringExact("example.com")),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccFirewallRuleGroup_linuxFqdnRejected verifies FQDN rules on Linux platform are rejected.
func TestAccFirewallRuleGroup_linuxFqdnRejected(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccFirewallRuleGroupConfig_linuxFqdn(rName),
				ExpectError: regexp.MustCompile(`(?s)FQDN is not supported on Linux platform`),
			},
		},
	})
}

// TestAccFirewallRuleGroup_linuxUnsupportedProtocol verifies Linux-unsupported protocols are rejected.
func TestAccFirewallRuleGroup_linuxUnsupportedProtocol(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccFirewallRuleGroupConfig_linuxGRE(rName),
				ExpectError: regexp.MustCompile(`(?s)Protocol 'GRE' is not supported on Linux platform`),
			},
			{
				Config:      testAccFirewallRuleGroupConfig_linuxIGMP(rName),
				ExpectError: regexp.MustCompile(`(?s)Protocol 'IGMP' is not supported on Linux platform`),
			},
			{
				Config:      testAccFirewallRuleGroupConfig_linuxESP(rName),
				ExpectError: regexp.MustCompile(`(?s)Protocol 'ESP' is not supported on Linux platform`),
			},
		},
	})
}

// TestAccFirewallRuleGroup_fqdnRequiresOut verifies FQDN rules must have direction = OUT.
func TestAccFirewallRuleGroup_fqdnRequiresOut(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccFirewallRuleGroupConfig_fqdnInbound(rName),
				ExpectError: regexp.MustCompile(`(?s)FQDN rules must have direction set to 'OUT'`),
			},
		},
	})
}

// TestAccFirewallRuleGroup_addressFamily cycles through each accepted address
// family. IP4 and IP6 steps configure an address; the final ANY step omits
// addresses (ANY forbids them) and verifies the previously configured address
// list is cleared from state.
func TestAccFirewallRuleGroup_addressFamily(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupConfig_addressFamily(rName, "IP4", `remote_address = [{ address = "10.0.0.0", netmask = 8 }]`),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("address_family"), knownvalue.StringExact("IP4")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("remote_address"), knownvalue.ListSizeExact(1)),
				},
			},
			{
				Config: testAccFirewallRuleGroupConfig_addressFamily(rName, "IP6", `remote_address = [{ address = "2001:db8::", netmask = 32 }]`),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("address_family"), knownvalue.StringExact("IP6")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("remote_address"), knownvalue.ListSizeExact(1)),
				},
			},
			{
				Config: testAccFirewallRuleGroupConfig_addressFamily(rName, "ANY", ""),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("address_family"), knownvalue.StringExact("ANY")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("remote_address"), knownvalue.Null()),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccFirewallRuleGroup_description verifies the group-level description can be
// created empty, set on update, and reset to null on a later update.
func TestAccFirewallRuleGroup_description(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupConfig_description(rName, ""),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.Null()),
				},
			},
			{
				Config: testAccFirewallRuleGroupConfig_description(rName, "Updated description"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Updated description")),
				},
			},
			{
				Config: testAccFirewallRuleGroupConfig_description(rName, ""),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.Null()),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccFirewallRuleGroup_clearNestedLists verifies optional nested lists
// (local_port, remote_port, remote_address) can be set on a rule and then
// cleared (reset to null) on a subsequent update.
func TestAccFirewallRuleGroup_clearNestedLists(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupConfig_nestedListsSet(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("local_port"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("remote_port"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("remote_address"), knownvalue.ListSizeExact(1)),
				},
			},
			{
				Config: testAccFirewallRuleGroupConfig_nestedListsCleared(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("local_port"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("remote_port"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("remote_address"), knownvalue.Null()),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccFirewallRuleGroup_ruleFields exercises rule fields that are otherwise
// never set in other tests (watch_mode, executable_path, service_name,
// network_location, local_address) alongside DENY action and BOTH direction.
func TestAccFirewallRuleGroup_ruleFields(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupConfig_ruleFields(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("action"), knownvalue.StringExact("DENY")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("direction"), knownvalue.StringExact("BOTH")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("watch_mode"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("executable_path"), knownvalue.StringExact(`C:\Windows\System32\svchost.exe`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("service_name"), knownvalue.StringExact("TestService")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("network_location"), knownvalue.StringExact("PUBLIC")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("local_address").AtSliceIndex(0).AtMapKey("address"), knownvalue.StringExact("192.168.1.0")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("local_address").AtSliceIndex(0).AtMapKey("netmask"), knownvalue.Int64Exact(24)),
				},
			},
			{
				// Remove the optional fields and verify they reset. watch_mode and
				// network_location are optional+computed, so they revert to their
				// defaults (false / "ANY"); the plain-optional fields go null.
				Config: testAccFirewallRuleGroupConfig_ruleFieldsCleared(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("watch_mode"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("network_location"), knownvalue.StringExact("ANY")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("executable_path"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("service_name"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("local_address"), knownvalue.Null()),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccFirewallRuleGroup_fqdnWithRemoteAddress verifies FQDN and remote_address
// cannot be set together.
func TestAccFirewallRuleGroup_fqdnWithRemoteAddress(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccFirewallRuleGroupConfig_fqdnWithRemoteAddress(rName),
				ExpectError: regexp.MustCompile(`(?s)FQDN and remote_address cannot be used together`),
			},
		},
	})
}

// TestAccFirewallRuleGroup_fqdnSubdirectory verifies FQDN values with subdirectories are rejected.
func TestAccFirewallRuleGroup_fqdnSubdirectory(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccFirewallRuleGroupConfig_fqdnSubdirectory(rName),
				ExpectError: regexp.MustCompile(`(?s)FQDN should not contain subdirectories`),
			},
		},
	})
}

// TestAccFirewallRuleGroup_serviceNameNonWindows verifies service_name is rejected on non-Windows platforms.
func TestAccFirewallRuleGroup_serviceNameNonWindows(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccFirewallRuleGroupConfig_serviceNameMac(rName),
				ExpectError: regexp.MustCompile(`(?s)service_name is only supported on Windows platform`),
			},
		},
	})
}

// TestAccFirewallRuleGroup_executablePathLinux verifies executable_path is rejected on Linux.
func TestAccFirewallRuleGroup_executablePathLinux(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccFirewallRuleGroupConfig_executablePathLinux(rName),
				ExpectError: regexp.MustCompile(`(?s)executable_path is not supported on Linux platform`),
			},
		},
	})
}

// TestAccFirewallRuleGroup_icmpFieldsNonICMP verifies icmp_type is rejected on non-ICMP protocols.
func TestAccFirewallRuleGroup_icmpFieldsNonICMP(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccFirewallRuleGroupConfig_icmpFieldsTCP(rName),
				ExpectError: regexp.MustCompile(`(?s)icmp_type is only valid for ICMPV4 or ICMPV6 protocols`),
			},
		},
	})
}

// TestAccFirewallRuleGroup_portNonTCPUDP verifies local_port is rejected on non-TCP/UDP protocols.
func TestAccFirewallRuleGroup_portNonTCPUDP(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccFirewallRuleGroupConfig_portAnyProtocol(rName),
				ExpectError: regexp.MustCompile(`(?s)local_port is only valid for TCP or UDP protocols`),
			},
		},
	})
}

// TestAccFirewallRuleGroup_localAddressWithAnyFamily verifies local_address is rejected when address_family is ANY.
func TestAccFirewallRuleGroup_localAddressWithAnyFamily(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccFirewallRuleGroupConfig_localAddressAnyFamily(rName),
				ExpectError: regexp.MustCompile(`(?s)local_address cannot be set when address_family is 'ANY'`),
			},
		},
	})
}

func testAccFirewallRuleGroupConfig_basic(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "Test firewall rule group"
  platform    = "Windows"
  enabled     = true

  rules = [
    {
      name        = "Allow HTTPS"
      description = "Allow outbound HTTPS"
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
`, name)
}

func testAccFirewallRuleGroupConfig_multipleRules(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "Test firewall rule group with multiple rules"
  platform    = "Windows"
  enabled     = true

  rules = [
    {
      name        = "Rule 1"
      description = "First rule"
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
    },
    {
      name        = "Rule 2"
      description = "Second rule"
      enabled     = true
      action      = "ALLOW"
      direction   = "OUT"
      protocol    = "UDP"

      remote_port = [
        {
          start = 53
          end   = 0
        }
      ]
    },
    {
      name        = "Rule 3"
      description = "Third rule"
      enabled     = true
      action      = "ALLOW"
      direction   = "OUT"
      protocol    = "TCP"

      remote_port = [
        {
          start = 80
          end   = 0
        }
      ]
    }
  ]
}
`, name)
}

func testAccFirewallRuleGroupConfig_addRule(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "Test firewall rule group with multiple rules"
  platform    = "Windows"
  enabled     = true

  rules = [
    {
      name        = "Rule 1"
      description = "First rule"
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
    },
    {
      name        = "Rule 2"
      description = "Second rule"
      enabled     = true
      action      = "ALLOW"
      direction   = "OUT"
      protocol    = "UDP"

      remote_port = [
        {
          start = 53
          end   = 0
        }
      ]
    },
    {
      name        = "Rule 3"
      description = "Third rule"
      enabled     = true
      action      = "ALLOW"
      direction   = "OUT"
      protocol    = "TCP"

      remote_port = [
        {
          start = 80
          end   = 0
        }
      ]
    },
    {
      name        = "Rule 4"
      description = "Fourth rule - added"
      enabled     = true
      action      = "ALLOW"
      direction   = "OUT"
      protocol    = "TCP"

      remote_port = [
        {
          start = 8080
          end   = 0
        }
      ]
    }
  ]
}
`, name)
}

func testAccFirewallRuleGroupConfig_insertMiddle(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "Test firewall rule group with multiple rules"
  platform    = "Windows"
  enabled     = true

  rules = [
    {
      name        = "Rule 1"
      description = "First rule"
      enabled     = true
      action      = "ALLOW"
      direction   = "OUT"
      protocol    = "TCP"

      remote_port = [{ start = 443, end = 0 }]
    },
    {
      name        = "Inserted Rule"
      description = "Newly inserted rule"
      enabled     = true
      action      = "ALLOW"
      direction   = "OUT"
      protocol    = "TCP"

      remote_port = [{ start = 22, end = 0 }]
    },
    {
      name        = "Rule 2"
      description = "Second rule"
      enabled     = true
      action      = "ALLOW"
      direction   = "OUT"
      protocol    = "UDP"

      remote_port = [{ start = 53, end = 0 }]
    },
    {
      name        = "Rule 3"
      description = "Third rule"
      enabled     = true
      action      = "ALLOW"
      direction   = "OUT"
      protocol    = "TCP"

      remote_port = [{ start = 80, end = 0 }]
    }
  ]
}
`, name)
}

func testAccFirewallRuleGroupConfig_icmpWildcards(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "Test ICMP wildcard handling"
  platform    = "Windows"
  enabled     = true

  rules = [
    {
      name        = "ICMP Wildcard"
      description = "Allow any ICMPv4"
      enabled     = true
      action      = "ALLOW"
      direction   = "IN"
      protocol    = "ICMPV4"
      icmp_type   = "*"
      icmp_code   = "*"
    }
  ]
}
`, name)
}

func testAccFirewallRuleGroupConfig_fqdn(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "Test FQDN rule"
  platform    = "Windows"
  enabled     = true

  rules = [
    {
      name        = "Allow FQDN"
      description = "Allow outbound to example.com"
      enabled     = true
      action      = "ALLOW"
      direction   = "OUT"
      protocol    = "TCP"
      fqdn        = "example.com"
    }
  ]
}
`, name)
}

func testAccFirewallRuleGroupConfig_linuxFqdn(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "Linux FQDN rejection"
  platform    = "Linux"
  enabled     = true

  rules = [
    {
      name        = "Bad FQDN"
      description = "FQDN rule on Linux"
      enabled     = true
      action      = "ALLOW"
      direction   = "OUT"
      protocol    = "TCP"
      fqdn        = "example.com"
    }
  ]
}
`, name)
}

func testAccFirewallRuleGroupConfig_linuxGRE(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "Linux GRE rejection"
  platform    = "Linux"
  enabled     = true

  rules = [
    {
      name        = "Bad GRE"
      description = "GRE on Linux"
      enabled     = true
      action      = "ALLOW"
      direction   = "OUT"
      protocol    = "GRE"
    }
  ]
}
`, name)
}

func testAccFirewallRuleGroupConfig_linuxIGMP(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "Linux IGMP rejection"
  platform    = "Linux"
  enabled     = true

  rules = [
    {
      name        = "Bad IGMP"
      description = "IGMP on Linux"
      enabled     = true
      action      = "ALLOW"
      direction   = "IN"
      protocol    = "IGMP"
    }
  ]
}
`, name)
}

func testAccFirewallRuleGroupConfig_linuxESP(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "Linux ESP rejection"
  platform    = "Linux"
  enabled     = true

  rules = [
    {
      name        = "Bad ESP"
      description = "ESP on Linux"
      enabled     = true
      action      = "ALLOW"
      direction   = "IN"
      protocol    = "ESP"
    }
  ]
}
`, name)
}

func testAccFirewallRuleGroupConfig_fqdnInbound(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "FQDN with inbound direction"
  platform    = "Windows"
  enabled     = true

  rules = [
    {
      name        = "Bad FQDN Direction"
      description = "FQDN with IN direction"
      enabled     = true
      action      = "ALLOW"
      direction   = "IN"
      protocol    = "TCP"
      fqdn        = "example.com"
    }
  ]
}
`, name)
}

func testAccFirewallRuleGroupConfig_mac(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "Test Mac firewall rule group"
  platform    = "Mac"
  enabled     = true

  rules = [
    {
      name        = "Allow HTTPS"
      description = "Allow outbound HTTPS"
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
`, name)
}

func testAccFirewallRuleGroupConfig_emptyRules(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "Test rule group with no rules"
  platform    = "Windows"
  enabled     = true
}
`, name)
}

func testAccFirewallRuleGroupConfig_enabled(name string, enabled bool) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name     = %[1]q
  platform = "Windows"
  enabled  = %[2]t

  rules = [
    {
      name        = "Allow HTTPS"
      enabled     = true
      action      = "ALLOW"
      direction   = "OUT"
      protocol    = "TCP"
      remote_port = [{ start = 443, end = 0 }]
    }
  ]
}
`, name, enabled)
}

func testAccFirewallRuleGroupConfig_linux(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "Test Linux firewall rule group"
  platform    = "Linux"
  enabled     = true

  rules = [
    {
      name        = "Allow SSH"
      description = "Allow inbound SSH"
      enabled     = true
      action      = "ALLOW"
      direction   = "IN"
      protocol    = "TCP"
      local_port  = [{ start = 22, end = 0 }]
    }
  ]
}
`, name)
}

func testAccFirewallRuleGroupConfig_portRange(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "Test port range"
  platform    = "Windows"
  enabled     = true

  rules = [
    {
      name        = "High Ports"
      description = "Allow high port range"
      enabled     = true
      action      = "ALLOW"
      direction   = "IN"
      protocol    = "TCP"
      local_port  = [{ start = 8000, end = 9000 }]
    }
  ]
}
`, name)
}

func testAccFirewallRuleGroupConfig_ipAddresses(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "Test IP address restrictions"
  platform    = "Windows"
  enabled     = true

  rules = [
    {
      name           = "Internal Network"
      description    = "Allow internal network"
      enabled        = true
      action         = "ALLOW"
      direction      = "IN"
      protocol       = "ANY"
      remote_address = [{ address = "10.0.0.0", netmask = 8 }]
    }
  ]
}
`, name)
}

func testAccFirewallRuleGroupConfig_addressFamily(name, family, addressAttr string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "Test address_family cycling"
  platform    = "Windows"
  enabled     = true

  rules = [
    {
      name           = "Family Rule"
      description    = "Rule cycling address families"
      enabled        = true
      action         = "ALLOW"
      direction      = "IN"
      protocol       = "ANY"
      address_family = %[2]q
      %[3]s
    }
  ]
}
`, name, family, addressAttr)
}

func testAccFirewallRuleGroupConfig_description(name, description string) string {
	descriptionAttr := ""
	if description != "" {
		descriptionAttr = fmt.Sprintf("description = %q", description)
	}
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name     = %[1]q
  platform = "Windows"
  enabled  = true
  %[2]s

  rules = [
    {
      name      = "Allow HTTPS"
      enabled   = true
      action    = "ALLOW"
      direction = "OUT"
      protocol  = "TCP"

      remote_port = [
        {
          start = 443
          end   = 0
        }
      ]
    }
  ]
}
`, name, descriptionAttr)
}

func testAccFirewallRuleGroupConfig_nestedListsSet(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "Test clearing nested lists"
  platform    = "Windows"
  enabled     = true

  rules = [
    {
      name           = "Nested Lists"
      description    = "Rule with nested lists set"
      enabled        = true
      action         = "ALLOW"
      direction      = "OUT"
      protocol       = "TCP"
      local_port     = [{ start = 8080, end = 0 }]
      remote_port    = [{ start = 443, end = 0 }]
      remote_address = [{ address = "10.0.0.0", netmask = 8 }]
    }
  ]
}
`, name)
}

func testAccFirewallRuleGroupConfig_nestedListsCleared(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "Test clearing nested lists"
  platform    = "Windows"
  enabled     = true

  rules = [
    {
      name        = "Nested Lists"
      description = "Rule with nested lists cleared"
      enabled     = true
      action      = "ALLOW"
      direction   = "OUT"
      protocol    = "TCP"
    }
  ]
}
`, name)
}

func testAccFirewallRuleGroupConfig_singlePort(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "Test single-port normalization"
  platform    = "Windows"
  enabled     = true

  rules = [
    {
      name      = "Single Port"
      enabled   = true
      action    = "ALLOW"
      direction = "OUT"
      protocol  = "TCP"

      remote_port = [
        {
          start = 443
          end   = 443
        }
      ]
    }
  ]
}
`, name)
}

func testAccFirewallRuleGroupConfig_reordered(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "Test firewall rule group with multiple rules"
  platform    = "Windows"
  enabled     = true

  rules = [
    {
      name        = "Rule 3"
      description = "Third rule"
      enabled     = true
      action      = "ALLOW"
      direction   = "OUT"
      protocol    = "TCP"

      remote_port = [
        {
          start = 80
          end   = 0
        }
      ]
    },
    {
      name        = "Rule 1"
      description = "First rule"
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
    },
    {
      name        = "Rule 2"
      description = "Second rule"
      enabled     = true
      action      = "ALLOW"
      direction   = "OUT"
      protocol    = "UDP"

      remote_port = [
        {
          start = 53
          end   = 0
        }
      ]
    }
  ]
}
`, name)
}

func testAccFirewallRuleGroupConfig_ruleFields(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "Test rule field round-trip"
  platform    = "Windows"
  enabled     = true

  rules = [
    {
      name             = "Field Rule"
      description      = "Exercises watch_mode, executable_path, service_name, network_location, local_address"
      enabled          = true
      action           = "DENY"
      direction        = "BOTH"
      protocol         = "TCP"
      watch_mode       = true
      executable_path  = "C:\\Windows\\System32\\svchost.exe"
      service_name     = "TestService"
      network_location = "PUBLIC"
      local_address    = [{ address = "192.168.1.0", netmask = 24 }]
    }
  ]
}
`, name)
}

func testAccFirewallRuleGroupConfig_ruleFieldsCleared(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "Test rule field round-trip"
  platform    = "Windows"
  enabled     = true

  rules = [
    {
      name        = "Field Rule"
      description = "Optional fields removed"
      enabled     = true
      action      = "DENY"
      direction   = "BOTH"
      protocol    = "TCP"
    }
  ]
}
`, name)
}

func testAccFirewallRuleGroupConfig_fqdnWithRemoteAddress(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "FQDN with remote_address"
  platform    = "Windows"
  enabled     = true

  rules = [
    {
      name           = "Bad FQDN Address"
      description    = "FQDN combined with remote_address"
      enabled        = true
      action         = "ALLOW"
      direction      = "OUT"
      protocol       = "TCP"
      fqdn           = "example.com"
      remote_address = [{ address = "10.0.0.0", netmask = 8 }]
    }
  ]
}
`, name)
}

func testAccFirewallRuleGroupConfig_fqdnSubdirectory(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "FQDN with subdirectory"
  platform    = "Windows"
  enabled     = true

  rules = [
    {
      name        = "Bad FQDN Subdir"
      description = "FQDN containing a subdirectory"
      enabled     = true
      action      = "ALLOW"
      direction   = "OUT"
      protocol    = "TCP"
      fqdn        = "example.com/api"
    }
  ]
}
`, name)
}

func testAccFirewallRuleGroupConfig_serviceNameMac(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "service_name on Mac"
  platform    = "Mac"
  enabled     = true

  rules = [
    {
      name         = "Bad Service"
      description  = "service_name on non-Windows"
      enabled      = true
      action       = "ALLOW"
      direction    = "OUT"
      protocol     = "TCP"
      service_name = "TestService"
    }
  ]
}
`, name)
}

func testAccFirewallRuleGroupConfig_executablePathLinux(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "executable_path on Linux"
  platform    = "Linux"
  enabled     = true

  rules = [
    {
      name            = "Bad Exec Path"
      description     = "executable_path on Linux"
      enabled         = true
      action          = "ALLOW"
      direction       = "OUT"
      protocol        = "TCP"
      executable_path = "/usr/bin/curl"
    }
  ]
}
`, name)
}

func testAccFirewallRuleGroupConfig_icmpFieldsTCP(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "icmp_type on TCP"
  platform    = "Windows"
  enabled     = true

  rules = [
    {
      name        = "Bad ICMP"
      description = "icmp_type on non-ICMP protocol"
      enabled     = true
      action      = "ALLOW"
      direction   = "IN"
      protocol    = "TCP"
      icmp_type   = "8"
    }
  ]
}
`, name)
}

func testAccFirewallRuleGroupConfig_portAnyProtocol(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "local_port on ANY protocol"
  platform    = "Windows"
  enabled     = true

  rules = [
    {
      name        = "Bad Port"
      description = "local_port on non-TCP/UDP protocol"
      enabled     = true
      action      = "ALLOW"
      direction   = "IN"
      protocol    = "ANY"
      local_port  = [{ start = 80, end = 0 }]
    }
  ]
}
`, name)
}

func testAccFirewallRuleGroupConfig_localAddressAnyFamily(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "local_address with address_family ANY"
  platform    = "Windows"
  enabled     = true

  rules = [
    {
      name           = "Bad Address Family"
      description    = "local_address set with address_family ANY"
      enabled        = true
      action         = "ALLOW"
      direction      = "IN"
      protocol       = "ANY"
      address_family = "ANY"
      local_address  = [{ address = "10.0.0.0", netmask = 8 }]
    }
  ]
}
`, name)
}
