package firewall_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccFirewallPolicy_basic(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPolicyConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platform_name"), knownvalue.StringExact("Windows")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_group_ids"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.Null()),
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

func TestAccFirewallPolicy_withRuleGroup(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	rgName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPolicyConfig_ruleGroup(rName, rgName, false),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_group_ids"), knownvalue.Null()),
				},
			},
			{
				Config: testAccFirewallPolicyConfig_ruleGroup(rName, rgName, true),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_group_ids"), knownvalue.ListSizeExact(1)),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("rule_group_ids").AtSliceIndex(0),
						"crowdstrike_firewall_rule_group.test", tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccFirewallPolicyConfig_ruleGroup(rName, rgName, false),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_group_ids"), knownvalue.Null()),
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

func TestAccFirewallPolicy_update(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	rNameUpdated := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPolicyConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Test firewall policy")),
				},
			},
			{
				Config: testAccFirewallPolicyConfig_updated(rNameUpdated),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rNameUpdated)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Updated description")),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccFirewallPolicyConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Test firewall policy")),
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

func TestAccFirewallPolicy_description(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPolicyConfig_description(rName, "Initial description"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Initial description")),
				},
			},
			{
				Config: testAccFirewallPolicyConfig_description(rName, "Updated description"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Updated description")),
				},
			},
			{
				Config: testAccFirewallPolicyConfig_description(rName, ""),
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

func TestAccFirewallPolicy_linux(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPolicyConfig_linux(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platform_name"), knownvalue.StringExact("Linux")),
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

func TestAccFirewallPolicy_mac(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPolicyConfig_mac(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platform_name"), knownvalue.StringExact("Mac")),
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

func TestAccFirewallPolicy_allSettings(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPolicyConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_inbound"), knownvalue.StringExact("DENY")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_outbound"), knownvalue.StringExact("ALLOW")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enforce"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("monitor_mode"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("local_logging"), knownvalue.Bool(false)),
				},
			},
			{
				Config: testAccFirewallPolicyConfig_allSettings(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_inbound"), knownvalue.StringExact("DENY")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_outbound"), knownvalue.StringExact("ALLOW")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enforce"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("monitor_mode"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("local_logging"), knownvalue.Bool(true)),
				},
			},
			{
				Config: testAccFirewallPolicyConfig_allSettingsUpdated(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_inbound"), knownvalue.StringExact("ALLOW")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_outbound"), knownvalue.StringExact("DENY")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enforce"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("local_logging"), knownvalue.Bool(false)),
				},
			},
			{
				Config: testAccFirewallPolicyConfig_enforceWithMonitorMode(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enforce"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("monitor_mode"), knownvalue.Bool(true)),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccFirewallPolicyConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_inbound"), knownvalue.StringExact("DENY")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_outbound"), knownvalue.StringExact("ALLOW")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enforce"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("monitor_mode"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("local_logging"), knownvalue.Bool(false)),
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

func TestAccFirewallPolicy_monitorModeRequiresEnforce(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccFirewallPolicyConfig_monitorModeWithoutEnforce(rName),
				ExpectError: regexp.MustCompile("monitor_mode requires enforce"),
			},
		},
	})
}

func TestAccFirewallPolicy_withHostGroup(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	hgName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	hgName2 := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPolicyConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.Null()),
				},
			},
			{
				Config: testAccFirewallPolicyConfig_withHostGroup(rName, hgName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(1)),
					statecheck.CompareValueCollection(
						resourceName,
						[]tfjsonpath.Path{tfjsonpath.New("host_groups")},
						"crowdstrike_host_group.test", tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
				},
			},
			{
				Config: testAccFirewallPolicyConfig_withTwoHostGroups(rName, hgName, hgName2),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(2)),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccFirewallPolicyConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.Null()),
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

func TestAccFirewallPolicy_ruleGroupOrdering(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	rg1 := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	rg2 := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPolicyConfig_twoRuleGroups(rName, rg1, rg2, false),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_group_ids"), knownvalue.ListSizeExact(2)),
					statecheck.CompareValuePairs(resourceName, tfjsonpath.New("rule_group_ids").AtSliceIndex(0), "crowdstrike_firewall_rule_group.test1", tfjsonpath.New("id"), compare.ValuesSame()),
					statecheck.CompareValuePairs(resourceName, tfjsonpath.New("rule_group_ids").AtSliceIndex(1), "crowdstrike_firewall_rule_group.test2", tfjsonpath.New("id"), compare.ValuesSame()),
				},
			},
			{
				Config: testAccFirewallPolicyConfig_twoRuleGroups(rName, rg1, rg2, true),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.CompareValuePairs(resourceName, tfjsonpath.New("rule_group_ids").AtSliceIndex(0), "crowdstrike_firewall_rule_group.test2", tfjsonpath.New("id"), compare.ValuesSame()),
					statecheck.CompareValuePairs(resourceName, tfjsonpath.New("rule_group_ids").AtSliceIndex(1), "crowdstrike_firewall_rule_group.test1", tfjsonpath.New("id"), compare.ValuesSame()),
				},
			},
		},
	})
}

func testAccFirewallPolicyConfig_basic(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_policy" "test" {
  name          = %[1]q
  description   = "Test firewall policy"
  platform_name = "Windows"
  enabled       = false
}
`, rName)
}

func testAccFirewallPolicyConfig_updated(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_policy" "test" {
  name          = %[1]q
  description   = "Updated description"
  platform_name = "Windows"
  enabled       = true
}
`, rName)
}

func testAccFirewallPolicyConfig_ruleGroup(policyName, rgName string, attach bool) string {
	ruleGroupIDs := ""
	if attach {
		ruleGroupIDs = `
  rule_group_ids = [
    crowdstrike_firewall_rule_group.test.id,
  ]`
	}
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[2]q
  description = "Test rule group for policy"
  platform    = "Windows"
  enabled     = true

  rules = [
    {
      name        = "Test Rule"
      description = "Test rule"
      enabled     = true
      action      = "ALLOW"
      direction   = "OUT"
      protocol    = "TCP"
      remote_port = [{ start = 443, end = 0 }]
    }
  ]
}

resource "crowdstrike_firewall_policy" "test" {
  name          = %[1]q
  description   = "Test firewall policy with rule group"
  platform_name = "Windows"
  enabled       = true
%[3]s
}
`, policyName, rgName, ruleGroupIDs)
}

func testAccFirewallPolicyConfig_twoRuleGroups(policyName, rg1Name, rg2Name string, reversed bool) string {
	order := `[
    crowdstrike_firewall_rule_group.test1.id,
    crowdstrike_firewall_rule_group.test2.id,
  ]`
	if reversed {
		order = `[
    crowdstrike_firewall_rule_group.test2.id,
    crowdstrike_firewall_rule_group.test1.id,
  ]`
	}
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test1" {
  name        = %[2]q
  description = "Test rule group 1"
  platform    = "Windows"
  enabled     = true
  rules = [{
    name = "Rule 1", description = "r1", enabled = true,
    action = "ALLOW", direction = "OUT", protocol = "TCP",
    remote_port = [{ start = 443, end = 0 }]
  }]
}

resource "crowdstrike_firewall_rule_group" "test2" {
  name        = %[3]q
  description = "Test rule group 2"
  platform    = "Windows"
  enabled     = true
  rules = [{
    name = "Rule 2", description = "r2", enabled = true,
    action = "ALLOW", direction = "OUT", protocol = "TCP",
    remote_port = [{ start = 8080, end = 0 }]
  }]
}

resource "crowdstrike_firewall_policy" "test" {
  name          = %[1]q
  description   = "Test firewall policy with two rule groups"
  platform_name = "Windows"
  enabled       = true
  rule_group_ids = %[4]s
}
`, policyName, rg1Name, rg2Name, order)
}

func testAccFirewallPolicyConfig_description(rName, description string) string {
	descriptionAttr := ""
	if description != "" {
		descriptionAttr = fmt.Sprintf("description   = %q", description)
	}
	return fmt.Sprintf(`
resource "crowdstrike_firewall_policy" "test" {
  name          = %[1]q
  %[2]s
  platform_name = "Windows"
  enabled       = false
}
`, rName, descriptionAttr)
}

func testAccFirewallPolicyConfig_linux(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_policy" "test" {
  name          = %[1]q
  description   = "Test Linux firewall policy"
  platform_name = "Linux"
  enabled       = false
}
`, rName)
}

func testAccFirewallPolicyConfig_mac(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_policy" "test" {
  name          = %[1]q
  description   = "Test Mac firewall policy"
  platform_name = "Mac"
  enabled       = false
}
`, rName)
}

func testAccFirewallPolicyConfig_allSettings(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_policy" "test" {
  name             = %[1]q
  description      = "Test policy with all settings"
  platform_name    = "Windows"
  enabled          = false
  default_inbound  = "DENY"
  default_outbound = "ALLOW"
  enforce          = false
  monitor_mode     = false
  local_logging    = true
}
`, rName)
}

func testAccFirewallPolicyConfig_allSettingsUpdated(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_policy" "test" {
  name             = %[1]q
  description      = "Test policy with updated settings"
  platform_name    = "Windows"
  enabled          = false
  default_inbound  = "ALLOW"
  default_outbound = "DENY"
  enforce          = true
  monitor_mode     = false
  local_logging    = false
}
`, rName)
}

func testAccFirewallPolicyConfig_enforceWithMonitorMode(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_policy" "test" {
  name             = %[1]q
  description      = "Test policy with enforce and monitor mode"
  platform_name    = "Windows"
  enabled          = false
  default_inbound  = "DENY"
  default_outbound = "ALLOW"
  enforce          = true
  monitor_mode     = true
  local_logging    = false
}
`, rName)
}

func testAccFirewallPolicyConfig_monitorModeWithoutEnforce(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_policy" "test" {
  name          = %[1]q
  description   = "Test policy with monitor mode but no enforce"
  platform_name = "Windows"
  enabled       = false
  enforce       = false
  monitor_mode  = true
}
`, rName)
}

func testAccFirewallPolicyConfig_withHostGroup(policyName, hgName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name            = %[2]q
  description     = "Test host group for firewall policy"
  type            = "dynamic"
  assignment_rule = "platform_name:'Windows'"
}

resource "crowdstrike_firewall_policy" "test" {
  name          = %[1]q
  description   = "Test firewall policy with host group"
  platform_name = "Windows"
  enabled       = false

  host_groups = [
    crowdstrike_host_group.test.id,
  ]
}
`, policyName, hgName)
}

func testAccFirewallPolicyConfig_withTwoHostGroups(policyName, hgName, hgName2 string) string {
	return fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name            = %[2]q
  description     = "Test host group for firewall policy"
  type            = "dynamic"
  assignment_rule = "platform_name:'Windows'"
}

resource "crowdstrike_host_group" "test2" {
  name            = %[3]q
  description     = "Second test host group for firewall policy"
  type            = "dynamic"
  assignment_rule = "platform_name:'Windows'"
}

resource "crowdstrike_firewall_policy" "test" {
  name          = %[1]q
  description   = "Test firewall policy with two host groups"
  platform_name = "Windows"
  enabled       = false

  host_groups = [
    crowdstrike_host_group.test.id,
    crowdstrike_host_group.test2.id,
  ]
}
`, policyName, hgName, hgName2)
}
