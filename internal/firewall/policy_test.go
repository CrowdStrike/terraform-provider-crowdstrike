package firewall_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccFirewallPolicyResource_basic(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-test-policy")
	resourceName := "crowdstrike_firewall_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPolicyConfig_basic(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "platform_name", "Windows"),
					resource.TestCheckResourceAttr(resourceName, "enabled", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated", "rule_group_ids"},
			},
		},
	})
}

func TestAccFirewallPolicyResource_withRuleGroup(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-test-policy")
	rgName := sdkacctest.RandomWithPrefix("tf-test-rg")
	resourceName := "crowdstrike_firewall_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPolicyConfig_withRuleGroup(rName, rgName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "platform_name", "Windows"),
					resource.TestCheckResourceAttr(resourceName, "enabled", "true"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

func TestAccFirewallPolicyResource_update(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-test-policy")
	rNameUpdated := sdkacctest.RandomWithPrefix("tf-test-policy-updated")
	resourceName := "crowdstrike_firewall_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPolicyConfig_basic(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "enabled", "false"),
				),
			},
			{
				Config: testAccFirewallPolicyConfig_updated(rNameUpdated),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rNameUpdated),
					resource.TestCheckResourceAttr(resourceName, "enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "description", "Updated description"),
				),
			},
		},
	})
}

func TestAccFirewallPolicyResource_linux(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-test-policy-linux")
	resourceName := "crowdstrike_firewall_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPolicyConfig_linux(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "platform_name", "Linux"),
				),
			},
		},
	})
}

func TestAccFirewallPolicyResource_mac(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-test-policy-mac")
	resourceName := "crowdstrike_firewall_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPolicyConfig_mac(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "platform_name", "Mac"),
				),
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

func testAccFirewallPolicyConfig_withRuleGroup(policyName, rgName string) string {
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

  rule_group_ids = [
    crowdstrike_firewall_rule_group.test.id,
  ]
}
`, policyName, rgName)
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

func TestAccFirewallPolicyResource_allSettings(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-test-policy-settings")
	resourceName := "crowdstrike_firewall_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPolicyConfig_allSettings(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "default_inbound", "DENY"),
					resource.TestCheckResourceAttr(resourceName, "default_outbound", "ALLOW"),
					resource.TestCheckResourceAttr(resourceName, "enforce", "false"),
					resource.TestCheckResourceAttr(resourceName, "test_mode", "false"),
					resource.TestCheckResourceAttr(resourceName, "local_logging", "true"),
				),
			},
			{
				Config: testAccFirewallPolicyConfig_allSettingsUpdated(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "default_inbound", "ALLOW"),
					resource.TestCheckResourceAttr(resourceName, "default_outbound", "DENY"),
					resource.TestCheckResourceAttr(resourceName, "enforce", "true"),
					resource.TestCheckResourceAttr(resourceName, "local_logging", "false"),
				),
			},
		},
	})
}

func TestAccFirewallPolicyResource_noRuleGroups(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-test-policy-norg")
	resourceName := "crowdstrike_firewall_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPolicyConfig_basic(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckNoResourceAttr(resourceName, "rule_group_ids"),
				),
			},
		},
	})
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
  test_mode        = false
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
  test_mode        = false
  local_logging    = false
}
`, rName)
}

func TestAccFirewallPolicyResource_withHostGroup(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-test-policy-hg")
	hgName := sdkacctest.RandomWithPrefix("tf-test-hg")
	hgName2 := sdkacctest.RandomWithPrefix("tf-test-hg2")
	resourceName := "crowdstrike_firewall_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPolicyConfig_withHostGroup(rName, hgName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "1"),
				),
			},
			{
				Config: testAccFirewallPolicyConfig_withTwoHostGroups(rName, hgName, hgName2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "2"),
				),
			},
		},
	})
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
