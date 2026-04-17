package firewall_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccFirewallRuleGroupResource_basic(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create and Read
			{
				Config: testAccFirewallRuleGroupConfig_basic(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "platform", "Windows"),
					resource.TestCheckResourceAttr(resourceName, "enabled", "true"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
					resource.TestCheckResourceAttr(resourceName, "rules.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rules.0.name", "Allow HTTPS"),
					resource.TestCheckResourceAttr(resourceName, "rules.0.action", "ALLOW"),
					resource.TestCheckResourceAttr(resourceName, "rules.0.direction", "OUT"),
					resource.TestCheckResourceAttr(resourceName, "rules.0.protocol", "TCP"),
				),
			},
			// Import
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
		},
	})
}

func TestAccFirewallRuleGroupResource_multipleRules(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create with multiple rules
			{
				Config: testAccFirewallRuleGroupConfig_multipleRules(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "rules.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "rules.0.name", "Rule 1"),
					resource.TestCheckResourceAttr(resourceName, "rules.1.name", "Rule 2"),
					resource.TestCheckResourceAttr(resourceName, "rules.2.name", "Rule 3"),
				),
			},
			// Update - add a rule
			{
				Config: testAccFirewallRuleGroupConfig_addRule(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "rules.#", "4"),
					resource.TestCheckResourceAttr(resourceName, "rules.3.name", "Rule 4"),
				),
			},
			// Update - remove a rule
			{
				Config: testAccFirewallRuleGroupConfig_multipleRules(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "rules.#", "3"),
				),
			},
		},
	})
}

func TestAccFirewallRuleGroupResource_mac(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupConfig_mac(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "platform", "Mac"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

func testAccFirewallRuleGroupConfig_basic(name string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
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
	return acctest.ProviderConfig + fmt.Sprintf(`
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
	return acctest.ProviderConfig + fmt.Sprintf(`
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

func TestAccFirewallRuleGroupResource_emptyRules(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupConfig_emptyRules(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "platform", "Windows"),
					resource.TestCheckResourceAttr(resourceName, "rules.#", "0"),
				),
			},
		},
	})
}

func TestAccFirewallRuleGroupResource_boundaryPorts(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupConfig_boundaryPorts(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "rules.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "rules.0.name", "Min Port"),
					resource.TestCheckResourceAttr(resourceName, "rules.1.name", "Max Port"),
				),
			},
		},
	})
}

func TestAccFirewallRuleGroupResource_linux(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupConfig_linux(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "platform", "Linux"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

func TestAccFirewallRuleGroupResource_portRange(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupConfig_portRange(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "rules.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rules.0.local_port.0.start", "8000"),
					resource.TestCheckResourceAttr(resourceName, "rules.0.local_port.0.end", "9000"),
				),
			},
		},
	})
}

func TestAccFirewallRuleGroupResource_ipAddresses(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_firewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupConfig_ipAddresses(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "rules.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rules.0.remote_address.0.address", "10.0.0.0"),
					resource.TestCheckResourceAttr(resourceName, "rules.0.remote_address.0.netmask", "8"),
				),
			},
		},
	})
}

func testAccFirewallRuleGroupConfig_mac(name string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
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
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "Test rule group with no rules"
  platform    = "Windows"
  enabled     = true
}
`, name)
}

func testAccFirewallRuleGroupConfig_boundaryPorts(name string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "Test boundary port values"
  platform    = "Windows"
  enabled     = true

  rules = [
    {
      name        = "Min Port"
      description = "Rule with minimum port value"
      enabled     = true
      action      = "ALLOW"
      direction   = "IN"
      protocol    = "TCP"
      local_port  = [{ start = 1, end = 0 }]
    },
    {
      name        = "Max Port"
      description = "Rule with maximum port value"
      enabled     = true
      action      = "ALLOW"
      direction   = "IN"
      protocol    = "TCP"
      local_port  = [{ start = 65535, end = 0 }]
    }
  ]
}
`, name)
}

func testAccFirewallRuleGroupConfig_linux(name string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
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
	return acctest.ProviderConfig + fmt.Sprintf(`
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
	return acctest.ProviderConfig + fmt.Sprintf(`
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
