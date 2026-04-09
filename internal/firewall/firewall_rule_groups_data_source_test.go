package firewall_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccFirewallRuleGroupsDataSource_basic(t *testing.T) {
	dataSourceName := "data.crowdstrike_firewall_rule_groups.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupsDataSourceConfig_basic(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "rule_groups.#"),
				),
			},
		},
	})
}

func TestAccFirewallRuleGroupsDataSource_withFilter(t *testing.T) {
	dataSourceName := "data.crowdstrike_firewall_rule_groups.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupsDataSourceConfig_withFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "rule_groups.#"),
				),
			},
		},
	})
}

func TestAccFirewallRuleGroupsDataSource_withPlatformFilter(t *testing.T) {
	dataSourceName := "data.crowdstrike_firewall_rule_groups.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupsDataSourceConfig_withPlatformFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "rule_groups.#"),
				),
			},
		},
	})
}

func TestAccFirewallRuleGroupsDataSource_resourceMatch(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-test-fw-rg-ds")
	dataSourceName := "data.crowdstrike_firewall_rule_groups.test"
	resourceName := "crowdstrike_firewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupsDataSourceConfig_resourceMatch(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "rule_groups.#"),
					resource.TestCheckResourceAttrPair(dataSourceName, "rule_groups.0.id", resourceName, "id"),
					resource.TestCheckResourceAttrPair(dataSourceName, "rule_groups.0.name", resourceName, "name"),
				),
			},
		},
	})
}

func TestAccFirewallRuleGroupsDataSource_emptyResults(t *testing.T) {
	dataSourceName := "data.crowdstrike_firewall_rule_groups.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupsDataSourceConfig_emptyResults(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, "rule_groups.#", "0"),
				),
			},
		},
	})
}

func testAccFirewallRuleGroupsDataSourceConfig_basic() string {
	return acctest.ProviderConfig + `
data "crowdstrike_firewall_rule_groups" "test" {}
`
}

func testAccFirewallRuleGroupsDataSourceConfig_withFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_firewall_rule_groups" "test" {
  filter = "platform:'0'"
}
`
}

func testAccFirewallRuleGroupsDataSourceConfig_withPlatformFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_firewall_rule_groups" "test" {
  platform = "Windows"
}
`
}

func testAccFirewallRuleGroupsDataSourceConfig_resourceMatch(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "Test rule group for data source test"
  platform    = "Windows"
  enabled     = true
}

data "crowdstrike_firewall_rule_groups" "test" {
  filter = "name:'%[1]s'"

  depends_on = [crowdstrike_firewall_rule_group.test]
}
`, rName)
}

func testAccFirewallRuleGroupsDataSourceConfig_emptyResults() string {
	return acctest.ProviderConfig + `
data "crowdstrike_firewall_rule_groups" "test" {
  filter = "name:'NonExistentRuleGroupThatShouldNeverExist12345'"
}
`
}
