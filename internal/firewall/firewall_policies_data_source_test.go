package firewall_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccFirewallPoliciesDataSource_basic(t *testing.T) {
	dataSourceName := "data.crowdstrike_firewall_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPoliciesDataSourceConfig_basic(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.#"),
				),
			},
		},
	})
}

func TestAccFirewallPoliciesDataSource_withFilter(t *testing.T) {
	dataSourceName := "data.crowdstrike_firewall_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPoliciesDataSourceConfig_withFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.#"),
				),
			},
		},
	})
}

func TestAccFirewallPoliciesDataSource_withPlatformFilter(t *testing.T) {
	dataSourceName := "data.crowdstrike_firewall_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPoliciesDataSourceConfig_withPlatformFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.#"),
				),
			},
		},
	})
}

func TestAccFirewallPoliciesDataSource_withIDs(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-test-fw-policy-ds")
	dataSourceName := "data.crowdstrike_firewall_policies.test"
	resourceName := "crowdstrike_firewall_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPoliciesDataSourceConfig_withIDs(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, "policies.#", "1"),
					resource.TestCheckResourceAttrPair(dataSourceName, "policies.0.id", resourceName, "id"),
					resource.TestCheckResourceAttrPair(dataSourceName, "policies.0.name", resourceName, "name"),
				),
			},
		},
	})
}

func TestAccFirewallPoliciesDataSource_emptyResults(t *testing.T) {
	dataSourceName := "data.crowdstrike_firewall_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPoliciesDataSourceConfig_emptyResults(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, "policies.#", "0"),
				),
			},
		},
	})
}

func testAccFirewallPoliciesDataSourceConfig_basic() string {
	return acctest.ProviderConfig + `
data "crowdstrike_firewall_policies" "test" {}
`
}

func testAccFirewallPoliciesDataSourceConfig_withFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_firewall_policies" "test" {
  filter = "platform_name:'Windows'"
}
`
}

func testAccFirewallPoliciesDataSourceConfig_withPlatformFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_firewall_policies" "test" {
  platform_name = "Windows"
}
`
}

func testAccFirewallPoliciesDataSourceConfig_withIDs(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_firewall_policy" "test" {
  name          = %[1]q
  description   = "Test firewall policy for data source test"
  platform_name = "Windows"
  enabled       = false
}

data "crowdstrike_firewall_policies" "test" {
  ids = [crowdstrike_firewall_policy.test.id]
}
`, rName)
}

func testAccFirewallPoliciesDataSourceConfig_emptyResults() string {
	return acctest.ProviderConfig + `
data "crowdstrike_firewall_policies" "test" {
  filter = "name:'NonExistentFirewallPolicyThatShouldNeverExist12345'"
}
`
}
