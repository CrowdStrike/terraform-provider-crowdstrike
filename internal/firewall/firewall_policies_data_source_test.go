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

func TestAccFirewallPoliciesDataSource_basic(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	dataSourceName := "data.crowdstrike_firewall_policies.test"
	resourceName := "crowdstrike_firewall_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPoliciesDataSourceConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("policies"), knownvalue.NotNull()),
					statecheck.CompareValueCollection(
						dataSourceName, []tfjsonpath.Path{tfjsonpath.New("policies"), tfjsonpath.New("id")},
						resourceName, tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
				},
			},
		},
	})
}

func TestAccFirewallPoliciesDataSource_withFilter(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	dataSourceName := "data.crowdstrike_firewall_policies.test"
	resourceName := "crowdstrike_firewall_policy.test"
	policyPath := tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPoliciesDataSourceConfig_withFilter(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("policies"), knownvalue.ListSizeExact(1)),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("id"),
						dataSourceName, policyPath("id"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("name"),
						dataSourceName, policyPath("name"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("platform_name"),
						dataSourceName, policyPath("platform_name"),
						compare.ValuesSame(),
					),
				},
			},
		},
	})
}

func TestAccFirewallPoliciesDataSource_withPlatformFilter(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	dataSourceName := "data.crowdstrike_firewall_policies.test"
	resourceName := "crowdstrike_firewall_policy.test"
	policyPath := tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPoliciesDataSourceConfig_withPlatformFilter(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("policies"), knownvalue.ListSizeExact(1)),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("id"),
						dataSourceName, policyPath("id"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("platform_name"),
						dataSourceName, policyPath("platform_name"),
						compare.ValuesSame(),
					),
				},
			},
		},
	})
}

func TestAccFirewallPoliciesDataSource_withNameFilter(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	dataSourceName := "data.crowdstrike_firewall_policies.test"
	resourceName := "crowdstrike_firewall_policy.test"
	policyPath := tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPoliciesDataSourceConfig_withNameFilter(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("policies"), knownvalue.ListSizeExact(1)),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("id"),
						dataSourceName, policyPath("id"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("name"),
						dataSourceName, policyPath("name"),
						compare.ValuesSame(),
					),
					statecheck.ExpectKnownValue(dataSourceName, policyPath("created_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(dataSourceName, policyPath("created_timestamp"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(dataSourceName, policyPath("modified_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(dataSourceName, policyPath("modified_timestamp"), knownvalue.NotNull()),
				},
			},
		},
	})
}

func TestAccFirewallPoliciesDataSource_withEnabledFilter(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	dataSourceName := "data.crowdstrike_firewall_policies.test"
	resourceName := "crowdstrike_firewall_policy.test"
	policyPath := tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPoliciesDataSourceConfig_withEnabledFilterMatch(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("policies"), knownvalue.ListSizeExact(1)),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("enabled"),
						dataSourceName, policyPath("enabled"),
						compare.ValuesSame(),
					),
				},
			},
			{
				Config: testAccFirewallPoliciesDataSourceConfig_withEnabledFilterNoMatch(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("policies"), knownvalue.ListSizeExact(0)),
				},
			},
		},
	})
}

func TestAccFirewallPoliciesDataSource_withIDs(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	dataSourceName := "data.crowdstrike_firewall_policies.test"
	resourceName := "crowdstrike_firewall_policy.test"
	policyPath := tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPoliciesDataSourceConfig_withIDs(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("policies"), knownvalue.ListSizeExact(1)),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("id"),
						dataSourceName, policyPath("id"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("name"),
						dataSourceName, policyPath("name"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("description"),
						dataSourceName, policyPath("description"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("platform_name"),
						dataSourceName, policyPath("platform_name"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("enabled"),
						dataSourceName, policyPath("enabled"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("host_groups"),
						dataSourceName, policyPath("host_groups"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("rule_group_ids"),
						dataSourceName, policyPath("rule_group_ids"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("default_inbound"),
						dataSourceName, policyPath("default_inbound"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("default_outbound"),
						dataSourceName, policyPath("default_outbound"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("enforce"),
						dataSourceName, policyPath("enforce"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("monitor_mode"),
						dataSourceName, policyPath("monitor_mode"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("local_logging"),
						dataSourceName, policyPath("local_logging"),
						compare.ValuesSame(),
					),
				},
			},
		},
	})
}

func TestAccFirewallPoliciesDataSource_conflictingFilters(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccFirewallPoliciesDataSourceConfig_conflicting(),
				ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
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
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("policies"), knownvalue.ListSizeExact(0)),
				},
			},
		},
	})
}

func testAccFirewallPoliciesPolicyBlock(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name            = "%[1]s-hg"
  description     = "Test host group for firewall policy data source test"
  type            = "dynamic"
  assignment_rule = "platform_name:'Windows'"
}

resource "crowdstrike_firewall_rule_group" "test" {
  name        = "%[1]s-rg"
  description = "Test rule group for firewall policy data source test"
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
  name             = %[1]q
  description      = "Test firewall policy for data source test"
  platform_name    = "Windows"
  enabled          = false
  default_inbound  = "DENY"
  default_outbound = "ALLOW"
  enforce          = false
  monitor_mode     = false
  local_logging    = true

  host_groups = [crowdstrike_host_group.test.id]

  rule_group_ids = [
    crowdstrike_firewall_rule_group.test.id,
  ]
}
`, rName)
}

func testAccFirewallPoliciesDataSourceConfig_basic(rName string) string {
	return testAccFirewallPoliciesPolicyBlock(rName) + `
data "crowdstrike_firewall_policies" "test" {
  depends_on = [crowdstrike_firewall_policy.test]
}
`
}

func testAccFirewallPoliciesDataSourceConfig_withFilter(rName string) string {
	return testAccFirewallPoliciesPolicyBlock(rName) + `
data "crowdstrike_firewall_policies" "test" {
  filter = "name.raw:'${crowdstrike_firewall_policy.test.name}'"
}
`
}

func testAccFirewallPoliciesDataSourceConfig_withPlatformFilter(rName string) string {
	return testAccFirewallPoliciesPolicyBlock(rName) + `
data "crowdstrike_firewall_policies" "test" {
  platform_name = "Windows"
  name          = "${crowdstrike_firewall_policy.test.name}*"
  depends_on    = [crowdstrike_firewall_policy.test]
}
`
}

func testAccFirewallPoliciesDataSourceConfig_withNameFilter(rName string) string {
	return testAccFirewallPoliciesPolicyBlock(rName) + `
data "crowdstrike_firewall_policies" "test" {
  name       = "${crowdstrike_firewall_policy.test.name}*"
  depends_on = [crowdstrike_firewall_policy.test]
}
`
}

func testAccFirewallPoliciesDataSourceConfig_withEnabledFilterMatch(rName string) string {
	return testAccFirewallPoliciesPolicyBlock(rName) + `
data "crowdstrike_firewall_policies" "test" {
  enabled    = false
  name       = "${crowdstrike_firewall_policy.test.name}*"
  depends_on = [crowdstrike_firewall_policy.test]
}
`
}

func testAccFirewallPoliciesDataSourceConfig_withEnabledFilterNoMatch(rName string) string {
	return testAccFirewallPoliciesPolicyBlock(rName) + `
data "crowdstrike_firewall_policies" "test" {
  enabled    = true
  name       = "${crowdstrike_firewall_policy.test.name}*"
  depends_on = [crowdstrike_firewall_policy.test]
}
`
}

func testAccFirewallPoliciesDataSourceConfig_withIDs(rName string) string {
	return testAccFirewallPoliciesPolicyBlock(rName) + `
data "crowdstrike_firewall_policies" "test" {
  ids = [crowdstrike_firewall_policy.test.id]
}
`
}

func testAccFirewallPoliciesDataSourceConfig_conflicting() string {
	return `
data "crowdstrike_firewall_policies" "test" {
  filter = "platform_name:'Windows'"
  ids    = ["0123456789abcdef0123456789abcdef"]
}
`
}

func testAccFirewallPoliciesDataSourceConfig_emptyResults() string {
	return `
data "crowdstrike_firewall_policies" "test" {
  filter = "name:'NonExistentFirewallPolicyThatShouldNeverExist12345'"
}
`
}
