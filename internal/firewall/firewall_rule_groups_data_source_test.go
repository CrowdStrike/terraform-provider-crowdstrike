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

func TestAccFirewallRuleGroupsDataSource_basic(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	dataSourceName := "data.crowdstrike_firewall_rule_groups.test"
	resourceName := "crowdstrike_firewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupsDataSourceConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					// Unfiltered list; membership + fails-on-empty proves the created
					// group is present. Size cannot be pinned on a shared account.
					statecheck.CompareValueCollection(
						dataSourceName,
						[]tfjsonpath.Path{tfjsonpath.New("rule_groups"), tfjsonpath.New("id")},
						resourceName, tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
				},
			},
		},
	})
}

func TestAccFirewallRuleGroupsDataSource_withPlatformFilter(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	dataSourceName := "data.crowdstrike_firewall_rule_groups.test"
	resourceName := "crowdstrike_firewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupsDataSourceConfig_withPlatformFilter(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					// platform is a non-unique filter; membership + fails-on-empty is the
					// strongest guarantee available here. Exclusion cannot be proven
					// against a shared account that may hold other Windows rule groups.
					statecheck.CompareValueCollection(
						dataSourceName,
						[]tfjsonpath.Path{tfjsonpath.New("rule_groups"), tfjsonpath.New("id")},
						resourceName, tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
					statecheck.CompareValueCollection(
						dataSourceName,
						[]tfjsonpath.Path{tfjsonpath.New("rule_groups"), tfjsonpath.New("platform")},
						resourceName, tfjsonpath.New("platform"),
						compare.ValuesSame(),
					),
				},
			},
		},
	})
}

func TestAccFirewallRuleGroupsDataSource_ids(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	dataSourceName := "data.crowdstrike_firewall_rule_groups.test"
	resourceName := "crowdstrike_firewall_rule_group.test"
	rgPath := tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupsDataSourceConfig_ids(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("rule_groups"), knownvalue.ListSizeExact(1)),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("id"),
						dataSourceName, rgPath("id"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("name"),
						dataSourceName, rgPath("name"),
						compare.ValuesSame(),
					),
				},
			},
		},
	})
}

func TestAccFirewallRuleGroupsDataSource_nameFilter(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	dataSourceName := "data.crowdstrike_firewall_rule_groups.test"
	resourceName := "crowdstrike_firewall_rule_group.test"
	rgPath := tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupsDataSourceConfig_nameFilter(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("rule_groups"), knownvalue.ListSizeExact(1)),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("id"),
						dataSourceName, rgPath("id"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("name"),
						dataSourceName, rgPath("name"),
						compare.ValuesSame(),
					),
				},
			},
		},
	})
}

func TestAccFirewallRuleGroupsDataSource_enabledFilter(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	dataSourceName := "data.crowdstrike_firewall_rule_groups.test"
	resourceName := "crowdstrike_firewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupsDataSourceConfig_enabledFilter(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					// enabled is a non-unique filter; membership + fails-on-empty is the strongest
					// guarantee available here (CompareValueCollection cannot prove exclusion).
					statecheck.CompareValueCollection(
						dataSourceName,
						[]tfjsonpath.Path{tfjsonpath.New("rule_groups"), tfjsonpath.New("id")},
						resourceName, tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
					statecheck.CompareValueCollection(
						dataSourceName,
						[]tfjsonpath.Path{tfjsonpath.New("rule_groups"), tfjsonpath.New("enabled")},
						resourceName, tfjsonpath.New("enabled"),
						compare.ValuesSame(),
					),
				},
			},
		},
	})
}

func TestAccFirewallRuleGroupsDataSource_withFilter(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	dataSourceName := "data.crowdstrike_firewall_rule_groups.test"
	resourceName := "crowdstrike_firewall_rule_group.test"
	rgPath := tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRuleGroupsDataSourceConfig_withFilter(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("rule_groups"), knownvalue.ListSizeExact(1)),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("id"),
						dataSourceName, rgPath("id"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("name"),
						dataSourceName, rgPath("name"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("description"),
						dataSourceName, rgPath("description"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("platform"),
						dataSourceName, rgPath("platform"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("enabled"),
						dataSourceName, rgPath("enabled"),
						compare.ValuesSame(),
					),
					statecheck.ExpectKnownValue(dataSourceName, rgPath("rule_count"), knownvalue.Int64Exact(1)),
					statecheck.ExpectKnownValue(dataSourceName, rgPath("created_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(dataSourceName, rgPath("created_on"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(dataSourceName, rgPath("modified_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(dataSourceName, rgPath("modified_on"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(dataSourceName, rgPath("rules"), knownvalue.ListSizeExact(1)),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("name"),
						dataSourceName, rgPath("rules").AtSliceIndex(0).AtMapKey("name"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("action"),
						dataSourceName, rgPath("rules").AtSliceIndex(0).AtMapKey("action"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("direction"),
						dataSourceName, rgPath("rules").AtSliceIndex(0).AtMapKey("direction"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("protocol"),
						dataSourceName, rgPath("rules").AtSliceIndex(0).AtMapKey("protocol"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("remote_port"),
						dataSourceName, rgPath("rules").AtSliceIndex(0).AtMapKey("remote_port"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("enabled"),
						dataSourceName, rgPath("rules").AtSliceIndex(0).AtMapKey("enabled"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("description"),
						dataSourceName, rgPath("rules").AtSliceIndex(0).AtMapKey("description"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("address_family"),
						dataSourceName, rgPath("rules").AtSliceIndex(0).AtMapKey("address_family"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("local_port"),
						dataSourceName, rgPath("rules").AtSliceIndex(0).AtMapKey("local_port"),
						compare.ValuesSame(),
					),
				},
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
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("rule_groups"), knownvalue.ListSizeExact(0)),
				},
			},
		},
	})
}

func TestAccFirewallRuleGroupsDataSource_conflictingFilters(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccFirewallRuleGroupsDataSourceConfig_conflictingFilters(),
				ExpectError: regexp.MustCompile("Cannot specify 'filter', 'ids', and individual filter attributes together"),
			},
		},
	})
}

// testAccFirewallRuleGroupBlock returns a single Windows rule group resource with
// one rule, used as the shared fixture for the data source tests.
func testAccFirewallRuleGroupBlock(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
  name        = %[1]q
  description = "Test rule group for data source test"
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
      local_port  = [{ start = 8080, end = 0 }]
      remote_port = [{ start = 443, end = 0 }]
    }
  ]
}
`, rName)
}

func testAccFirewallRuleGroupsDataSourceConfig_basic(rName string) string {
	return testAccFirewallRuleGroupBlock(rName) + `
data "crowdstrike_firewall_rule_groups" "test" {
  depends_on = [crowdstrike_firewall_rule_group.test]
}
`
}

func testAccFirewallRuleGroupsDataSourceConfig_withFilter(rName string) string {
	return testAccFirewallRuleGroupBlock(rName) + fmt.Sprintf(`
data "crowdstrike_firewall_rule_groups" "test" {
  filter = "name:'%[1]s'"

  depends_on = [crowdstrike_firewall_rule_group.test]
}
`, rName)
}

func testAccFirewallRuleGroupsDataSourceConfig_withPlatformFilter(rName string) string {
	return testAccFirewallRuleGroupBlock(rName) + `
data "crowdstrike_firewall_rule_groups" "test" {
  platform = "Windows"

  depends_on = [crowdstrike_firewall_rule_group.test]
}
`
}

func testAccFirewallRuleGroupsDataSourceConfig_ids(rName string) string {
	return testAccFirewallRuleGroupBlock(rName) + `
data "crowdstrike_firewall_rule_groups" "test" {
  ids = [crowdstrike_firewall_rule_group.test.id]

  depends_on = [crowdstrike_firewall_rule_group.test]
}
`
}

func testAccFirewallRuleGroupsDataSourceConfig_nameFilter(rName string) string {
	return testAccFirewallRuleGroupBlock(rName) + `
data "crowdstrike_firewall_rule_groups" "test" {
  name = "${crowdstrike_firewall_rule_group.test.name}*"

  depends_on = [crowdstrike_firewall_rule_group.test]
}
`
}

func testAccFirewallRuleGroupsDataSourceConfig_enabledFilter(rName string) string {
	return testAccFirewallRuleGroupBlock(rName) + `
data "crowdstrike_firewall_rule_groups" "test" {
  enabled = true

  depends_on = [crowdstrike_firewall_rule_group.test]
}
`
}

func testAccFirewallRuleGroupsDataSourceConfig_emptyResults() string {
	return `
data "crowdstrike_firewall_rule_groups" "test" {
  filter = "name:'NonExistentRuleGroupThatShouldNeverExist12345'"
}
`
}

func testAccFirewallRuleGroupsDataSourceConfig_conflictingFilters() string {
	return `
data "crowdstrike_firewall_rule_groups" "test" {
  filter   = "platform:'0'"
  platform = "Windows"
}
`
}
