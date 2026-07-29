package hostgroups_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccHostGroupMembersDataSource_ByID(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_host_group.test"
	dataSourceName := "data.crowdstrike_host_group_members.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccHostGroupMembersDataSourceConfigByID(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("id"),
						dataSourceName, tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("name"),
						dataSourceName, tfjsonpath.New("name"),
						compare.ValuesSame(),
					),
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("filter"),
						knownvalue.Null(),
					),
					// The assignment rule references a random tag, so no host
					// can match it.
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("member_count"),
						knownvalue.Int64Exact(0),
					),
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("host_ids"),
						knownvalue.SetSizeExact(0),
					),
				},
			},
		},
	})
}

func TestAccHostGroupMembersDataSource_ByName(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_host_group.test"
	dataSourceName := "data.crowdstrike_host_group_members.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccHostGroupMembersDataSourceConfigByName(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("id"),
						dataSourceName, tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("name"),
						dataSourceName, tfjsonpath.New("name"),
						compare.ValuesSame(),
					),
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("member_count"),
						knownvalue.Int64Exact(0),
					),
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("host_ids"),
						knownvalue.SetSizeExact(0),
					),
				},
			},
		},
	})
}

// TestAccHostGroupMembersDataSource_AllHosts exercises a group that matches
// every host in the CID. The member count depends on the CID, so the test
// asserts the invariant that member_count always equals the size of host_ids.
func TestAccHostGroupMembersDataSource_AllHosts(t *testing.T) {
	rName := acctest.RandomResourceName()
	dataSourceName := "data.crowdstrike_host_group_members.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccHostGroupMembersDataSourceConfigAllHosts(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("host_ids"),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("member_count"),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownOutputValue(
						"count_matches_host_ids",
						knownvalue.Bool(true),
					),
				},
			},
		},
	})
}

// TestAccHostGroupMembersDataSource_Filter checks that filter is passed to the
// membership query: the group matches every host, but the filter matches no
// hostname.
func TestAccHostGroupMembersDataSource_Filter(t *testing.T) {
	rName := acctest.RandomResourceName()
	dataSourceName := "data.crowdstrike_host_group_members.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccHostGroupMembersDataSourceConfigFilter(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("member_count"),
						knownvalue.Int64Exact(0),
					),
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("host_ids"),
						knownvalue.SetSizeExact(0),
					),
				},
			},
		},
	})
}

func TestAccHostGroupMembersDataSource_InvalidFilter(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccHostGroupMembersDataSourceConfigInvalidFilter(rName),
				ExpectError: regexp.MustCompile("Invalid filter expression supplied"),
			},
		},
	})
}

func TestAccHostGroupMembersDataSource_ValidationErrors(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		configFunc  func() string
		expectError *regexp.Regexp
	}{
		"neither_id_nor_name": {
			configFunc:  testAccHostGroupMembersDataSourceConfigNeither,
			expectError: regexp.MustCompile(`No attribute specified when one \(and only one\) of \[name,id\] is required`),
		},
		"both_id_and_name": {
			configFunc:  testAccHostGroupMembersDataSourceConfigBoth,
			expectError: regexp.MustCompile(`2 attributes specified when one \(and only one\) of \[name,id\] is required`),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			resource.ParallelTest(t, resource.TestCase{
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				PreCheck:                 func() { acctest.PreCheck(t) },
				Steps: []resource.TestStep{
					{
						Config:      tc.configFunc(),
						ExpectError: tc.expectError,
					},
				},
			})
		})
	}
}

func TestAccHostGroupMembersDataSource_NotFound(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		configFunc  func() string
		expectError *regexp.Regexp
	}{
		"by_name": {
			configFunc:  testAccHostGroupMembersDataSourceConfigNotFoundName,
			expectError: regexp.MustCompile("Resource Not Found"),
		},
		"by_id": {
			configFunc:  testAccHostGroupMembersDataSourceConfigNotFoundID,
			expectError: regexp.MustCompile("Resource Not Found"),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			resource.ParallelTest(t, resource.TestCase{
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				PreCheck:                 func() { acctest.PreCheck(t) },
				Steps: []resource.TestStep{
					{
						Config:      tc.configFunc(),
						ExpectError: tc.expectError,
					},
				},
			})
		})
	}
}

// Test config helpers.

// testAccHostGroupMembersHostGroupConfig returns a dynamic host group whose
// assignment rule references a random tag, so it never has members.
func testAccHostGroupMembersHostGroupConfig(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name            = %[1]q
  description     = "Test host group for members data source"
  type            = "dynamic"
  assignment_rule = "tags:'FalconGroupingTags/%[1]s'"
}
`, rName)
}

// testAccHostGroupMembersAllHostsGroupConfig returns a dynamic host group that
// matches every host with a hostname.
func testAccHostGroupMembersAllHostsGroupConfig(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name            = %[1]q
  description     = "Test host group for members data source"
  type            = "dynamic"
  assignment_rule = "hostname:*'*'"
}
`, rName)
}

func testAccHostGroupMembersDataSourceConfigByID(rName string) string {
	return testAccHostGroupMembersHostGroupConfig(rName) + `
data "crowdstrike_host_group_members" "test" {
  id = crowdstrike_host_group.test.id
}
`
}

func testAccHostGroupMembersDataSourceConfigByName(rName string) string {
	return testAccHostGroupMembersHostGroupConfig(rName) + `
data "crowdstrike_host_group_members" "test" {
  name = crowdstrike_host_group.test.name
}
`
}

func testAccHostGroupMembersDataSourceConfigAllHosts(rName string) string {
	return testAccHostGroupMembersAllHostsGroupConfig(rName) + `
data "crowdstrike_host_group_members" "test" {
  id = crowdstrike_host_group.test.id
}

output "count_matches_host_ids" {
  value = data.crowdstrike_host_group_members.test.member_count == length(data.crowdstrike_host_group_members.test.host_ids)
}
`
}

func testAccHostGroupMembersDataSourceConfigFilter(rName string) string {
	return testAccHostGroupMembersAllHostsGroupConfig(rName) + fmt.Sprintf(`
data "crowdstrike_host_group_members" "test" {
  id     = crowdstrike_host_group.test.id
  filter = "hostname:'%[1]s'"
}
`, rName)
}

func testAccHostGroupMembersDataSourceConfigInvalidFilter(rName string) string {
	return testAccHostGroupMembersHostGroupConfig(rName) + `
data "crowdstrike_host_group_members" "test" {
  id     = crowdstrike_host_group.test.id
  filter = "not_a_real_field:'value'"
}
`
}

func testAccHostGroupMembersDataSourceConfigNeither() string {
	return `
data "crowdstrike_host_group_members" "test" {
}
`
}

func testAccHostGroupMembersDataSourceConfigBoth() string {
	return `
data "crowdstrike_host_group_members" "test" {
  id   = "00000000000000000000000000000001"
  name = "test"
}
`
}

func testAccHostGroupMembersDataSourceConfigNotFoundName() string {
	return `
data "crowdstrike_host_group_members" "test" {
  name = "tf-acc-nonexistent-host-group-name-that-should-never-exist"
}
`
}

func testAccHostGroupMembersDataSourceConfigNotFoundID() string {
	return `
data "crowdstrike_host_group_members" "test" {
  id = "00000000000000000000000000000001"
}
`
}
