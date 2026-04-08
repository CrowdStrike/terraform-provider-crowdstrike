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

func TestAccHostGroupDataSource_ByName(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_host_group.test"
	dataSourceName := "data.crowdstrike_host_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccHostGroupDataSourceConfigByName(rName),
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
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("description"),
						dataSourceName, tfjsonpath.New("description"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("type"),
						dataSourceName, tfjsonpath.New("type"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("assignment_rule"),
						dataSourceName, tfjsonpath.New("assignment_rule"),
						compare.ValuesSame(),
					),
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("created_by"),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("created_timestamp"),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("modified_by"),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("modified_timestamp"),
						knownvalue.NotNull(),
					),
				},
			},
		},
	})
}

func TestAccHostGroupDataSource_ByID(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_host_group.test"
	dataSourceName := "data.crowdstrike_host_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccHostGroupDataSourceConfigByID(rName),
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
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("description"),
						dataSourceName, tfjsonpath.New("description"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("type"),
						dataSourceName, tfjsonpath.New("type"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("assignment_rule"),
						dataSourceName, tfjsonpath.New("assignment_rule"),
						compare.ValuesSame(),
					),
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("created_by"),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("created_timestamp"),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("modified_by"),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("modified_timestamp"),
						knownvalue.NotNull(),
					),
				},
			},
		},
	})
}

func TestAccHostGroupDataSource_ValidationErrors(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		configFunc  func() string
		expectError *regexp.Regexp
	}{
		"neither_id_nor_name": {
			configFunc:  testAccHostGroupDataSourceConfigNeither,
			expectError: regexp.MustCompile(`No attribute specified when one \(and only one\) of \[name,id\] is required`),
		},
		"both_id_and_name": {
			configFunc:  testAccHostGroupDataSourceConfigBoth,
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

func TestAccHostGroupDataSource_NotFound(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccHostGroupDataSourceConfigNotFoundName(),
				ExpectError: regexp.MustCompile("Resource Not Found"),
			},
		},
	})
}

// Test config helpers.

func testAccHostGroupDataSourceConfigByName(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name        = %[1]q
  description = "Test host group for singular data source"
  type        = "dynamic"
  assignment_rule = "tags:'FalconGroupingTags/tf-acc-test'+os_version:*'*'"
}

data "crowdstrike_host_group" "test" {
  name = crowdstrike_host_group.test.name

  depends_on = [crowdstrike_host_group.test]
}
`, rName)
}

func testAccHostGroupDataSourceConfigByID(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name        = %[1]q
  description = "Test host group for singular data source"
  type        = "dynamic"
  assignment_rule = "tags:'FalconGroupingTags/tf-acc-test'+os_version:*'*'"
}

data "crowdstrike_host_group" "test" {
  id = crowdstrike_host_group.test.id

  depends_on = [crowdstrike_host_group.test]
}
`, rName)
}

func testAccHostGroupDataSourceConfigNeither() string {
	return acctest.ProviderConfig + `
data "crowdstrike_host_group" "test" {
}
`
}

func testAccHostGroupDataSourceConfigBoth() string {
	return acctest.ProviderConfig + `
data "crowdstrike_host_group" "test" {
  id   = "00000000000000000000000000000001"
  name = "test"
}
`
}

func testAccHostGroupDataSourceConfigNotFoundName() string {
	return acctest.ProviderConfig + `
data "crowdstrike_host_group" "test" {
  name = "tf-acc-nonexistent-host-group-name-that-should-never-exist"
}
`
}
