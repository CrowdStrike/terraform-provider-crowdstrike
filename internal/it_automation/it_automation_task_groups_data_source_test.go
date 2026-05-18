package itautomation_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccITAutomationTaskGroupsDataSource_WithIDs(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_it_automation_task_group.test"
	dataSourceName := "data.crowdstrike_it_automation_task_groups.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccITAutomationTaskGroupsDataSourceConfigWithIDs(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("id"),
						dataSourceName, tfjsonpath.New("task_groups").AtSliceIndex(0).AtMapKey("id"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("name"),
						dataSourceName, tfjsonpath.New("task_groups").AtSliceIndex(0).AtMapKey("name"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("access_type"),
						dataSourceName, tfjsonpath.New("task_groups").AtSliceIndex(0).AtMapKey("access_type"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("description"),
						dataSourceName, tfjsonpath.New("task_groups").AtSliceIndex(0).AtMapKey("description"),
						compare.ValuesSame(),
					),
				},
			},
		},
	})
}

func TestAccITAutomationTaskGroupsDataSource_IndividualFilters(t *testing.T) {
	dataSourceName := "data.crowdstrike_it_automation_task_groups.test"

	testCases := map[string]struct {
		configFunc func() string
		checkFunc  resource.TestCheckFunc
	}{
		"name": {
			configFunc: testAccITAutomationTaskGroupsDataSourceConfigWithNameFilter,
			checkFunc: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet(dataSourceName, "task_groups.#"),
			),
		},
		"access_type": {
			configFunc: testAccITAutomationTaskGroupsDataSourceConfigWithAccessTypeFilter,
			checkFunc: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet(dataSourceName, "task_groups.#"),
				resource.TestCheckResourceAttr(dataSourceName, "task_groups.0.access_type", "Public"),
			),
		},
		"fql_filter": {
			configFunc: testAccITAutomationTaskGroupsDataSourceConfigWithFQLFilter,
			checkFunc: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet(dataSourceName, "task_groups.#"),
			),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			resource.ParallelTest(t, resource.TestCase{
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				PreCheck:                 func() { acctest.PreCheck(t) },
				Steps: []resource.TestStep{
					{
						Config: tc.configFunc(),
						Check:  tc.checkFunc,
					},
				},
			})
		})
	}
}

func TestAccITAutomationTaskGroupsDataSource_ValidationErrors(t *testing.T) {
	testCases := map[string]struct {
		configFunc  func() string
		expectError *regexp.Regexp
	}{
		"filter_with_ids": {
			configFunc:  testAccITAutomationTaskGroupsDataSourceConfigValidationFilterIDs,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"filter_with_name": {
			configFunc:  testAccITAutomationTaskGroupsDataSourceConfigValidationFilterName,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"ids_with_name": {
			configFunc:  testAccITAutomationTaskGroupsDataSourceConfigValidationIDsName,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"ids_with_access_type": {
			configFunc:  testAccITAutomationTaskGroupsDataSourceConfigValidationIDsAccessType,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"all_three": {
			configFunc:  testAccITAutomationTaskGroupsDataSourceConfigValidationAllThree,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
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

func TestAccITAutomationTaskGroupsDataSource_404Handling(t *testing.T) {
	dataSourceName := "data.crowdstrike_it_automation_task_groups.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccITAutomationTaskGroupsDataSourceConfig404NonExistentID(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, "task_groups.#", "0"),
				),
			},
		},
	})
}

func testAccITAutomationTaskGroupsDataSourceConfigWithIDs(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_it_automation_task_group" "test" {
  name        = %[1]q
  description = "Test task group for data source acceptance test"
  access_type = "Public"
}

data "crowdstrike_it_automation_task_groups" "test" {
  ids = [crowdstrike_it_automation_task_group.test.id]

  depends_on = [crowdstrike_it_automation_task_group.test]
}
`, rName)
}

func testAccITAutomationTaskGroupsDataSourceConfigWithNameFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_it_automation_task_groups" "test" {
  name = "*"
}
`
}

func testAccITAutomationTaskGroupsDataSourceConfigWithAccessTypeFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_it_automation_task_groups" "test" {
  access_type = "Public"
}
`
}

func testAccITAutomationTaskGroupsDataSourceConfigWithFQLFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_it_automation_task_groups" "test" {
  filter = "access_type:'Public'"
  sort   = "name|asc"
}
`
}

func testAccITAutomationTaskGroupsDataSourceConfigValidationFilterIDs() string {
	return acctest.ProviderConfig + `
data "crowdstrike_it_automation_task_groups" "test" {
  filter = "name:'test'"
  ids    = ["00000000000000000000000000000001"]
}
`
}

func testAccITAutomationTaskGroupsDataSourceConfigValidationFilterName() string {
	return acctest.ProviderConfig + `
data "crowdstrike_it_automation_task_groups" "test" {
  filter = "access_type:'Public'"
  name   = "test"
}
`
}

func testAccITAutomationTaskGroupsDataSourceConfigValidationIDsName() string {
	return acctest.ProviderConfig + `
data "crowdstrike_it_automation_task_groups" "test" {
  ids  = ["00000000000000000000000000000001"]
  name = "test"
}
`
}

func testAccITAutomationTaskGroupsDataSourceConfigValidationIDsAccessType() string {
	return acctest.ProviderConfig + `
data "crowdstrike_it_automation_task_groups" "test" {
  ids         = ["00000000000000000000000000000001"]
  access_type = "Public"
}
`
}

func testAccITAutomationTaskGroupsDataSourceConfigValidationAllThree() string {
	return acctest.ProviderConfig + `
data "crowdstrike_it_automation_task_groups" "test" {
  filter      = "name:'test'"
  name        = "test"
  access_type = "Public"
}
`
}

func testAccITAutomationTaskGroupsDataSourceConfig404NonExistentID() string {
	return acctest.ProviderConfig + `
data "crowdstrike_it_automation_task_groups" "test" {
  ids = ["00000000000000000000000000000000"]
}
`
}
