package itautomation_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccITAutomationTaskGroupsDataSource_ByIDs(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_it_automation_task_group.test"
	dataSourceName := "data.crowdstrike_it_automation_task_groups.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccITAutomationTaskGroupsDataSourceConfigByIDs(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("task_groups"),
						knownvalue.ListSizeExact(1),
					),
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
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("task_groups").AtSliceIndex(0).AtMapKey("is_preset"),
						knownvalue.Bool(false),
					),
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("task_groups").AtSliceIndex(0).AtMapKey("created_by"),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("task_groups").AtSliceIndex(0).AtMapKey("created_time"),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("task_groups").AtSliceIndex(0).AtMapKey("modified_by"),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("task_groups").AtSliceIndex(0).AtMapKey("modified_time"),
						knownvalue.NotNull(),
					),
				},
			},
		},
	})
}

func TestAccITAutomationTaskGroupsDataSource_ByFilter(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_it_automation_task_group.test"
	dataSourceName := "data.crowdstrike_it_automation_task_groups.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccITAutomationTaskGroupsDataSourceConfigByFilter(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("task_groups"),
						knownvalue.ListSizeExact(1),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("id"),
						dataSourceName, tfjsonpath.New("task_groups").AtSliceIndex(0).AtMapKey("id"),
						compare.ValuesSame(),
					),
				},
			},
		},
	})
}

func TestAccITAutomationTaskGroupsDataSource_ByIndividualFilter(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_it_automation_task_group.test"
	dataSourceName := "data.crowdstrike_it_automation_task_groups.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccITAutomationTaskGroupsDataSourceConfigByIndividualFilter(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("task_groups"),
						knownvalue.ListSizeExact(1),
					),
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
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("task_groups").AtSliceIndex(0).AtMapKey("access_type"),
						knownvalue.StringExact("Public"),
					),
				},
			},
		},
	})
}

func testAccITAutomationTaskGroupsDataSourceConfigByIDs(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_it_automation_task_group" "test" {
  name        = %[1]q
  description = "Test task group for data source acceptance test"
  access_type = "Public"
}

data "crowdstrike_it_automation_task_groups" "test" {
  ids = [crowdstrike_it_automation_task_group.test.id]
}
`, rName)
}

func testAccITAutomationTaskGroupsDataSourceConfigByFilter(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_it_automation_task_group" "test" {
  name        = %[1]q
  description = "Test task group for data source acceptance test"
  access_type = "Public"
}

data "crowdstrike_it_automation_task_groups" "test" {
  filter = format("name:'%%s'", crowdstrike_it_automation_task_group.test.name)
  sort   = "name|asc"
}
`, rName)
}

func testAccITAutomationTaskGroupsDataSourceConfigByIndividualFilter(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_it_automation_task_group" "test" {
  name        = %[1]q
  description = "Test task group for data source acceptance test"
  access_type = "Public"
}

data "crowdstrike_it_automation_task_groups" "test" {
  name        = crowdstrike_it_automation_task_group.test.name
  access_type = "Public"
}
`, rName)
}
