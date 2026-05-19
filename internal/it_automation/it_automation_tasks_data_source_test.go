package itautomation_test

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

func TestAccItAutomationTasksDataSource_ValidationErrors(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		configFunc  func() string
		expectError *regexp.Regexp
	}{
		"filter_with_ids": {
			configFunc:  testAccItAutomationTasksDataSourceConfigValidationFilterIDs,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"filter_with_individual": {
			configFunc:  testAccItAutomationTasksDataSourceConfigValidationFilterName,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"ids_with_individual": {
			configFunc:  testAccItAutomationTasksDataSourceConfigValidationIDsIndividual,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"invalid_type_value": {
			configFunc:  testAccItAutomationTasksDataSourceConfigValidationInvalidType,
			expectError: regexp.MustCompile(`(?s)Attribute type value must be one of.*query.*action`),
		},
		"invalid_access_type_value": {
			configFunc:  testAccItAutomationTasksDataSourceConfigValidationInvalidAccessType,
			expectError: regexp.MustCompile(`(?s)Attribute access_type value must be one of.*Public.*Shared`),
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

func TestAccItAutomationTasksDataSource_404Handling(t *testing.T) {
	dataSourceName := "data.crowdstrike_it_automation_tasks.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccItAutomationTasksDataSourceConfig404NonExistentID(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						dataSourceName,
						tfjsonpath.New("tasks"),
						knownvalue.ListSizeExact(0),
					),
				},
			},
		},
	})
}

func TestAccItAutomationTasksDataSource_ids(t *testing.T) {
	rName := acctest.RandomResourceName()
	dataSourceName := "data.crowdstrike_it_automation_tasks.test"
	resourceName := "crowdstrike_it_automation_task.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:            testAccItAutomationTasksDataSourceConfigIDs(rName),
				ConfigStateChecks: tasksDataSourceStateChecks(resourceName, dataSourceName),
			},
		},
	})
}

func TestAccItAutomationTasksDataSource_NameFilter(t *testing.T) {
	rName := acctest.RandomResourceName()
	dataSourceName := "data.crowdstrike_it_automation_tasks.test"
	resourceName := "crowdstrike_it_automation_task.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:            testAccItAutomationTasksDataSourceConfigNameFilter(rName),
				ConfigStateChecks: tasksDataSourceStateChecks(resourceName, dataSourceName),
			},
		},
	})
}

func TestAccItAutomationTasksDataSource_FQLFilter(t *testing.T) {
	rName := acctest.RandomResourceName()
	dataSourceName := "data.crowdstrike_it_automation_tasks.test"
	resourceName := "crowdstrike_it_automation_task.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:            testAccItAutomationTasksDataSourceConfigFQLFilter(rName),
				ConfigStateChecks: tasksDataSourceStateChecks(resourceName, dataSourceName),
			},
		},
	})
}

// tasksDataSourceStateChecks verifies the data source returns exactly one task
// matching the managed resource fixture, and compares every attribute exposed
// by both the resource and the data source.
func tasksDataSourceStateChecks(resourceName, dataSourceName string) []statecheck.StateCheck {
	attrs := []string{
		"id",
		"name",
		"description",
		"type",
		"access_type",
		"target",
		"os_query",
		"task_group_id",
		"linux_script_content",
		"linux_script_file_id",
		"linux_script_language",
		"mac_script_content",
		"mac_script_file_id",
		"mac_script_language",
		"windows_script_content",
		"windows_script_file_id",
		"windows_script_language",
	}

	taskPath := tfjsonpath.New("tasks").AtSliceIndex(0)

	checks := []statecheck.StateCheck{
		statecheck.ExpectKnownValue(
			dataSourceName,
			tfjsonpath.New("tasks"),
			knownvalue.ListSizeExact(1),
		),
		// assigned_user_ids, additional_file_ids, assigned_user_group_ids: the API returns
		// nil for these fields on tasks that have none, so the data source stores null.
		statecheck.ExpectKnownValue(
			dataSourceName,
			taskPath.AtMapKey("assigned_user_ids"),
			knownvalue.Null(),
		),
		statecheck.ExpectKnownValue(
			dataSourceName,
			taskPath.AtMapKey("additional_file_ids"),
			knownvalue.Null(),
		),
		// Data-source-only computed attributes.
		statecheck.ExpectKnownValue(
			dataSourceName,
			taskPath.AtMapKey("assigned_user_group_ids"),
			knownvalue.Null(),
		),
		statecheck.ExpectKnownValue(
			dataSourceName,
			taskPath.AtMapKey("supported_os"),
			knownvalue.NotNull(),
		),
		statecheck.ExpectKnownValue(
			dataSourceName,
			taskPath.AtMapKey("has_task_parameters"),
			knownvalue.Bool(false),
		),
		statecheck.ExpectKnownValue(
			dataSourceName,
			taskPath.AtMapKey("runs"),
			knownvalue.NotNull(),
		),
		statecheck.ExpectKnownValue(
			dataSourceName,
			taskPath.AtMapKey("created_by"),
			knownvalue.NotNull(),
		),
		statecheck.ExpectKnownValue(
			dataSourceName,
			taskPath.AtMapKey("created_time"),
			knownvalue.NotNull(),
		),
		statecheck.ExpectKnownValue(
			dataSourceName,
			taskPath.AtMapKey("modified_by"),
			knownvalue.NotNull(),
		),
		statecheck.ExpectKnownValue(
			dataSourceName,
			taskPath.AtMapKey("modified_time"),
			knownvalue.NotNull(),
		),
	}
	for _, a := range attrs {
		checks = append(checks, statecheck.CompareValuePairs(
			resourceName, tfjsonpath.New(a),
			dataSourceName, taskPath.AtMapKey(a),
			compare.ValuesSame(),
		))
	}
	return checks
}

func testAccItAutomationTasksDataSourceConfigValidationFilterIDs() string {
	return acctest.ProviderConfig + `
data "crowdstrike_it_automation_tasks" "test" {
  filter = "access_type:'Public'"
  ids    = ["id-one", "id-two"]
}
`
}

func testAccItAutomationTasksDataSourceConfigValidationFilterName() string {
	return acctest.ProviderConfig + `
data "crowdstrike_it_automation_tasks" "test" {
  filter = "access_type:'Public'"
  name   = "test"
}
`
}

func testAccItAutomationTasksDataSourceConfigValidationIDsIndividual() string {
	return acctest.ProviderConfig + `
data "crowdstrike_it_automation_tasks" "test" {
  ids         = ["id-one"]
  access_type = "Public"
}
`
}

func testAccItAutomationTasksDataSourceConfigValidationInvalidType() string {
	return acctest.ProviderConfig + `
data "crowdstrike_it_automation_tasks" "test" {
  type = "invalid-type"
}
`
}

func testAccItAutomationTasksDataSourceConfigValidationInvalidAccessType() string {
	return acctest.ProviderConfig + `
data "crowdstrike_it_automation_tasks" "test" {
  access_type = "Private"
}
`
}

func testAccItAutomationTasksDataSourceConfig404NonExistentID() string {
	return acctest.ProviderConfig + `
data "crowdstrike_it_automation_tasks" "test" {
  ids = ["00000000000000000000000000000000"]
}
`
}

func testAccItAutomationTasksDataSourceConfigIDs(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_it_automation_task" "test" {
  name        = %[1]q
  access_type = "Public"
  description = "Test task for data source acceptance test"
  type        = "query"
  os_query    = "SELECT * FROM system_info;"
}

data "crowdstrike_it_automation_tasks" "test" {
  ids = [crowdstrike_it_automation_task.test.id]
}
`, rName)
}

func testAccItAutomationTasksDataSourceConfigNameFilter(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_it_automation_task" "test" {
  name        = %[1]q
  access_type = "Public"
  description = "Test task for data source name filter test"
  type        = "query"
  os_query    = "SELECT * FROM system_info;"
}

data "crowdstrike_it_automation_tasks" "test" {
  name = crowdstrike_it_automation_task.test.name
}
`, rName)
}

func testAccItAutomationTasksDataSourceConfigFQLFilter(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_it_automation_task" "test" {
  name        = %[1]q
  access_type = "Public"
  description = "Test task for data source FQL filter test"
  type        = "query"
  os_query    = "SELECT * FROM system_info;"
}

data "crowdstrike_it_automation_tasks" "test" {
  filter = format("name:'%%s'", crowdstrike_it_automation_task.test.name)
}
`, rName)
}
