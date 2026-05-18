package itautomation_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
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
			configFunc:  testAccItAutomationTasksDataSourceConfigValidationFilterIndividual,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"ids_with_individual": {
			configFunc:  testAccItAutomationTasksDataSourceConfigValidationIDsIndividual,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"all_three": {
			configFunc:  testAccItAutomationTasksDataSourceConfigValidationAllThree,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"filter_with_name": {
			configFunc:  testAccItAutomationTasksDataSourceConfigValidationFilterName,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"ids_with_type": {
			configFunc:  testAccItAutomationTasksDataSourceConfigValidationIDsType,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"filter_with_access_type": {
			configFunc:  testAccItAutomationTasksDataSourceConfigValidationFilterAccessType,
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
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, "tasks.#", "0"),
				),
			},
		},
	})
}

func TestAccItAutomationTasksDataSource_ResourceMatch(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	dataSourceName := "data.crowdstrike_it_automation_tasks.test"
	resourceName := "crowdstrike_it_automation_task.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccItAutomationTasksDataSourceConfigResourceMatch(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, "tasks.#", "1"),
					resource.TestCheckResourceAttrPair(resourceName, "id", dataSourceName, "tasks.0.id"),
					resource.TestCheckResourceAttrPair(resourceName, "name", dataSourceName, "tasks.0.name"),
					resource.TestCheckResourceAttrPair(resourceName, "description", dataSourceName, "tasks.0.description"),
					resource.TestCheckResourceAttrPair(resourceName, "type", dataSourceName, "tasks.0.type"),
					resource.TestCheckResourceAttrPair(resourceName, "access_type", dataSourceName, "tasks.0.access_type"),
					resource.TestCheckResourceAttrPair(resourceName, "os_query", dataSourceName, "tasks.0.os_query"),
				),
			},
		},
	})
}

func TestAccItAutomationTasksDataSource_NameFilter(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	dataSourceName := "data.crowdstrike_it_automation_tasks.test"
	resourceName := "crowdstrike_it_automation_task.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccItAutomationTasksDataSourceConfigNameFilter(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, "tasks.#", "1"),
					resource.TestCheckResourceAttrPair(resourceName, "id", dataSourceName, "tasks.0.id"),
					resource.TestCheckResourceAttrPair(resourceName, "name", dataSourceName, "tasks.0.name"),
				),
			},
		},
	})
}

func TestAccItAutomationTasksDataSource_FQLFilter(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	dataSourceName := "data.crowdstrike_it_automation_tasks.test"
	resourceName := "crowdstrike_it_automation_task.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccItAutomationTasksDataSourceConfigFQLFilter(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, "tasks.#", "1"),
					resource.TestCheckResourceAttrPair(resourceName, "id", dataSourceName, "tasks.0.id"),
					resource.TestCheckResourceAttrPair(resourceName, "name", dataSourceName, "tasks.0.name"),
				),
			},
		},
	})
}

func testAccItAutomationTasksDataSourceConfigValidationFilterIDs() string {
	return acctest.ProviderConfig + `
data "crowdstrike_it_automation_tasks" "test" {
  filter = "access_type:'Public'"
  ids    = ["id-one", "id-two"]
}
`
}

func testAccItAutomationTasksDataSourceConfigValidationFilterIndividual() string {
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

func testAccItAutomationTasksDataSourceConfigValidationAllThree() string {
	return acctest.ProviderConfig + `
data "crowdstrike_it_automation_tasks" "test" {
  filter = "access_type:'Public'"
  ids    = ["id-one"]
  name   = "test"
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

func testAccItAutomationTasksDataSourceConfigValidationIDsType() string {
	return acctest.ProviderConfig + `
data "crowdstrike_it_automation_tasks" "test" {
  ids  = ["id-one"]
  type = "query"
}
`
}

func testAccItAutomationTasksDataSourceConfigValidationFilterAccessType() string {
	return acctest.ProviderConfig + `
data "crowdstrike_it_automation_tasks" "test" {
  filter      = "name:'test'"
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

func testAccItAutomationTasksDataSourceConfigResourceMatch(rName string) string {
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

  depends_on = [crowdstrike_it_automation_task.test]
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

  depends_on = [crowdstrike_it_automation_task.test]
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

  depends_on = [crowdstrike_it_automation_task.test]
}
`, rName)
}
