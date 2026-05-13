package itautomation_test

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

const policiesDataSourceName = "data.crowdstrike_it_automation_policies.test"

func TestAccITAutomationPoliciesDataSource_ByIDs(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_it_automation_policy.windows"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccITAutomationPoliciesDataSourceConfigByIDs(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						policiesDataSourceName,
						tfjsonpath.New("policies"),
						knownvalue.ListSizeExact(1),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("id"),
						policiesDataSourceName, tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey("id"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("name"),
						policiesDataSourceName, tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey("name"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("description"),
						policiesDataSourceName, tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey("description"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("platform_name"),
						policiesDataSourceName, tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey("platform_name"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("enabled"),
						policiesDataSourceName, tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey("enabled"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("concurrent_host_file_transfer_limit"),
						policiesDataSourceName, tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey("concurrent_host_file_transfer_limit"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("concurrent_host_limit"),
						policiesDataSourceName, tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey("concurrent_host_limit"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("concurrent_task_limit"),
						policiesDataSourceName, tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey("concurrent_task_limit"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("enable_os_query"),
						policiesDataSourceName, tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey("enable_os_query"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("enable_python_execution"),
						policiesDataSourceName, tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey("enable_python_execution"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("enable_script_execution"),
						policiesDataSourceName, tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey("enable_script_execution"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("execution_timeout"),
						policiesDataSourceName, tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey("execution_timeout"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("execution_timeout_unit"),
						policiesDataSourceName, tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey("execution_timeout_unit"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("cpu_throttle"),
						policiesDataSourceName, tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey("cpu_throttle"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("memory_allocation"),
						policiesDataSourceName, tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey("memory_allocation"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("memory_allocation_unit"),
						policiesDataSourceName, tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey("memory_allocation_unit"),
						compare.ValuesSame(),
					),
					statecheck.ExpectKnownValue(
						policiesDataSourceName,
						tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey("precedence"),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						policiesDataSourceName,
						tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey("created_at"),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						policiesDataSourceName,
						tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey("created_by"),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						policiesDataSourceName,
						tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey("modified_at"),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						policiesDataSourceName,
						tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey("modified_by"),
						knownvalue.NotNull(),
					),
				},
			},
		},
	})
}

func TestAccITAutomationPoliciesDataSource_ByPlatform(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccITAutomationPoliciesDataSourceConfigByPlatform(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						policiesDataSourceName,
						tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey("platform_name"),
						knownvalue.StringExact("Linux"),
					),
				},
			},
		},
	})
}

func TestAccITAutomationPoliciesDataSource_NameAndEnabledFilter(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccITAutomationPoliciesDataSourceConfigNameAndEnabledFilter(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						policiesDataSourceName,
						tfjsonpath.New("policies"),
						knownvalue.ListSizeExact(1),
					),
					statecheck.ExpectKnownValue(
						policiesDataSourceName,
						tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey("enabled"),
						knownvalue.Bool(true),
					),
					statecheck.ExpectKnownValue(
						policiesDataSourceName,
						tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey("platform_name"),
						knownvalue.StringExact("Windows"),
					),
				},
			},
		},
	})
}

func TestAccITAutomationPoliciesDataSource_AllPlatforms(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccITAutomationPoliciesDataSourceConfigAll(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						policiesDataSourceName,
						tfjsonpath.New("policies"),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						policiesDataSourceName,
						tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey("platform_name"),
						knownvalue.NotNull(),
					),
				},
			},
		},
	})
}

func TestAccITAutomationPoliciesDataSource_ValidationErrors(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		config      string
		expectError *regexp.Regexp
	}{
		"ids_with_platform_name": {
			config: acctest.ProviderConfig + `
data "crowdstrike_it_automation_policies" "test" {
  ids           = ["00000000000000000000000000000001"]
  platform_name = "Windows"
}
`,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"ids_with_name": {
			config: acctest.ProviderConfig + `
data "crowdstrike_it_automation_policies" "test" {
  ids  = ["00000000000000000000000000000001"]
  name = "prod*"
}
`,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"ids_with_enabled": {
			config: acctest.ProviderConfig + `
data "crowdstrike_it_automation_policies" "test" {
  ids     = ["00000000000000000000000000000001"]
  enabled = true
}
`,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			resource.ParallelTest(t, resource.TestCase{
				PreCheck:                 func() { acctest.PreCheck(t) },
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config:      tc.config,
						ExpectError: tc.expectError,
					},
				},
			})
		})
	}
}

func testAccITAutomationPoliciesDataSourceConfigByIDs(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "windows" {
  name            = "%[1]s-windows-hg"
  description     = "Test host group"
  type            = "dynamic"
  assignment_rule = "platform_name:'Windows'"
}

resource "crowdstrike_it_automation_policy" "windows" {
  name          = %[1]q
  description   = "Test Windows policy for data source acceptance test"
  platform_name = "Windows"
  enabled       = true
  host_groups   = [crowdstrike_host_group.windows.id]

  concurrent_host_file_transfer_limit = 2500
  concurrent_host_limit               = 5000
  concurrent_task_limit               = 3

  enable_os_query         = true
  enable_python_execution = true
  enable_script_execution = true
  execution_timeout       = 30
  execution_timeout_unit  = "Minutes"

  cpu_throttle           = 15
  memory_allocation      = 1024
  memory_allocation_unit = "MB"
}

data "crowdstrike_it_automation_policies" "test" {
  ids = [crowdstrike_it_automation_policy.windows.id]
}
`, rName)
}

func testAccITAutomationPoliciesDataSourceConfigByPlatform(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "linux" {
  name            = "%[1]s-linux-hg"
  description     = "Test host group"
  type            = "dynamic"
  assignment_rule = "platform_name:'Linux'"
}

resource "crowdstrike_it_automation_policy" "linux" {
  name          = %[1]q
  description   = "Test Linux policy for data source acceptance test"
  platform_name = "Linux"
  enabled       = true
  host_groups   = [crowdstrike_host_group.linux.id]

  concurrent_host_file_transfer_limit = 2500
  concurrent_host_limit               = 5000
  concurrent_task_limit               = 3

  enable_os_query         = true
  enable_python_execution = true
  enable_script_execution = true
  execution_timeout       = 30
  execution_timeout_unit  = "Minutes"

  cpu_throttle           = 15
  memory_allocation      = 1024
  memory_allocation_unit = "MB"
}

data "crowdstrike_it_automation_policies" "test" {
  platform_name = "Linux"

  depends_on = [crowdstrike_it_automation_policy.linux]
}
`, rName)
}

func testAccITAutomationPoliciesDataSourceConfigNameAndEnabledFilter(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "windows" {
  name            = "%[1]s-windows-hg"
  description     = "Test host group"
  type            = "dynamic"
  assignment_rule = "platform_name:'Windows'"
}

resource "crowdstrike_it_automation_policy" "enabled_win" {
  name          = "%[1]s-enabled"
  description   = "Enabled Windows policy"
  platform_name = "Windows"
  enabled       = true
  host_groups   = [crowdstrike_host_group.windows.id]

  concurrent_host_file_transfer_limit = 2500
  concurrent_host_limit               = 5000
  concurrent_task_limit               = 3

  enable_os_query         = true
  enable_python_execution = true
  enable_script_execution = true
  execution_timeout       = 30
  execution_timeout_unit  = "Minutes"

  cpu_throttle           = 15
  memory_allocation      = 1024
  memory_allocation_unit = "MB"
}

resource "crowdstrike_it_automation_policy" "disabled_win" {
  name          = "%[1]s-disabled"
  description   = "Disabled Windows policy"
  platform_name = "Windows"
  enabled       = false
  host_groups   = [crowdstrike_host_group.windows.id]

  concurrent_host_file_transfer_limit = 2500
  concurrent_host_limit               = 5000
  concurrent_task_limit               = 3

  enable_os_query         = true
  enable_python_execution = true
  enable_script_execution = true
  execution_timeout       = 30
  execution_timeout_unit  = "Minutes"

  cpu_throttle           = 15
  memory_allocation      = 1024
  memory_allocation_unit = "MB"
}

data "crowdstrike_it_automation_policies" "test" {
  platform_name = "Windows"
  name          = "%[1]s-enabled"
  enabled       = true

  depends_on = [
    crowdstrike_it_automation_policy.enabled_win,
    crowdstrike_it_automation_policy.disabled_win,
  ]
}
`, rName)
}

func testAccITAutomationPoliciesDataSourceConfigAll() string {
	return acctest.ProviderConfig + `
data "crowdstrike_it_automation_policies" "test" {}
`
}
