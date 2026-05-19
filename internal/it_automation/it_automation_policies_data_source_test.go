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

func policyDataSourceFullCompareChecks(resourceName string, idx int) []statecheck.StateCheck {
	dsPath := func(attr string) tfjsonpath.Path {
		return tfjsonpath.New("policies").AtSliceIndex(idx).AtMapKey(attr)
	}
	cmp := func(attr string) statecheck.StateCheck {
		return statecheck.CompareValuePairs(
			resourceName, tfjsonpath.New(attr),
			policiesDataSourceName, dsPath(attr),
			compare.ValuesSame(),
		)
	}
	notNull := func(attr string) statecheck.StateCheck {
		return statecheck.ExpectKnownValue(policiesDataSourceName, dsPath(attr), knownvalue.NotNull())
	}
	return []statecheck.StateCheck{
		cmp("id"),
		cmp("name"),
		cmp("description"),
		cmp("platform_name"),
		cmp("enabled"),
		cmp("concurrent_host_file_transfer_limit"),
		cmp("concurrent_host_limit"),
		cmp("concurrent_task_limit"),
		cmp("enable_os_query"),
		cmp("enable_python_execution"),
		cmp("enable_script_execution"),
		cmp("execution_timeout"),
		cmp("execution_timeout_unit"),
		cmp("cpu_throttle"),
		cmp("memory_allocation"),
		cmp("memory_allocation_unit"),
		cmp("cpu_scheduling_priority"),
		cmp("memory_pressure_level"),
		cmp("host_groups"),
		notNull("precedence"),
		notNull("created_at"),
		notNull("created_by"),
		notNull("modified_at"),
		notNull("modified_by"),
	}
}

func TestAccITAutomationPoliciesDataSource_ByIDs(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	firstPolicy := "crowdstrike_it_automation_policy.first"
	secondPolicy := "crowdstrike_it_automation_policy.second"

	checks := append(
		[]statecheck.StateCheck{
			statecheck.ExpectKnownValue(
				policiesDataSourceName,
				tfjsonpath.New("policies"),
				knownvalue.ListSizeExact(2),
			),
		},
		append(
			policyDataSourceFullCompareChecks(firstPolicy, 0),
			policyDataSourceFullCompareChecks(secondPolicy, 1)...,
		)...,
	)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:            testAccITAutomationPoliciesDataSourceConfigByIDs(rName),
				ConfigStateChecks: checks,
			},
		},
	})
}

func TestAccITAutomationPoliciesDataSource_Filters(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_it_automation_policy.test"

	checks := append(
		[]statecheck.StateCheck{
			statecheck.ExpectKnownValue(
				policiesDataSourceName,
				tfjsonpath.New("policies"),
				knownvalue.ListSizeExact(1),
			),
		},
		policyDataSourceFullCompareChecks(resourceName, 0)...,
	)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:            testAccITAutomationPoliciesDataSourceConfigFilters(rName),
				ConfigStateChecks: checks,
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
		"ids_with_sort": {
			config: acctest.ProviderConfig + `
data "crowdstrike_it_automation_policies" "test" {
  ids  = ["00000000000000000000000000000001"]
  sort = "precedence|asc"
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

resource "crowdstrike_it_automation_policy" "first" {
  name          = "%[1]s-first"
  description   = "First Windows policy for IDs data source test"
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

resource "crowdstrike_it_automation_policy" "second" {
  name          = "%[1]s-second"
  description   = "Second Windows policy for IDs data source test"
  platform_name = "Windows"
  enabled       = false
  host_groups   = [crowdstrike_host_group.windows.id]

  concurrent_host_file_transfer_limit = 1000
  concurrent_host_limit               = 2000
  concurrent_task_limit               = 5

  enable_os_query         = false
  enable_python_execution = false
  enable_script_execution = true
  execution_timeout       = 60
  execution_timeout_unit  = "Minutes"

  cpu_throttle           = 25
  memory_allocation      = 512
  memory_allocation_unit = "MB"
}

data "crowdstrike_it_automation_policies" "test" {
  ids = [
    crowdstrike_it_automation_policy.first.id,
    crowdstrike_it_automation_policy.second.id,
  ]
}
`, rName)
}

func testAccITAutomationPoliciesDataSourceConfigFilters(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name            = "%[1]s-hg"
  description     = "Test host group"
  type            = "dynamic"
  assignment_rule = "platform_name:'Windows'"
}

resource "crowdstrike_it_automation_policy" "test" {
  name          = %[1]q
  description   = "Test Windows policy for filters data source test"
  platform_name = "Windows"
  enabled       = true
  host_groups   = [crowdstrike_host_group.test.id]

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
  name          = %[1]q
  enabled       = true

  depends_on = [crowdstrike_it_automation_policy.test]
}
`, rName)
}
