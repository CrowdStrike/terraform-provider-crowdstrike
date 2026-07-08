package itautomation_test

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const scheduledTaskResourceName = "crowdstrike_it_automation_scheduled_task.test"

// Fake task IDs are used for plan-only validation tests where we never reach
// the API. They must satisfy schema-level validators (non-whitespace, length).
const (
	scheduledTaskFakeTaskID  = "00000000000000000000000000000001"
	scheduledTaskFakeQueryID = "00000000000000000000000000000002"
)

// scheduledTaskFixtureConfig returns HCL that creates an action task and a
// query task whose IDs can be referenced by tests via
// `crowdstrike_it_automation_task.action.id` and
// `crowdstrike_it_automation_task.query.id`.
//
// The action task is the schedule's underlying task. The query task is used
// by `trigger_condition` statements which only accept query-task references.
func scheduledTaskFixtureConfig(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_it_automation_task" "action" {
  name                  = "%[1]s-action"
  access_type           = "Public"
  description           = "Scheduled task acceptance test - action"
  type                  = "action"
  linux_script_language = "bash"
  linux_script_content  = "echo 'hello'"
}

resource "crowdstrike_it_automation_task" "query" {
  name                  = "%[1]s-query"
  access_type           = "Public"
  description           = "Scheduled task acceptance test - query"
  type                  = "query"
  linux_script_language = "bash"
  linux_script_content  = "echo 'name:bash'"
}
`, suffix)
}

// importStateIgnore lists computed fields whose values may shift between the
// initial read and the import re-read (the schedule may tick over between
// the two API calls), so ImportStateVerify must skip them.
var scheduledTaskImportIgnore = []string{
	"last_run",
	"next_run_time",
	"modified_time",
	"modified_by",
}

func TestAccITAutomationScheduledTaskResource_basic(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_basic(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("created_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("created_time"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("task_name"), knownvalue.StringExact(rName+"-action")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("task_type"), knownvalue.StringExact("action")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("task_id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("target"), knownvalue.StringExact("platform_name:'Linux'")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("frequency"), knownvalue.StringExact("Daily")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("start_time"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule_name"), knownvalue.Null()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("expiration_period"), knownvalue.Null()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("run_time_limit_minutes"), knownvalue.Null()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("execution_args"), knownvalue.Null()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition"), knownvalue.Null()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("end_time"), knownvalue.Null()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("day_of_week"), knownvalue.Null()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("day_of_month"), knownvalue.Null()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("interval"), knownvalue.Null()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("discover_new_hosts"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("queue_offline_hosts"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("distribute_execution"), knownvalue.Bool(false)),
				},
			},
			{
				ResourceName:            scheduledTaskResourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: scheduledTaskImportIgnore,
			},
		},
	})
}

func TestAccITAutomationScheduledTaskResource_update(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_basic(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.CompareValuePairs(
						scheduledTaskResourceName, tfjsonpath.New("task_id"),
						"crowdstrike_it_automation_task.action", tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("task_name"), knownvalue.StringExact(rName+"-action")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("task_type"), knownvalue.StringExact("action")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("target"), knownvalue.StringExact("platform_name:'Linux'")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("frequency"), knownvalue.StringExact("Daily")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule_name"), knownvalue.Null()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("expiration_period"), knownvalue.Null()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("run_time_limit_minutes"), knownvalue.Null()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("execution_args"), knownvalue.Null()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition"), knownvalue.Null()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("discover_new_hosts"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("queue_offline_hosts"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("distribute_execution"), knownvalue.Bool(false)),
				},
			},
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_lifecycleUpdated(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.CompareValuePairs(
						scheduledTaskResourceName, tfjsonpath.New("task_id"),
						"crowdstrike_it_automation_task.query", tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("task_name"), knownvalue.StringExact(rName+"-query")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("task_type"), knownvalue.StringExact("query")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("target"), knownvalue.StringExact("platform_name:'Linux'+tags:'production'")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("frequency"), knownvalue.StringExact("Weekly")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("day_of_week"), knownvalue.StringExact("Friday")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("start_time"), knownvalue.StringExact("2027-06-01T09:00:00Z")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("end_time"), knownvalue.StringExact("2028-06-01T09:00:00Z")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule_name"), knownvalue.StringExact(rName+"-schedule")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("expiration_period"), knownvalue.StringExact("1h")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("run_time_limit_minutes"), knownvalue.Int64Exact(30)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("execution_args"), knownvalue.MapExact(map[string]knownvalue.Check{
						"k1": knownvalue.StringExact("v1"),
						"k2": knownvalue.StringExact("v2"),
					})),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("discover_new_hosts"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("queue_offline_hosts"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("distribute_execution"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(0).AtMapKey("operator"), knownvalue.StringExact("OR")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(0).AtMapKey("statements"), knownvalue.ListSizeExact(2)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(0).AtMapKey("statements").AtSliceIndex(0).AtMapKey("key"), knownvalue.StringExact("name")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(0).AtMapKey("statements").AtSliceIndex(0).AtMapKey("data_type"), knownvalue.StringExact("StringType")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(0).AtMapKey("statements").AtSliceIndex(0).AtMapKey("data_comparator"), knownvalue.StringExact("Equals")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(0).AtMapKey("statements").AtSliceIndex(0).AtMapKey("value"), knownvalue.StringExact("bash")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(0).AtMapKey("statements").AtSliceIndex(1).AtMapKey("value"), knownvalue.StringExact("zsh")),
				},
			},
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_basic(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.CompareValuePairs(
						scheduledTaskResourceName, tfjsonpath.New("task_id"),
						"crowdstrike_it_automation_task.action", tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("task_name"), knownvalue.StringExact(rName+"-action")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("task_type"), knownvalue.StringExact("action")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("target"), knownvalue.StringExact("platform_name:'Linux'")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("frequency"), knownvalue.StringExact("Daily")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("day_of_week"), knownvalue.Null()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("end_time"), knownvalue.Null()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule_name"), knownvalue.Null()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("expiration_period"), knownvalue.Null()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("run_time_limit_minutes"), knownvalue.Null()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("execution_args"), knownvalue.Null()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition"), knownvalue.Null()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("discover_new_hosts"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("queue_offline_hosts"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("distribute_execution"), knownvalue.Bool(false)),
				},
			},
			{
				ResourceName:            scheduledTaskResourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: scheduledTaskImportIgnore,
			},
		},
	})
}

func TestAccITAutomationScheduledTaskResource_frequency_oneTime(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_oneTime(true, "platform_name:'Linux'", "2027-06-01T09:00:00Z"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("frequency"), knownvalue.StringExact("One-Time")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("interval"), knownvalue.Null()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("day_of_week"), knownvalue.Null()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("day_of_month"), knownvalue.Null()),
				},
			},
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_oneTime(true, "platform_name:'Linux'", "2027-07-01T09:00:00Z"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("start_time"), knownvalue.StringExact("2027-07-01T09:00:00Z")),
				},
			},
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_oneTime(true, "platform_name:'Mac'", "2027-07-01T09:00:00Z"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("target"), knownvalue.StringExact("platform_name:'Mac'")),
				},
			},
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_oneTime(false, "platform_name:'Mac'", "2027-07-01T09:00:00Z"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
				},
			},
		},
	})
}

func TestAccITAutomationScheduledTaskResource_frequency_minutes(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_frequency(`
    frequency  = "Minutes"
    interval   = 60
    start_time = "2027-06-01T09:00:00Z"
`),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("frequency"), knownvalue.StringExact("Minutes")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("interval"), knownvalue.Int64Exact(60)),
				},
			},
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_frequency(`
    frequency  = "Minutes"
    interval   = 10080
    start_time = "2027-06-01T09:00:00Z"
`),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("frequency"), knownvalue.StringExact("Minutes")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("interval"), knownvalue.Int64Exact(10080)),
				},
			},
		},
	})
}

func TestAccITAutomationScheduledTaskResource_frequency_hourly(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_frequency(`
    frequency  = "Hourly"
    interval   = 1
    start_time = "2027-06-01T09:00:00Z"
`),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("frequency"), knownvalue.StringExact("Hourly")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("interval"), knownvalue.Int64Exact(1)),
				},
			},
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_frequency(`
    frequency  = "Hourly"
    interval   = 168
    start_time = "2027-06-01T09:00:00Z"
`),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("frequency"), knownvalue.StringExact("Hourly")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("interval"), knownvalue.Int64Exact(168)),
				},
			},
		},
	})
}

func TestAccITAutomationScheduledTaskResource_frequency_daily(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_frequency(`
    frequency  = "Daily"
    start_time = "2027-06-01T09:00:00Z"
`),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("frequency"), knownvalue.StringExact("Daily")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("interval"), knownvalue.Null()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("day_of_week"), knownvalue.Null()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("day_of_month"), knownvalue.Null()),
				},
			},
		},
	})
}

func TestAccITAutomationScheduledTaskResource_frequency_weekly(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_frequency(`
    frequency   = "Weekly"
    day_of_week = "Wednesday"
    start_time  = "2027-06-01T09:00:00Z"
`),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("frequency"), knownvalue.StringExact("Weekly")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("day_of_week"), knownvalue.StringExact("Wednesday")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("interval"), knownvalue.Null()),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("day_of_month"), knownvalue.Null()),
				},
			},
		},
	})
}

func TestAccITAutomationScheduledTaskResource_frequency_monthly(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_frequency(`
    frequency    = "Monthly"
    day_of_month = 1
    start_time   = "2027-06-01T09:00:00Z"
`),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("frequency"), knownvalue.StringExact("Monthly")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("day_of_month"), knownvalue.Int64Exact(1)),
				},
			},
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_frequency(`
    frequency    = "Monthly"
    day_of_month = 28
    start_time   = "2027-06-01T09:00:00Z"
`),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("frequency"), knownvalue.StringExact("Monthly")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("day_of_month"), knownvalue.Int64Exact(28)),
				},
			},
		},
	})
}

func TestAccITAutomationScheduledTaskResource_frequencyMutation(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_frequency(`
    frequency  = "Minutes"
    interval   = 120
    start_time = "2027-06-01T09:00:00Z"
`),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("frequency"), knownvalue.StringExact("Minutes")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("interval"), knownvalue.Int64Exact(120)),
				},
			},
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_frequency(`
    frequency  = "Daily"
    start_time = "2027-06-01T09:00:00Z"
`),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("frequency"), knownvalue.StringExact("Daily")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("interval"), knownvalue.Null()),
				},
			},
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_frequency(`
    frequency  = "Hourly"
    interval   = 4
    start_time = "2027-06-01T09:00:00Z"
`),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("frequency"), knownvalue.StringExact("Hourly")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("interval"), knownvalue.Int64Exact(4)),
				},
			},
		},
	})
}

func TestAccITAutomationScheduledTaskResource_boolOmitemptyRegression(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_boolFlags(true, true, true, true),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("discover_new_hosts"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("queue_offline_hosts"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("distribute_execution"), knownvalue.Bool(true)),
				},
			},
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_boolFlags(false, false, false, false),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("discover_new_hosts"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("queue_offline_hosts"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("distribute_execution"), knownvalue.Bool(false)),
				},
			},
		},
	})
}

func TestAccITAutomationScheduledTaskResource_startTimeUnknown(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: scheduledTaskFixtureConfig(rName) + `
resource "crowdstrike_it_automation_scheduled_task" "test" {
  task_id = crowdstrike_it_automation_task.action.id
  enabled = true
  target  = "platform_name:'Linux'"

  schedule = {
    frequency  = "Daily"
    start_time = crowdstrike_it_automation_task.action.last_updated
  }
}
`,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccITAutomationScheduledTaskResource_startTimeOffset verifies the
// custom RFC3339 type's semantic equality is preserved when the user writes
// a non-UTC offset. No spurious diff should appear after apply.
func TestAccITAutomationScheduledTaskResource_startTimeOffset(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	// start_time is computed at runtime (next year) so it never falls into the
	// past, and keeps a non-UTC offset to exercise RFC3339 semantic equality.
	startTime := time.Date(time.Now().Year()+1, time.June, 1, 9, 0, 0, 0, time.FixedZone("", -5*60*60)).Format("2006-01-02T15:04:05-07:00")
	scheduleBody := fmt.Sprintf(`
    frequency  = "Daily"
    start_time = %q
`, startTime)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_frequency(scheduleBody),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule").AtMapKey("start_time"), knownvalue.StringExact(startTime)),
				},
			},
			{
				// Re-applying the same config must not produce a plan diff.
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_frequency(scheduleBody),
				ExpectNonEmptyPlan: false,
				PlanOnly:           true,
			},
		},
	})
}

func TestAccITAutomationScheduledTaskResource_triggerCondition(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_triggerOneGroup(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(0).AtMapKey("operator"), knownvalue.StringExact("OR")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(0).AtMapKey("statements"), knownvalue.ListSizeExact(2)),
					statecheck.CompareValuePairs(
						scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(0).AtMapKey("statements").AtSliceIndex(0).AtMapKey("task_id"),
						"crowdstrike_it_automation_task.query", tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(0).AtMapKey("statements").AtSliceIndex(0).AtMapKey("key"), knownvalue.StringExact("name")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(0).AtMapKey("statements").AtSliceIndex(0).AtMapKey("data_type"), knownvalue.StringExact("StringType")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(0).AtMapKey("statements").AtSliceIndex(0).AtMapKey("data_comparator"), knownvalue.StringExact("Equals")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(0).AtMapKey("statements").AtSliceIndex(0).AtMapKey("value"), knownvalue.StringExact("bash")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(0).AtMapKey("statements").AtSliceIndex(1).AtMapKey("data_comparator"), knownvalue.StringExact("Equals")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(0).AtMapKey("statements").AtSliceIndex(1).AtMapKey("value"), knownvalue.StringExact("zsh")),
				},
			},
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_triggerTwoGroups(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition"), knownvalue.ListSizeExact(2)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(0).AtMapKey("operator"), knownvalue.StringExact("OR")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(1).AtMapKey("operator"), knownvalue.StringExact("AND")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(1).AtMapKey("statements"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(1).AtMapKey("statements").AtSliceIndex(0).AtMapKey("key"), knownvalue.StringExact("name")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(1).AtMapKey("statements").AtSliceIndex(0).AtMapKey("data_type"), knownvalue.StringExact("StringType")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(1).AtMapKey("statements").AtSliceIndex(0).AtMapKey("data_comparator"), knownvalue.StringExact("Contains")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(1).AtMapKey("statements").AtSliceIndex(0).AtMapKey("value"), knownvalue.StringExact("sh")),
				},
			},
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_basic(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition"), knownvalue.Null()),
				},
			},
		},
	})
}

func TestAccITAutomationScheduledTaskResource_triggerConditionPreserved(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_triggerWithName(rName+"-schedule-v1"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule_name"), knownvalue.StringExact(rName+"-schedule-v1")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(0).AtMapKey("operator"), knownvalue.StringExact("AND")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(0).AtMapKey("statements"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(0).AtMapKey("statements").AtSliceIndex(0).AtMapKey("data_comparator"), knownvalue.StringExact("Equals")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(0).AtMapKey("statements").AtSliceIndex(0).AtMapKey("value"), knownvalue.StringExact("bash")),
				},
			},
			{
				// Identical trigger_condition block; only schedule_name changes.
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_triggerWithName(rName+"-schedule-v2"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule_name"), knownvalue.StringExact(rName+"-schedule-v2")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(0).AtMapKey("operator"), knownvalue.StringExact("AND")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(0).AtMapKey("statements"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(0).AtMapKey("statements").AtSliceIndex(0).AtMapKey("data_comparator"), knownvalue.StringExact("Equals")),
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("trigger_condition").AtSliceIndex(0).AtMapKey("statements").AtSliceIndex(0).AtMapKey("value"), knownvalue.StringExact("bash")),
				},
			},
		},
	})
}

func TestAccITAutomationScheduledTaskResource_scheduleName(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_scheduleName(""),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule_name"), knownvalue.Null()),
				},
			},
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_scheduleName(rName+"-schedule"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(scheduledTaskResourceName, plancheck.ResourceActionUpdate),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule_name"), knownvalue.StringExact(rName+"-schedule")),
				},
			},
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_scheduleName(""),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(scheduledTaskResourceName, plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("schedule_name"), knownvalue.Null()),
				},
			},
		},
	})
}

func TestAccITAutomationScheduledTaskResource_runTimeLimitClear(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_runTimeLimitOptional(0),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("run_time_limit_minutes"), knownvalue.Null()),
				},
			},
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_runTimeLimitOptional(30),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(scheduledTaskResourceName, plancheck.ResourceActionUpdate),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("run_time_limit_minutes"), knownvalue.Int64Exact(30)),
				},
			},
			{
				Config: scheduledTaskFixtureConfig(rName) +
					testAccScheduledTaskConfig_runTimeLimitOptional(0),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(scheduledTaskResourceName, plancheck.ResourceActionUpdate),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("run_time_limit_minutes"), knownvalue.Null()),
				},
			},
		},
	})
}

func TestAccITAutomationScheduledTaskResource_expirationPeriodRequiresFlag(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "crowdstrike_it_automation_scheduled_task" "test" {
  task_id           = %[1]q
  enabled           = true
  target            = "platform_name:'Linux'"
  expiration_period = "1h"

  schedule = {
    frequency  = "Daily"
    start_time = "2027-06-01T09:00:00Z"
  }
}
`, scheduledTaskFakeTaskID),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("(?s)expiration_period.*(discover_new_hosts|queue_offline_hosts|distribute_execution)"),
			},
		},
	})
}

func TestAccITAutomationScheduledTaskResource_expirationPeriodCanonical(t *testing.T) {
	cases := []struct {
		name        string
		value       string
		expectError *regexp.Regexp
	}{
		{
			name:        "60m_should_be_1h",
			value:       "60m",
			expectError: regexp.MustCompile(`(?i)1h`),
		},
		{
			name:        "3600s_should_be_1h",
			value:       "3600s",
			expectError: regexp.MustCompile(`(?i)1h`),
		},
		{
			name:        "24h_should_be_1d",
			value:       "24h",
			expectError: regexp.MustCompile(`(?i)1d`),
		},
		{
			name:        "decimal_rejected",
			value:       "1.5h",
			expectError: regexp.MustCompile(`(?i)expiration_period|duration|invalid`),
		},
		{
			name:        "below_minimum",
			value:       "0m",
			expectError: regexp.MustCompile(`(?i)expiration_period|duration|invalid`),
		},
		{
			name:        "wrong_format",
			value:       "1 hour",
			expectError: regexp.MustCompile(`(?i)expiration_period|duration|invalid`),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resource.ParallelTest(t, resource.TestCase{
				PreCheck:                 func() { acctest.PreCheck(t) },
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config: fmt.Sprintf(`
resource "crowdstrike_it_automation_scheduled_task" "test" {
  task_id              = %[1]q
  enabled              = true
  target               = "platform_name:'Linux'"
  discover_new_hosts   = true
  expiration_period    = %[2]q

  schedule = {
    frequency  = "Daily"
    start_time = "2027-06-01T09:00:00Z"
  }
}
`, scheduledTaskFakeTaskID, tc.value),
						PlanOnly:    true,
						ExpectError: tc.expectError,
					},
				},
			})
		})
	}
}

func TestAccITAutomationScheduledTaskResource_runTimeLimitMinutesBoundary(t *testing.T) {
	t.Run("accepts_1", func(t *testing.T) {
		rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
		resource.ParallelTest(t, resource.TestCase{
			PreCheck:                 func() { acctest.PreCheck(t) },
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: scheduledTaskFixtureConfig(rName) +
						testAccScheduledTaskConfig_runTimeLimit(1),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("run_time_limit_minutes"), knownvalue.Int64Exact(1)),
					},
				},
			},
		})
	})

	t.Run("accepts_120", func(t *testing.T) {
		rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
		resource.ParallelTest(t, resource.TestCase{
			PreCheck:                 func() { acctest.PreCheck(t) },
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: scheduledTaskFixtureConfig(rName) +
						testAccScheduledTaskConfig_runTimeLimit(120),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue(scheduledTaskResourceName, tfjsonpath.New("run_time_limit_minutes"), knownvalue.Int64Exact(120)),
					},
				},
			},
		})
	})

	t.Run("rejects_0", func(t *testing.T) {
		resource.ParallelTest(t, resource.TestCase{
			PreCheck:                 func() { acctest.PreCheck(t) },
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
resource "crowdstrike_it_automation_scheduled_task" "test" {
  task_id                = %[1]q
  enabled                = true
  target                 = "platform_name:'Linux'"
  run_time_limit_minutes = 0

  schedule = {
    frequency  = "Daily"
    start_time = "2027-06-01T09:00:00Z"
  }
}
`, scheduledTaskFakeTaskID),
					PlanOnly:    true,
					ExpectError: regexp.MustCompile(`(?i)run_time_limit_minutes`),
				},
			},
		})
	})

	t.Run("rejects_121", func(t *testing.T) {
		resource.ParallelTest(t, resource.TestCase{
			PreCheck:                 func() { acctest.PreCheck(t) },
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
resource "crowdstrike_it_automation_scheduled_task" "test" {
  task_id                = %[1]q
  enabled                = true
  target                 = "platform_name:'Linux'"
  run_time_limit_minutes = 121

  schedule = {
    frequency  = "Daily"
    start_time = "2027-06-01T09:00:00Z"
  }
}
`, scheduledTaskFakeTaskID),
					PlanOnly:    true,
					ExpectError: regexp.MustCompile(`(?i)run_time_limit_minutes`),
				},
			},
		})
	})
}

func TestAccITAutomationScheduledTaskResource_validateConfigNegative(t *testing.T) {
	cases := []struct {
		name        string
		schedule    string
		expectError *regexp.Regexp
	}{
		{
			name: "missing_start_time",
			schedule: `
    frequency = "Daily"`,
			expectError: regexp.MustCompile(`(?i)start_time|required.*creating`),
		},
		{
			name: "day_of_week_with_daily",
			schedule: `
    frequency   = "Daily"
    day_of_week = "Friday"
    start_time  = "2027-06-01T09:00:00Z"`,
			expectError: regexp.MustCompile(`(?i)day_of_week|Weekly`),
		},
		{
			name: "day_of_month_with_daily",
			schedule: `
    frequency    = "Daily"
    day_of_month = 5
    start_time   = "2027-06-01T09:00:00Z"`,
			expectError: regexp.MustCompile(`(?i)day_of_month|Monthly`),
		},
		{
			name: "interval_with_daily",
			schedule: `
    frequency  = "Daily"
    interval   = 60
    start_time = "2027-06-01T09:00:00Z"`,
			expectError: regexp.MustCompile(`(?i)interval|Minutes|Hourly`),
		},
		{
			name: "interval_with_weekly",
			schedule: `
    frequency   = "Weekly"
    day_of_week = "Friday"
    interval    = 60
    start_time  = "2027-06-01T09:00:00Z"`,
			expectError: regexp.MustCompile(`(?i)interval|Minutes|Hourly`),
		},
		{
			name: "interval_with_monthly",
			schedule: `
    frequency    = "Monthly"
    day_of_month = 1
    interval     = 60
    start_time   = "2027-06-01T09:00:00Z"`,
			expectError: regexp.MustCompile(`(?i)interval|Minutes|Hourly`),
		},
		{
			name: "interval_with_one_time",
			schedule: `
    frequency  = "One-Time"
    interval   = 60
    start_time = "2027-06-01T09:00:00Z"`,
			expectError: regexp.MustCompile(`(?i)interval|Minutes|Hourly`),
		},
		{
			name: "interval_below_minutes_range",
			schedule: `
    frequency  = "Minutes"
    interval   = 59
    start_time = "2027-06-01T09:00:00Z"`,
			// schema-level int64validator.Between(1, 10080) accepts 59, but
			// ValidateConfig must enforce the per-frequency 60-10080 range.
			expectError: regexp.MustCompile(`(?i)interval|60|Minutes`),
		},
		{
			name: "interval_above_hourly_range",
			schedule: `
    frequency  = "Hourly"
    interval   = 169
    start_time = "2027-06-01T09:00:00Z"`,
			expectError: regexp.MustCompile(`(?i)interval|168|Hourly`),
		},
		{
			name: "day_of_month_below_range",
			schedule: `
    frequency    = "Monthly"
    day_of_month = 0
    start_time   = "2027-06-01T09:00:00Z"`,
			expectError: regexp.MustCompile(`(?i)day_of_month|1|28`),
		},
		{
			name: "day_of_month_above_range",
			schedule: `
    frequency    = "Monthly"
    day_of_month = 29
    start_time   = "2027-06-01T09:00:00Z"`,
			expectError: regexp.MustCompile(`(?i)day_of_month|28`),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resource.ParallelTest(t, resource.TestCase{
				PreCheck:                 func() { acctest.PreCheck(t) },
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config: fmt.Sprintf(`
resource "crowdstrike_it_automation_scheduled_task" "test" {
  task_id = %[1]q
  enabled = true
  target  = "platform_name:'Linux'"

  schedule = {%[2]s
  }
}
`, scheduledTaskFakeTaskID, tc.schedule),
						PlanOnly:    true,
						ExpectError: tc.expectError,
					},
				},
			})
		})
	}
}

func TestAccITAutomationScheduledTaskResource_triggerConditionTypeMismatch(t *testing.T) {
	cases := []struct {
		name           string
		dataType       string
		dataComparator string
		expectError    *regexp.Regexp
	}{
		{
			name:           "contains_with_numeric",
			dataType:       "NumericType",
			dataComparator: "Contains",
			expectError:    regexp.MustCompile(`(?i)Contains|StringType`),
		},
		{
			name:           "matches_with_numeric",
			dataType:       "NumericType",
			dataComparator: "Matches",
			expectError:    regexp.MustCompile(`(?i)Matches|StringType`),
		},
		{
			name:           "less_than_with_string",
			dataType:       "StringType",
			dataComparator: "LessThan",
			expectError:    regexp.MustCompile(`(?i)LessThan|NumericType|SemverType`),
		},
		{
			name:           "greater_than_equals_with_string",
			dataType:       "StringType",
			dataComparator: "GreaterThanEquals",
			expectError:    regexp.MustCompile(`(?i)GreaterThanEquals|NumericType|SemverType`),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resource.ParallelTest(t, resource.TestCase{
				PreCheck:                 func() { acctest.PreCheck(t) },
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config: fmt.Sprintf(`
resource "crowdstrike_it_automation_scheduled_task" "test" {
  task_id = %[1]q
  enabled = true
  target  = "platform_name:'Linux'"

  schedule = {
    frequency  = "Daily"
    start_time = "2027-06-01T09:00:00Z"
  }

  trigger_condition = [
    {
      operator = "AND"
      statements = [
        {
          task_id         = %[2]q
          key             = "name"
          data_type       = %[3]q
          data_comparator = %[4]q
          value           = "1"
        },
      ]
    },
  ]
}
`, scheduledTaskFakeTaskID, scheduledTaskFakeQueryID, tc.dataType, tc.dataComparator),
						PlanOnly:    true,
						ExpectError: tc.expectError,
					},
				},
			})
		})
	}
}

func testAccScheduledTaskConfig_basic() string {
	return `
resource "crowdstrike_it_automation_scheduled_task" "test" {
  task_id = crowdstrike_it_automation_task.action.id
  enabled = true
  target  = "platform_name:'Linux'"

  schedule = {
    frequency  = "Daily"
    start_time = "2027-06-01T09:00:00Z"
  }
}
`
}

func testAccScheduledTaskConfig_lifecycleUpdated(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_it_automation_scheduled_task" "test" {
  task_id       = crowdstrike_it_automation_task.query.id
  enabled       = false
  schedule_name = "%[1]s-schedule"
  target        = "platform_name:'Linux'+tags:'production'"

  discover_new_hosts     = true
  queue_offline_hosts    = true
  distribute_execution   = true
  expiration_period      = "1h"
  run_time_limit_minutes = 30

  execution_args = {
    k1 = "v1"
    k2 = "v2"
  }

  schedule = {
    frequency   = "Weekly"
    day_of_week = "Friday"
    start_time  = "2027-06-01T09:00:00Z"
    end_time    = "2028-06-01T09:00:00Z"
  }

  trigger_condition = [
    {
      operator = "OR"
      statements = [
        {
          task_id         = crowdstrike_it_automation_task.query.id
          key             = "name"
          data_type       = "StringType"
          data_comparator = "Equals"
          value           = "bash"
        },
        {
          task_id         = crowdstrike_it_automation_task.query.id
          key             = "name"
          data_type       = "StringType"
          data_comparator = "Equals"
          value           = "zsh"
        },
      ]
    },
  ]
}
`, suffix)
}

func testAccScheduledTaskConfig_scheduleName(name string) string {
	nameLine := ""
	if name != "" {
		nameLine = fmt.Sprintf("schedule_name = %q", name)
	}
	return fmt.Sprintf(`
resource "crowdstrike_it_automation_scheduled_task" "test" {
  task_id = crowdstrike_it_automation_task.action.id
  enabled = true
  target  = "platform_name:'Linux'"
  %[1]s

  schedule = {
    frequency  = "Daily"
    start_time = "2027-06-01T09:00:00Z"
  }
}
`, nameLine)
}

func testAccScheduledTaskConfig_runTimeLimitOptional(minutes int) string {
	line := ""
	if minutes > 0 {
		line = fmt.Sprintf("run_time_limit_minutes = %d", minutes)
	}
	return fmt.Sprintf(`
resource "crowdstrike_it_automation_scheduled_task" "test" {
  task_id = crowdstrike_it_automation_task.action.id
  enabled = true
  target  = "platform_name:'Linux'"
  %[1]s

  schedule = {
    frequency  = "Daily"
    start_time = "2027-06-01T09:00:00Z"
  }
}
`, line)
}

func testAccScheduledTaskConfig_frequency(scheduleBody string) string {
	return fmt.Sprintf(`
resource "crowdstrike_it_automation_scheduled_task" "test" {
  task_id = crowdstrike_it_automation_task.action.id
  enabled = true
  target  = "platform_name:'Linux'"

  schedule = {%s
  }
}
`, scheduleBody)
}

func testAccScheduledTaskConfig_oneTime(enabled bool, target, startTime string) string {
	return fmt.Sprintf(`
resource "crowdstrike_it_automation_scheduled_task" "test" {
  task_id = crowdstrike_it_automation_task.action.id
  enabled = %[1]t
  target  = %[2]q

  schedule = {
    frequency  = "One-Time"
    start_time = %[3]q
  }
}
`, enabled, target, startTime)
}

func testAccScheduledTaskConfig_boolFlags(enabled, discoverNew, queueOffline, distribute bool) string {
	expiration := ""
	if discoverNew || queueOffline || distribute {
		expiration = `expiration_period = "30m"`
	}
	return fmt.Sprintf(`
resource "crowdstrike_it_automation_scheduled_task" "test" {
  task_id              = crowdstrike_it_automation_task.action.id
  enabled              = %[1]t
  target               = "platform_name:'Linux'"
  discover_new_hosts   = %[2]t
  queue_offline_hosts  = %[3]t
  distribute_execution = %[4]t
  %[5]s

  schedule = {
    frequency  = "Daily"
    start_time = "2027-06-01T09:00:00Z"
  }
}
`, enabled, discoverNew, queueOffline, distribute, expiration)
}

func testAccScheduledTaskConfig_triggerOneGroup() string {
	return `
resource "crowdstrike_it_automation_scheduled_task" "test" {
  task_id = crowdstrike_it_automation_task.action.id
  enabled = true
  target  = "platform_name:'Linux'"

  schedule = {
    frequency  = "Daily"
    start_time = "2027-06-01T09:00:00Z"
  }

  trigger_condition = [
    {
      operator = "OR"
      statements = [
        {
          task_id         = crowdstrike_it_automation_task.query.id
          key             = "name"
          data_type       = "StringType"
          data_comparator = "Equals"
          value           = "bash"
        },
        {
          task_id         = crowdstrike_it_automation_task.query.id
          key             = "name"
          data_type       = "StringType"
          data_comparator = "Equals"
          value           = "zsh"
        },
      ]
    },
  ]
}
`
}

func testAccScheduledTaskConfig_triggerTwoGroups() string {
	return `
resource "crowdstrike_it_automation_scheduled_task" "test" {
  task_id = crowdstrike_it_automation_task.action.id
  enabled = true
  target  = "platform_name:'Linux'"

  schedule = {
    frequency  = "Daily"
    start_time = "2027-06-01T09:00:00Z"
  }

  trigger_condition = [
    {
      operator = "OR"
      statements = [
        {
          task_id         = crowdstrike_it_automation_task.query.id
          key             = "name"
          data_type       = "StringType"
          data_comparator = "Equals"
          value           = "bash"
        },
        {
          task_id         = crowdstrike_it_automation_task.query.id
          key             = "name"
          data_type       = "StringType"
          data_comparator = "Equals"
          value           = "zsh"
        },
      ]
    },
    {
      operator = "AND"
      statements = [
        {
          task_id         = crowdstrike_it_automation_task.query.id
          key             = "name"
          data_type       = "StringType"
          data_comparator = "Contains"
          value           = "sh"
        },
      ]
    },
  ]
}
`
}

func testAccScheduledTaskConfig_triggerWithName(scheduleName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_it_automation_scheduled_task" "test" {
  task_id       = crowdstrike_it_automation_task.action.id
  enabled       = true
  target        = "platform_name:'Linux'"
  schedule_name = %[1]q

  schedule = {
    frequency  = "Daily"
    start_time = "2027-06-01T09:00:00Z"
  }

  trigger_condition = [
    {
      operator = "AND"
      statements = [
        {
          task_id         = crowdstrike_it_automation_task.query.id
          key             = "name"
          data_type       = "StringType"
          data_comparator = "Equals"
          value           = "bash"
        },
      ]
    },
  ]
}
`, scheduleName)
}

func testAccScheduledTaskConfig_runTimeLimit(minutes int) string {
	return fmt.Sprintf(`
resource "crowdstrike_it_automation_scheduled_task" "test" {
  task_id                = crowdstrike_it_automation_task.action.id
  enabled                = true
  target                 = "platform_name:'Linux'"
  run_time_limit_minutes = %d

  schedule = {
    frequency  = "Daily"
    start_time = "2027-06-01T09:00:00Z"
  }
}
`, minutes)
}
