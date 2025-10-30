package itautomation_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/go-version"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

const taskGroupResourceName = "crowdstrike_it_automation_task_group.test"

type taskGroupConfig struct {
	Name            string
	Description     string
	AccessType      string
	AssignedUserIds []string
	TaskIds         []string
}

func (config *taskGroupConfig) String() string {
	taskResources := ""
	var taskRefs []string

	for i := range len(config.TaskIds) {
		randomSuffix := sdkacctest.RandomWithPrefix("tf-acctest")
		taskName := fmt.Sprintf("task-%s-%d", randomSuffix, i)

		taskResources += fmt.Sprintf(`
resource "crowdstrike_it_automation_task" "task%d" {
  name        = "%s"
  description = "Test task %d for task group"
  type        = "query"
  os_query    = "SELECT * FROM system_info;"
}
`, i, taskName, i)

		taskRefs = append(taskRefs, fmt.Sprintf("crowdstrike_it_automation_task.task%d.id", i))
	}

	result := fmt.Sprintf(`%s
resource "crowdstrike_it_automation_task_group" "test" {
  name        = %q
  description = %q
  access_type = %q
`, taskResources, config.Name, config.Description, config.AccessType)

	if len(config.AssignedUserIds) > 0 {
		result += "\n  assigned_user_ids = [\n"
		for _, uid := range config.AssignedUserIds {
			result += fmt.Sprintf("    %q,\n", uid)
		}
		result += "  ]\n"
	}

	if len(taskRefs) > 0 {
		result += fmt.Sprintf("\n  task_ids = [%s]\n", strings.Join(taskRefs, ", "))
	}

	result += "}\n"
	return result
}

func (config *taskGroupConfig) TestChecks() resource.TestCheckFunc {
	var checks []resource.TestCheckFunc

	checks = append(checks,
		resource.TestCheckResourceAttrSet(taskGroupResourceName, "id"),
		resource.TestCheckResourceAttrSet(taskGroupResourceName, "last_updated"),
		resource.TestCheckResourceAttr(taskGroupResourceName, "name", config.Name),
		resource.TestCheckResourceAttr(taskGroupResourceName, "description", config.Description),
		resource.TestCheckResourceAttr(taskGroupResourceName, "access_type", config.AccessType),
	)

	if len(config.AssignedUserIds) > 0 {
		checks = append(checks,
			resource.TestCheckResourceAttr(taskGroupResourceName, "assigned_user_ids.#", fmt.Sprintf("%d", len(config.AssignedUserIds))),
		)
	}

	if len(config.TaskIds) > 0 {
		checks = append(checks,
			resource.TestCheckResourceAttr(taskGroupResourceName, "task_ids.#", fmt.Sprintf("%d", len(config.TaskIds))),
		)
	}

	return resource.ComposeAggregateTestCheckFunc(checks...)
}

func TestAccITAutomationTaskGroupResource_Basic(t *testing.T) {
	sdk := createSDKFixtures(t)
	t.Cleanup(func() { sdk.Cleanup(t) })

	rName := sdkacctest.RandomWithPrefix("tf-acctest")

	testCases := []struct {
		name   string
		config taskGroupConfig
	}{
		{
			name: "task_group_initial",
			config: taskGroupConfig{
				Name:            rName,
				Description:     "Task group for testing",
				AccessType:      "Shared",
				AssignedUserIds: sdk.UserIDs,
			},
		},
		{
			name: "task_group_updated",
			config: taskGroupConfig{
				Name:        rName + "-updated",
				Description: "Updated task group",
				AccessType:  "Public",
			},
		},
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
		},
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: acctest.ProviderConfig + tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			steps = append(steps, resource.TestStep{
				ResourceName:      taskGroupResourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"last_updated",
				},
			})
			return steps
		}(),
	})
}

func TestAccITAutomationTaskGroupResource_AccessTypes(t *testing.T) {
	sdk := createSDKFixtures(t)
	t.Cleanup(func() { sdk.Cleanup(t) })

	rName := sdkacctest.RandomWithPrefix("tf-acctest")

	testCases := []struct {
		name   string
		config taskGroupConfig
	}{
		{
			name: "shared_access",
			config: taskGroupConfig{
				Name:            rName + "-shared",
				Description:     "Task group with shared access",
				AccessType:      "Shared",
				AssignedUserIds: sdk.UserIDs,
			},
		},
		{
			name: "public_access",
			config: taskGroupConfig{
				Name:        rName + "-public",
				Description: "Task group with public access",
				AccessType:  "Public",
			},
		},
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
		},
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: acctest.ProviderConfig + tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			return steps
		}(),
	})
}

func TestAccITAutomationTaskGroupResource_WithTasks(t *testing.T) {
	sdk := createSDKFixtures(t)
	t.Cleanup(func() { sdk.Cleanup(t) })

	rName := sdkacctest.RandomWithPrefix("tf-acctest")

	testCases := []struct {
		name   string
		config taskGroupConfig
	}{
		{
			name: "task_group_with_tasks_initial",
			config: taskGroupConfig{
				Name:            rName,
				Description:     "Task group containing tasks",
				AccessType:      "Shared",
				AssignedUserIds: sdk.UserIDs,
				TaskIds:         []string{"placeholder1", "placeholder2", "placeholder3"},
			},
		},
		{
			name: "task_group_with_tasks_updated",
			config: taskGroupConfig{
				Name:        rName + "-updated",
				Description: "Updated task group with tasks",
				AccessType:  "Public",
				TaskIds:     []string{"placeholder1"},
			},
		},
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(t)
		},
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
		},
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: acctest.ProviderConfig + tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			steps = append(steps, resource.TestStep{
				ResourceName:      taskGroupResourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"last_updated",
				},
			})
			return steps
		}(),
	})
}
