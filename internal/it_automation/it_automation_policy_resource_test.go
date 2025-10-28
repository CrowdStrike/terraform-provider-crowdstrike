package itautomation_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/go-version"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

const policyResourceName = "crowdstrike_it_automation_policy.test"

type policyConfig struct {
	Name                            string
	Description                     string
	Platform                        string
	IsEnabled                       bool
	HostGroups                      []string
	ConcurrentHostFileTransferLimit int
	ConcurrentHostLimit             int
	ConcurrentTaskLimit             int
	EnableOsQuery                   bool
	EnablePythonExecution           bool
	EnableScriptExecution           bool
	ExecutionTimeout                int
	ExecutionTimeoutUnit            string
	CPUThrottle                     *int
	MemoryAllocation                *int
	MemoryAllocationUnit            *string
	CPUSchedulingPriority           *string
	MemoryPressureLevel             *string
}

func (config *policyConfig) String() string {
	isMac := config.Platform == "Mac"

	var hostGroupsBlock string
	if len(config.HostGroups) > 0 {
		hostGroupRef := fmt.Sprintf("crowdstrike_host_group.%s.id", strings.ToLower(config.Platform))
		hostGroupsBlock = fmt.Sprintf("\n  host_groups = [%s]\n", hostGroupRef)
	} else {
		hostGroupsBlock = ""
	}

	var resourceBlock string
	if isMac {
		resourceBlock = fmt.Sprintf(`
  cpu_scheduling_priority = %q
  memory_pressure_level   = %q`, *config.CPUSchedulingPriority, *config.MemoryPressureLevel)
	} else {
		resourceBlock = fmt.Sprintf(`
  cpu_throttle           = %d
  memory_allocation      = %d
  memory_allocation_unit = %q`, *config.CPUThrottle, *config.MemoryAllocation, *config.MemoryAllocationUnit)
	}

	return fmt.Sprintf(`
resource "crowdstrike_it_automation_policy" "test" {
  name        = %q
  description = %q
  platform_name    = %q
  enabled  = %t
%s
  concurrent_host_file_transfer_limit = %d
  concurrent_host_limit               = %d
  concurrent_task_limit               = %d

  enable_os_query         = %t
  enable_python_execution = %t
  enable_script_execution = %t
  execution_timeout       = %d
  execution_timeout_unit  = %q
%s
}
`, config.Name, config.Description, config.Platform, config.IsEnabled, hostGroupsBlock,
		config.ConcurrentHostFileTransferLimit, config.ConcurrentHostLimit,
		config.ConcurrentTaskLimit, config.EnableOsQuery, config.EnablePythonExecution,
		config.EnableScriptExecution, config.ExecutionTimeout, config.ExecutionTimeoutUnit,
		resourceBlock)
}

func (config *policyConfig) TestChecks() resource.TestCheckFunc {
	var checks []resource.TestCheckFunc

	checks = append(checks,
		resource.TestCheckResourceAttrSet(policyResourceName, "id"),
		resource.TestCheckResourceAttrSet(policyResourceName, "last_updated"),
		resource.TestCheckResourceAttr(policyResourceName, "name", config.Name),
		resource.TestCheckResourceAttr(policyResourceName, "description", config.Description),
		resource.TestCheckResourceAttr(policyResourceName, "platform_name", config.Platform),
		resource.TestCheckResourceAttr(policyResourceName, "enabled", fmt.Sprintf("%t", config.IsEnabled)),
		resource.TestCheckResourceAttr(policyResourceName, "concurrent_host_file_transfer_limit", fmt.Sprintf("%d", config.ConcurrentHostFileTransferLimit)),
		resource.TestCheckResourceAttr(policyResourceName, "concurrent_host_limit", fmt.Sprintf("%d", config.ConcurrentHostLimit)),
		resource.TestCheckResourceAttr(policyResourceName, "concurrent_task_limit", fmt.Sprintf("%d", config.ConcurrentTaskLimit)),
		resource.TestCheckResourceAttr(policyResourceName, "enable_os_query", fmt.Sprintf("%t", config.EnableOsQuery)),
		resource.TestCheckResourceAttr(policyResourceName, "enable_python_execution", fmt.Sprintf("%t", config.EnablePythonExecution)),
		resource.TestCheckResourceAttr(policyResourceName, "enable_script_execution", fmt.Sprintf("%t", config.EnableScriptExecution)),
		resource.TestCheckResourceAttr(policyResourceName, "execution_timeout", fmt.Sprintf("%d", config.ExecutionTimeout)),
		resource.TestCheckResourceAttr(policyResourceName, "execution_timeout_unit", config.ExecutionTimeoutUnit),
	)

	if len(config.HostGroups) > 0 {
		checks = append(checks,
			resource.TestCheckResourceAttr(policyResourceName, "host_groups.#", fmt.Sprintf("%d", len(config.HostGroups))),
		)
	}

	if config.Platform == "Mac" {
		checks = append(checks,
			resource.TestCheckResourceAttr(policyResourceName, "cpu_scheduling_priority", *config.CPUSchedulingPriority),
			resource.TestCheckResourceAttr(policyResourceName, "memory_pressure_level", *config.MemoryPressureLevel),
		)
	} else {
		checks = append(checks,
			resource.TestCheckResourceAttr(policyResourceName, "cpu_throttle", fmt.Sprintf("%d", *config.CPUThrottle)),
			resource.TestCheckResourceAttr(policyResourceName, "memory_allocation", fmt.Sprintf("%d", *config.MemoryAllocation)),
			resource.TestCheckResourceAttr(policyResourceName, "memory_allocation_unit", *config.MemoryAllocationUnit),
		)
	}

	return resource.ComposeAggregateTestCheckFunc(checks...)
}

func TestAccITAutomationPolicyResource_Windows(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acctest")

	testCases := []struct {
		name   string
		config policyConfig
	}{
		{
			name: "windows_initial",
			config: policyConfig{
				Name:                            rName,
				Description:                     "Windows policy for testing",
				Platform:                        "Windows",
				IsEnabled:                       true,
				HostGroups:                      []string{"placeholder"},
				ConcurrentHostFileTransferLimit: 2500,
				ConcurrentHostLimit:             5000,
				ConcurrentTaskLimit:             3,
				EnableOsQuery:                   true,
				EnablePythonExecution:           true,
				EnableScriptExecution:           true,
				ExecutionTimeout:                30,
				ExecutionTimeoutUnit:            "Minutes",
				CPUThrottle:                     utils.Addr(15),
				MemoryAllocation:                utils.Addr(1024),
				MemoryAllocationUnit:            utils.Addr("MB"),
			},
		},
		{
			name: "windows_updated",
			config: policyConfig{
				Name:                            rName + "-updated",
				Description:                     "Windows policy updated",
				Platform:                        "Windows",
				IsEnabled:                       false,
				HostGroups:                      []string{"placeholder"},
				ConcurrentHostFileTransferLimit: 3000,
				ConcurrentHostLimit:             10000,
				ConcurrentTaskLimit:             5,
				EnableOsQuery:                   false,
				EnablePythonExecution:           false,
				EnableScriptExecution:           true,
				ExecutionTimeout:                60,
				ExecutionTimeoutUnit:            "Minutes",
				CPUThrottle:                     utils.Addr(25),
				MemoryAllocation:                utils.Addr(2048),
				MemoryAllocationUnit:            utils.Addr("MB"),
			},
		},
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
		},
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			fixtures := getTestFixtures()
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: acctest.ProviderConfig + fixtures.HostGroupsOnly() + tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			steps = append(steps, resource.TestStep{
				ResourceName:      policyResourceName,
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

func TestAccITAutomationPolicyResource_Linux(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acctest")

	testCases := []struct {
		name   string
		config policyConfig
	}{
		{
			name: "linux_initial",
			config: policyConfig{
				Name:                            rName,
				Description:                     "Linux policy for testing",
				Platform:                        "Linux",
				IsEnabled:                       true,
				HostGroups:                      []string{"placeholder"},
				ConcurrentHostFileTransferLimit: 2500,
				ConcurrentHostLimit:             5000,
				ConcurrentTaskLimit:             3,
				EnableOsQuery:                   true,
				EnablePythonExecution:           true,
				EnableScriptExecution:           true,
				ExecutionTimeout:                30,
				ExecutionTimeoutUnit:            "Minutes",
				CPUThrottle:                     utils.Addr(15),
				MemoryAllocation:                utils.Addr(1024),
				MemoryAllocationUnit:            utils.Addr("MB"),
			},
		},
		{
			name: "linux_updated",
			config: policyConfig{
				Name:                            rName + "-updated",
				Description:                     "Linux policy updated",
				Platform:                        "Linux",
				IsEnabled:                       false,
				HostGroups:                      []string{"placeholder"},
				ConcurrentHostFileTransferLimit: 3000,
				ConcurrentHostLimit:             10000,
				ConcurrentTaskLimit:             5,
				EnableOsQuery:                   false,
				EnablePythonExecution:           false,
				EnableScriptExecution:           true,
				ExecutionTimeout:                60,
				ExecutionTimeoutUnit:            "Minutes",
				CPUThrottle:                     utils.Addr(25),
				MemoryAllocation:                utils.Addr(2048),
				MemoryAllocationUnit:            utils.Addr("MB"),
			},
		},
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
		},
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			fixtures := getTestFixtures()
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: acctest.ProviderConfig + fixtures.HostGroupsOnly() + tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			steps = append(steps, resource.TestStep{
				ResourceName:      policyResourceName,
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

func TestAccITAutomationPolicyResource_Mac(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acctest")

	testCases := []struct {
		name   string
		config policyConfig
	}{
		{
			name: "mac_initial",
			config: policyConfig{
				Name:                            rName,
				Description:                     "Mac policy for testing",
				Platform:                        "Mac",
				IsEnabled:                       true,
				HostGroups:                      []string{"placeholder"},
				ConcurrentHostFileTransferLimit: 2500,
				ConcurrentHostLimit:             5000,
				ConcurrentTaskLimit:             3,
				EnableOsQuery:                   true,
				EnablePythonExecution:           true,
				EnableScriptExecution:           true,
				ExecutionTimeout:                30,
				ExecutionTimeoutUnit:            "Minutes",
				CPUSchedulingPriority:           utils.Addr("Medium"),
				MemoryPressureLevel:             utils.Addr("Medium"),
			},
		},
		{
			name: "mac_updated",
			config: policyConfig{
				Name:                            rName + "-updated",
				Description:                     "Mac policy updated",
				Platform:                        "Mac",
				IsEnabled:                       false,
				HostGroups:                      []string{"placeholder"},
				ConcurrentHostFileTransferLimit: 3000,
				ConcurrentHostLimit:             10000,
				ConcurrentTaskLimit:             5,
				EnableOsQuery:                   false,
				EnablePythonExecution:           false,
				EnableScriptExecution:           true,
				ExecutionTimeout:                60,
				ExecutionTimeoutUnit:            "Minutes",
				CPUSchedulingPriority:           utils.Addr("High"),
				MemoryPressureLevel:             utils.Addr("Low"),
			},
		},
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
		},
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			fixtures := getTestFixtures()
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: acctest.ProviderConfig + fixtures.HostGroupsOnly() + tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			steps = append(steps, resource.TestStep{
				ResourceName:      policyResourceName,
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
