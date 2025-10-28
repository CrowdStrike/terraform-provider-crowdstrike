package itautomation_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

const defaultPolicyResourceName = "crowdstrike_it_automation_default_policy.test"

type defaultPolicyConfig struct {
	Platform                        string
	Description                     string
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

func (config *defaultPolicyConfig) String() string {
	isMac := config.Platform == "Mac"

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
resource "crowdstrike_it_automation_default_policy" "test" {
  platform_name    = %q
  description = %q

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
`, config.Platform, config.Description, config.ConcurrentHostFileTransferLimit,
		config.ConcurrentHostLimit, config.ConcurrentTaskLimit, config.EnableOsQuery,
		config.EnablePythonExecution, config.EnableScriptExecution, config.ExecutionTimeout,
		config.ExecutionTimeoutUnit, resourceBlock)
}

func (config *defaultPolicyConfig) TestChecks() resource.TestCheckFunc {
	var checks []resource.TestCheckFunc

	checks = append(checks,
		resource.TestCheckResourceAttrSet(defaultPolicyResourceName, "id"),
		resource.TestCheckResourceAttrSet(defaultPolicyResourceName, "name"),
		resource.TestCheckResourceAttrSet(defaultPolicyResourceName, "last_updated"),
		resource.TestCheckResourceAttr(defaultPolicyResourceName, "platform_name", config.Platform),
		resource.TestCheckResourceAttr(defaultPolicyResourceName, "description", config.Description),
		resource.TestCheckResourceAttr(defaultPolicyResourceName, "concurrent_host_file_transfer_limit", fmt.Sprintf("%d", config.ConcurrentHostFileTransferLimit)),
		resource.TestCheckResourceAttr(defaultPolicyResourceName, "concurrent_host_limit", fmt.Sprintf("%d", config.ConcurrentHostLimit)),
		resource.TestCheckResourceAttr(defaultPolicyResourceName, "concurrent_task_limit", fmt.Sprintf("%d", config.ConcurrentTaskLimit)),
		resource.TestCheckResourceAttr(defaultPolicyResourceName, "enable_os_query", fmt.Sprintf("%t", config.EnableOsQuery)),
		resource.TestCheckResourceAttr(defaultPolicyResourceName, "enable_python_execution", fmt.Sprintf("%t", config.EnablePythonExecution)),
		resource.TestCheckResourceAttr(defaultPolicyResourceName, "enable_script_execution", fmt.Sprintf("%t", config.EnableScriptExecution)),
		resource.TestCheckResourceAttr(defaultPolicyResourceName, "execution_timeout", fmt.Sprintf("%d", config.ExecutionTimeout)),
		resource.TestCheckResourceAttr(defaultPolicyResourceName, "execution_timeout_unit", config.ExecutionTimeoutUnit),
		resource.TestCheckResourceAttr(defaultPolicyResourceName, "enabled", "true"),
	)

	if config.Platform == "Mac" {
		checks = append(checks,
			resource.TestCheckResourceAttr(defaultPolicyResourceName, "cpu_scheduling_priority", *config.CPUSchedulingPriority),
			resource.TestCheckResourceAttr(defaultPolicyResourceName, "memory_pressure_level", *config.MemoryPressureLevel),
		)
	} else {
		checks = append(checks,
			resource.TestCheckResourceAttr(defaultPolicyResourceName, "cpu_throttle", fmt.Sprintf("%d", *config.CPUThrottle)),
			resource.TestCheckResourceAttr(defaultPolicyResourceName, "memory_allocation", fmt.Sprintf("%d", *config.MemoryAllocation)),
			resource.TestCheckResourceAttr(defaultPolicyResourceName, "memory_allocation_unit", *config.MemoryAllocationUnit),
		)
	}

	return resource.ComposeAggregateTestCheckFunc(checks...)
}

func TestAccITAutomationDefaultPolicyResource_Windows(t *testing.T) {
	testCases := []struct {
		name   string
		config defaultPolicyConfig
	}{
		{
			name: "windows_initial",
			config: defaultPolicyConfig{
				Platform:                        "Windows",
				Description:                     "Windows Default Policy - Initial",
				ConcurrentHostFileTransferLimit: 500,
				ConcurrentHostLimit:             5000,
				ConcurrentTaskLimit:             3,
				EnableOsQuery:                   false,
				EnablePythonExecution:           false,
				EnableScriptExecution:           false,
				ExecutionTimeout:                10,
				ExecutionTimeoutUnit:            "Minutes",
				CPUThrottle:                     utils.Addr(15),
				MemoryAllocation:                utils.Addr(1024),
				MemoryAllocationUnit:            utils.Addr("MB"),
			},
		},
		{
			name: "windows_updated",
			config: defaultPolicyConfig{
				Platform:                        "Windows",
				Description:                     "Windows Default Policy - Updated",
				ConcurrentHostFileTransferLimit: 1000,
				ConcurrentHostLimit:             10000,
				ConcurrentTaskLimit:             5,
				EnableOsQuery:                   true,
				EnablePythonExecution:           true,
				EnableScriptExecution:           true,
				ExecutionTimeout:                30,
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
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: acctest.ProviderConfig + tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			steps = append(steps, resource.TestStep{
				ResourceName:      defaultPolicyResourceName,
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

func TestAccITAutomationDefaultPolicyResource_Linux(t *testing.T) {
	testCases := []struct {
		name   string
		config defaultPolicyConfig
	}{
		{
			name: "linux_initial",
			config: defaultPolicyConfig{
				Platform:                        "Linux",
				Description:                     "Linux Default Policy - Initial",
				ConcurrentHostFileTransferLimit: 500,
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
			config: defaultPolicyConfig{
				Platform:                        "Linux",
				Description:                     "Linux Default Policy - Updated",
				ConcurrentHostFileTransferLimit: 750,
				ConcurrentHostLimit:             7500,
				ConcurrentTaskLimit:             4,
				EnableOsQuery:                   false,
				EnablePythonExecution:           false,
				EnableScriptExecution:           true,
				ExecutionTimeout:                45,
				ExecutionTimeoutUnit:            "Minutes",
				CPUThrottle:                     utils.Addr(20),
				MemoryAllocation:                utils.Addr(1536),
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
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: acctest.ProviderConfig + tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			steps = append(steps, resource.TestStep{
				ResourceName:      defaultPolicyResourceName,
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

func TestAccITAutomationDefaultPolicyResource_Mac(t *testing.T) {
	testCases := []struct {
		name   string
		config defaultPolicyConfig
	}{
		{
			name: "mac_initial",
			config: defaultPolicyConfig{
				Platform:                        "Mac",
				Description:                     "Mac Default Policy - Initial",
				ConcurrentHostFileTransferLimit: 500,
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
			config: defaultPolicyConfig{
				Platform:                        "Mac",
				Description:                     "Mac Default Policy - Updated",
				ConcurrentHostFileTransferLimit: 800,
				ConcurrentHostLimit:             8000,
				ConcurrentTaskLimit:             4,
				EnableOsQuery:                   false,
				EnablePythonExecution:           true,
				EnableScriptExecution:           false,
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
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: acctest.ProviderConfig + tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			steps = append(steps, resource.TestStep{
				ResourceName:      defaultPolicyResourceName,
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
