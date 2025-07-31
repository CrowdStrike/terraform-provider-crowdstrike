package contentupdatepolicy_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

const defaultPolicyResourceName = "crowdstrike_default_content_update_policy.test"

// defaultPolicyConfig represents a complete default policy configuration.
type defaultPolicyConfig struct {
	Description             string
	SensorOperations        ringConfig
	SystemCritical          ringConfig
	VulnerabilityManagement ringConfig
	RapidResponse           ringConfig
}

// String implements the Stringer interface and generates Terraform configuration from defaultPolicyConfig.
func (config *defaultPolicyConfig) String() string {
	return fmt.Sprintf(`
resource "crowdstrike_default_content_update_policy" "test" {
  description = %q

  sensor_operations = {
    ring_assignment = %q
	%s
  }

  system_critical = {
    ring_assignment = %q
	%s
  }

  vulnerability_management = {
    ring_assignment = %q
	%s
  }

  rapid_response = {
    ring_assignment = %q
	%s
  }
}
`,
		config.Description,
		config.SensorOperations.RingAssignment, config.SensorOperations.formatDelayHours(),
		config.SystemCritical.RingAssignment, config.SystemCritical.formatDelayHours(),
		config.VulnerabilityManagement.RingAssignment, config.VulnerabilityManagement.formatDelayHours(),
		config.RapidResponse.RingAssignment, config.RapidResponse.formatDelayHours())
}

// TestChecks generates all appropriate test checks based on the default policy configuration.
func (config *defaultPolicyConfig) TestChecks() resource.TestCheckFunc {
	var checks []resource.TestCheckFunc

	checks = append(checks,
		resource.TestCheckResourceAttrSet(defaultPolicyResourceName, "id"),
		resource.TestCheckResourceAttrSet(defaultPolicyResourceName, "last_updated"),
		resource.TestCheckResourceAttr(defaultPolicyResourceName, "description", config.Description),
	)

	checks = append(checks, config.SensorOperations.generateDefaultPolicyChecks("sensor_operations")...)
	checks = append(checks, config.SystemCritical.generateDefaultPolicyChecks("system_critical")...)
	checks = append(checks, config.VulnerabilityManagement.generateDefaultPolicyChecks("vulnerability_management")...)
	checks = append(checks, config.RapidResponse.generateDefaultPolicyChecks("rapid_response")...)

	return resource.ComposeAggregateTestCheckFunc(checks...)
}

// generateDefaultPolicyChecks creates appropriate test checks for a ring configuration in default policy context.
func (ring ringConfig) generateDefaultPolicyChecks(category string) []resource.TestCheckFunc {
	var checks []resource.TestCheckFunc

	checks = append(checks, resource.TestCheckResourceAttr(defaultPolicyResourceName, category+".ring_assignment", ring.RingAssignment))

	if ring.RingAssignment != "ga" {
		checks = append(checks, resource.TestCheckNoResourceAttr(defaultPolicyResourceName, category+".delay_hours"))
	} else {
		if ring.DelayHours != nil {
			checks = append(checks, resource.TestCheckResourceAttr(defaultPolicyResourceName, category+".delay_hours", fmt.Sprintf("%d", *ring.DelayHours)))
		} else {
			checks = append(checks, resource.TestCheckResourceAttr(defaultPolicyResourceName, category+".delay_hours", "0"))
		}
	}

	return checks
}

func TestAccDefaultContentUpdatePolicyResource_Basic(t *testing.T) {
	testCases := []struct {
		name   string
		config defaultPolicyConfig
	}{
		{
			name: "mixed_configuration_initial",
			config: defaultPolicyConfig{
				Description: "Default content update policy with mixed ring assignments - initial configuration",
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(24),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ea",
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
		},
		{
			name: "mixed_configuration_updated",
			config: defaultPolicyConfig{
				Description: "Default content update policy with mixed ring assignments - updated configuration",
				SensorOperations: ringConfig{
					RingAssignment: "ea",
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(48),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(12),
				},
				RapidResponse: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
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

func TestAccDefaultContentUpdatePolicyResource_AllGA(t *testing.T) {
	testCases := []struct {
		name   string
		config defaultPolicyConfig
	}{
		{
			name: "all_ga_zero_delay",
			config: defaultPolicyConfig{
				Description: "Default content update policy with all GA ring assignments and zero delay",
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				RapidResponse: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
			},
		},
		{
			name: "all_ga_various_delays",
			config: defaultPolicyConfig{
				Description: "Default content update policy with all GA ring assignments and various delay hours",
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(12),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(24),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(48),
				},
				RapidResponse: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(72),
				},
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
			return steps
		}(),
	})
}

func TestAccDefaultContentUpdatePolicyResource_AllEA(t *testing.T) {
	testCases := []struct {
		name   string
		config defaultPolicyConfig
	}{
		{
			name: "all_ea_no_delays",
			config: defaultPolicyConfig{
				Description: "Default content update policy with all EA ring assignments",
				SensorOperations: ringConfig{
					RingAssignment: "ea",
				},
				SystemCritical: ringConfig{
					RingAssignment: "ea",
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ea",
				},
				RapidResponse: ringConfig{
					RingAssignment: "ea",
				},
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
			return steps
		}(),
	})
}

func TestAccDefaultContentUpdatePolicyResource_DelayHoursBoundaries(t *testing.T) {
	validDelayHours := []int{0, 1, 2, 4, 8, 12, 24, 48, 72}

	var testCases []struct {
		name   string
		config defaultPolicyConfig
	}

	for _, delay := range validDelayHours {
		testCases = append(testCases, struct {
			name   string
			config defaultPolicyConfig
		}{
			name: fmt.Sprintf("delay_hours_%d", delay),
			config: defaultPolicyConfig{
				Description: fmt.Sprintf("Default content update policy testing delay hours boundary value: %d", delay),
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(delay),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(delay),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(delay),
				},
				RapidResponse: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(delay),
				},
			},
		})
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
			return steps
		}(),
	})
}

func TestAccDefaultContentUpdatePolicyResource_Validation(t *testing.T) {
	validationTests := []struct {
		name        string
		config      defaultPolicyConfig
		expectError *regexp.Regexp
	}{
		{
			name: "invalid_delay_with_ea_ring_sensor_operations",
			config: defaultPolicyConfig{
				Description: "Test policy with invalid delay hours on EA ring assignment - should fail validation",
				SensorOperations: ringConfig{
					RingAssignment: "ea",
					DelayHours:     utils.Addr(24),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ea",
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
			expectError: regexp.MustCompile("delay_hours can only be set when ring_assignment is 'ga'"),
		},
		{
			name: "invalid_delay_with_pause_ring_vulnerability_management",
			config: defaultPolicyConfig{
				Description: "Test policy with invalid delay hours on pause ring assignment - should fail validation",
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(24),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "pause",
					DelayHours:     utils.Addr(12),
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
			expectError: regexp.MustCompile("delay_hours can only be set when ring_assignment is 'ga'"),
		},
		{
			name: "system_critical_cannot_use_pause",
			config: defaultPolicyConfig{
				Description: "Test policy with pause on system critical - should fail validation",
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				SystemCritical: ringConfig{
					RingAssignment: "pause",
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ea",
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
			expectError: regexp.MustCompile(`(?s).*Attribute system_critical.ring_assignment value must be one of.*"pause"`),
		},
		{
			name: "invalid_delay_hours_too_high",
			config: defaultPolicyConfig{
				Description: "Test policy with invalid delay hours value - should fail validation",
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(100),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ea",
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
			expectError: regexp.MustCompile("Attribute sensor_operations.delay_hours value must be one of"),
		},
		{
			name: "invalid_ring_assignment",
			config: defaultPolicyConfig{
				Description: "Test policy with invalid ring assignment value - should fail validation",
				SensorOperations: ringConfig{
					RingAssignment: "invalid",
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ea",
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
			expectError: regexp.MustCompile("Attribute sensor_operations.ring_assignment value must be one of"),
		},
		{
			name: "empty_description",
			config: defaultPolicyConfig{
				Description: "",
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ea",
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
			expectError: regexp.MustCompile("Attribute description string length must be at least 1"),
		},
	}

	for _, tc := range validationTests {
		t.Run(tc.name, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { acctest.PreCheck(t) },
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				TerraformVersionChecks: []tfversion.TerraformVersionCheck{
					tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
				},
				Steps: []resource.TestStep{
					{
						Config:      acctest.ProviderConfig + tc.config.String(),
						ExpectError: tc.expectError,
					},
				},
			})
		})
	}
}

func TestAccDefaultContentUpdatePolicyResource_RingTransitions(t *testing.T) {
	testCases := []struct {
		name   string
		config defaultPolicyConfig
	}{
		{
			name: "all_pause_to_mixed",
			config: defaultPolicyConfig{
				Description: "Default content update policy transitioning from pause to mixed assignments",
				SensorOperations: ringConfig{
					RingAssignment: "pause",
				},
				SystemCritical: ringConfig{
					RingAssignment: "ea",
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "pause",
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
		},
		{
			name: "mixed_to_all_ga",
			config: defaultPolicyConfig{
				Description: "Default content update policy transitioning to all GA assignments with various delays",
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(1),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(2),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(4),
				},
				RapidResponse: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(8),
				},
			},
		},
		{
			name: "ga_to_ea_transitions",
			config: defaultPolicyConfig{
				Description: "Default content update policy transitioning from GA to all EA assignments",
				SensorOperations: ringConfig{
					RingAssignment: "ea",
				},
				SystemCritical: ringConfig{
					RingAssignment: "ea",
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ea",
				},
				RapidResponse: ringConfig{
					RingAssignment: "ea",
				},
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
			return steps
		}(),
	})
}
