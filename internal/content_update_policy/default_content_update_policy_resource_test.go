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

// cleanInitialConfig ensures no pinned versions exist before any test starts.
var cleanInitialConfig = defaultPolicyConfig{
	Description: "Clean initial state - no pinned versions",
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
}

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
	// Include data source for content versions when pinned versions are used
	dataSource := ""
	if config.SensorOperations.PinnedContentVersion != nil ||
		config.SystemCritical.PinnedContentVersion != nil ||
		config.VulnerabilityManagement.PinnedContentVersion != nil ||
		config.RapidResponse.PinnedContentVersion != nil {
		dataSource = `data "crowdstrike_content_category_versions" "test" {}

`
	}

	return fmt.Sprintf(`%s
resource "crowdstrike_default_content_update_policy" "test" {
  description = %q

  sensor_operations = {
    ring_assignment = %q
	%s
	%s
  }

  system_critical = {
    ring_assignment = %q
	%s
	%s
  }

  vulnerability_management = {
    ring_assignment = %q
	%s
	%s
  }

  rapid_response = {
    ring_assignment = %q
	%s
	%s
  }
}
`,
		dataSource,
		config.Description,
		config.SensorOperations.RingAssignment, config.SensorOperations.formatDelayHours(), config.SensorOperations.formatPinnedVersion(),
		config.SystemCritical.RingAssignment, config.SystemCritical.formatDelayHours(), config.SystemCritical.formatPinnedVersion(),
		config.VulnerabilityManagement.RingAssignment, config.VulnerabilityManagement.formatDelayHours(), config.VulnerabilityManagement.formatPinnedVersion(),
		config.RapidResponse.RingAssignment, config.RapidResponse.formatDelayHours(), config.RapidResponse.formatPinnedVersion())
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

	if ring.PinnedContentVersion != nil {
		checks = append(checks, resource.TestCheckResourceAttrSet(defaultPolicyResourceName, category+".pinned_content_version"))
	} else {
		checks = append(checks, resource.TestCheckNoResourceAttr(defaultPolicyResourceName, category+".pinned_content_version"))
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
			tfversion.SkipBelow(version.Must(version.NewVersion("1.9.3"))),
		},
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			// Start with clean initial state to ensure no pinned versions exist
			steps = append(steps, resource.TestStep{
				Config: acctest.ProviderConfig + cleanInitialConfig.String(),
				Check:  cleanInitialConfig.TestChecks(),
			})
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

func TestAccDefaultContentUpdatePolicyResource_PinnedContentVersionUpdates(t *testing.T) {
	testCases := []struct {
		name   string
		config defaultPolicyConfig
	}{
		{
			name: "add_pinned_version",
			config: defaultPolicyConfig{
				Description: "Default policy adding pinned version to existing configuration",
				SensorOperations: ringConfig{
					RingAssignment: "ga",
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
		},
		{
			name: "with_pinned_version",
			config: defaultPolicyConfig{
				Description: "Default policy adding pinned version to existing configuration",
				SensorOperations: ringConfig{
					RingAssignment:       "ga",
					DelayHours:           utils.Addr(24),
					PinnedContentVersion: utils.Addr("data.crowdstrike_content_category_versions.test.sensor_operations[0]"),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment:       "ea",
					PinnedContentVersion: utils.Addr("data.crowdstrike_content_category_versions.test.vulnerability_management[0]"),
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
		},
		{
			name: "update_pinned_version",
			config: defaultPolicyConfig{
				Description: "Default policy updating pinned version values",
				SensorOperations: ringConfig{
					RingAssignment:       "ga",
					DelayHours:           utils.Addr(24),
					PinnedContentVersion: utils.Addr("length(data.crowdstrike_content_category_versions.test.sensor_operations) > 1 ? data.crowdstrike_content_category_versions.test.sensor_operations[1] : data.crowdstrike_content_category_versions.test.sensor_operations[0]"),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment:       "ea",
					PinnedContentVersion: utils.Addr("length(data.crowdstrike_content_category_versions.test.vulnerability_management) > 1 ? data.crowdstrike_content_category_versions.test.vulnerability_management[1] : data.crowdstrike_content_category_versions.test.vulnerability_management[0]"),
				},
				RapidResponse: ringConfig{
					RingAssignment:       "pause",
					PinnedContentVersion: utils.Addr("data.crowdstrike_content_category_versions.test.rapid_response[0]"),
				},
			},
		},
		{
			name: "remove_pinned_version",
			config: defaultPolicyConfig{
				Description: "Default policy removing pinned version",
				SensorOperations: ringConfig{
					RingAssignment: "ga",
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
		},
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.9.3"))),
		},
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			// Start with clean initial state to ensure no pinned versions exist
			steps = append(steps, resource.TestStep{
				Config: acctest.ProviderConfig + cleanInitialConfig.String(),
				Check:  cleanInitialConfig.TestChecks(),
			})
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

func TestAccDefaultContentUpdatePolicyResource_PinnedContentVersionValidationErrors(t *testing.T) {
	// Test ring assignment change errors with pinned versions
	validationTests := []struct {
		name        string
		config      defaultPolicyConfig
		expectError *regexp.Regexp
	}{
		{
			name: "sensor_operations_ring_assignment_change_blocked",
			config: defaultPolicyConfig{
				Description: "Default policy with pinned sensor operations version",
				SensorOperations: ringConfig{
					RingAssignment:       "ea",
					PinnedContentVersion: utils.Addr("data.crowdstrike_content_category_versions.test.sensor_operations[0]"),
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
			expectError: regexp.MustCompile("Cannot change ring assignment with pinned content version"),
		},
		{
			name: "system_critical_ring_assignment_change_blocked",
			config: defaultPolicyConfig{
				Description: "Default policy with pinned system critical version",
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				SystemCritical: ringConfig{
					RingAssignment:       "ea",
					PinnedContentVersion: utils.Addr("data.crowdstrike_content_category_versions.test.system_critical[0]"),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ea",
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
			expectError: regexp.MustCompile("Cannot change ring assignment with pinned content version"),
		},
		{
			name: "sensor_operations_delay_hours_change_blocked",
			config: defaultPolicyConfig{
				Description: "Default policy with pinned sensor operations version",
				SensorOperations: ringConfig{
					RingAssignment:       "ga",
					DelayHours:           utils.Addr(48),
					PinnedContentVersion: utils.Addr("data.crowdstrike_content_category_versions.test.sensor_operations[0]"),
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
			expectError: regexp.MustCompile("Cannot change delay hours with pinned content version"),
		},
		{
			name: "system_critical_delay_hours_change_blocked",
			config: defaultPolicyConfig{
				Description: "Default policy with pinned system critical version",
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				SystemCritical: ringConfig{
					RingAssignment:       "ga",
					DelayHours:           utils.Addr(72),
					PinnedContentVersion: utils.Addr("data.crowdstrike_content_category_versions.test.system_critical[0]"),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ea",
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
			expectError: regexp.MustCompile("Cannot change delay hours with pinned content version"),
		},
	}

	for _, tc := range validationTests {
		t.Run(tc.name, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { acctest.PreCheck(t) },
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				TerraformVersionChecks: []tfversion.TerraformVersionCheck{
					tfversion.SkipBelow(version.Must(version.NewVersion("1.9.3"))),
				},
				Steps: []resource.TestStep{
					// Start with clean initial state to ensure no pinned versions exist
					{
						Config: acctest.ProviderConfig + cleanInitialConfig.String(),
						Check:  cleanInitialConfig.TestChecks(),
					},
					{
						Config:      acctest.ProviderConfig + tc.config.String(),
						ExpectError: tc.expectError,
					},
				},
			})
		})
	}
}

func TestAccDefaultContentUpdatePolicyResource_PinnedContentVersionValidTransitions(t *testing.T) {
	// Test scenarios where pinned version changes should succeed
	testCases := []struct {
		name   string
		config defaultPolicyConfig
	}{
		{
			name: "initial_state_with_pinned_version",
			config: defaultPolicyConfig{
				Description: "Default policy valid transition initial state",
				SensorOperations: ringConfig{
					RingAssignment:       "ga",
					DelayHours:           utils.Addr(0),
					PinnedContentVersion: utils.Addr("data.crowdstrike_content_category_versions.test.sensor_operations[0]"),
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
		},
		{
			name: "remove_pinned_version_then_change_ring",
			config: defaultPolicyConfig{
				Description: "Default policy valid transition after removing pinned version",
				SensorOperations: ringConfig{
					RingAssignment: "ea",
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
		},
		{
			name: "change_other_fields_with_pinned",
			config: defaultPolicyConfig{
				Description: "Updated description while keeping pinned version",
				SensorOperations: ringConfig{
					RingAssignment:       "ea",
					PinnedContentVersion: utils.Addr("data.crowdstrike_content_category_versions.test.sensor_operations[0]"),
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
		},
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.9.3"))),
		},
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			// Start with clean initial state to ensure no pinned versions exist
			steps = append(steps, resource.TestStep{
				Config: acctest.ProviderConfig + cleanInitialConfig.String(),
				Check:  cleanInitialConfig.TestChecks(),
			})
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

func TestAccDefaultContentUpdatePolicyResource_PinnedContentVersion(t *testing.T) {
	testCases := []struct {
		name   string
		config defaultPolicyConfig
	}{
		{
			name: "single_category_pinned",
			config: defaultPolicyConfig{
				Description: "Default content update policy with single pinned category",
				SensorOperations: ringConfig{
					RingAssignment:       "ga",
					DelayHours:           utils.Addr(0), // Keep same as clean config to avoid validation error
					PinnedContentVersion: utils.Addr("data.crowdstrike_content_category_versions.test.sensor_operations[0]"),
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
		},
		{
			name: "all_categories_pinned",
			config: defaultPolicyConfig{
				Description: "Default content update policy with all categories pinned",
				SensorOperations: ringConfig{
					RingAssignment:       "ga",
					DelayHours:           utils.Addr(0), // Keep same as clean config
					PinnedContentVersion: utils.Addr("data.crowdstrike_content_category_versions.test.sensor_operations[0]"),
				},
				SystemCritical: ringConfig{
					RingAssignment:       "ga",
					DelayHours:           utils.Addr(0), // Keep same as clean config
					PinnedContentVersion: utils.Addr("data.crowdstrike_content_category_versions.test.system_critical[0]"),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment:       "ea", // Keep same as clean config
					PinnedContentVersion: utils.Addr("data.crowdstrike_content_category_versions.test.vulnerability_management[0]"),
				},
				RapidResponse: ringConfig{
					RingAssignment:       "pause", // Keep same as clean config
					PinnedContentVersion: utils.Addr("data.crowdstrike_content_category_versions.test.rapid_response[0]"),
				},
			},
		},
		{
			name: "mixed_pinned_unpinned",
			config: defaultPolicyConfig{
				Description: "Default content update policy with mixed pinned and unpinned categories",
				SensorOperations: ringConfig{
					RingAssignment:       "ga",
					DelayHours:           utils.Addr(0), // Keep same as clean config
					PinnedContentVersion: utils.Addr("data.crowdstrike_content_category_versions.test.sensor_operations[0]"),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga", // Keep same as clean config
					DelayHours:     utils.Addr(0),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment:       "ea", // Keep same as clean config
					PinnedContentVersion: utils.Addr("data.crowdstrike_content_category_versions.test.vulnerability_management[0]"),
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause", // Keep same as clean config
				},
			},
		},
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.9.3"))),
		},
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			// Start with clean initial state to ensure no pinned versions exist
			steps = append(steps, resource.TestStep{
				Config: acctest.ProviderConfig + cleanInitialConfig.String(),
				Check:  cleanInitialConfig.TestChecks(),
			})
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: acctest.ProviderConfig + tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
				steps = append(steps, resource.TestStep{
					ResourceName:      defaultPolicyResourceName,
					ImportState:       true,
					ImportStateVerify: true,
					ImportStateVerifyIgnore: []string{
						"last_updated",
					},
				})
			}
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
			tfversion.SkipBelow(version.Must(version.NewVersion("1.9.3"))),
		},
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			// Start with clean initial state to ensure no pinned versions exist
			steps = append(steps, resource.TestStep{
				Config: acctest.ProviderConfig + cleanInitialConfig.String(),
				Check:  cleanInitialConfig.TestChecks(),
			})
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
			tfversion.SkipBelow(version.Must(version.NewVersion("1.9.3"))),
		},
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			// Start with clean initial state to ensure no pinned versions exist
			steps = append(steps, resource.TestStep{
				Config: acctest.ProviderConfig + cleanInitialConfig.String(),
				Check:  cleanInitialConfig.TestChecks(),
			})
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
			tfversion.SkipBelow(version.Must(version.NewVersion("1.9.3"))),
		},
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			// Start with clean initial state to ensure no pinned versions exist
			steps = append(steps, resource.TestStep{
				Config: acctest.ProviderConfig + cleanInitialConfig.String(),
				Check:  cleanInitialConfig.TestChecks(),
			})
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
					tfversion.SkipBelow(version.Must(version.NewVersion("1.9.3"))),
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
			tfversion.SkipBelow(version.Must(version.NewVersion("1.9.3"))),
		},
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			// Start with clean initial state to ensure no pinned versions exist
			steps = append(steps, resource.TestStep{
				Config: acctest.ProviderConfig + cleanInitialConfig.String(),
				Check:  cleanInitialConfig.TestChecks(),
			})
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
