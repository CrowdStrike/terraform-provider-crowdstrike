package sensorvisibilityexclusion_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// exclusionConfig represents a complete sensor visibility exclusion configuration.
type exclusionConfig struct {
	Value                      string
	ApplyToDescendantProcesses *bool
	ApplyGlobally              *bool
	HostGroupCount             int
}

// String implements the Stringer interface and generates Terraform configuration from exclusionConfig.
func (config *exclusionConfig) String() string {
	var hostGroupResources string
	var hostGroupsBlock string
	var applyGloballyBlock string

	randomSuffix := sdkacctest.RandString(8)

	// Validate configuration - either apply_globally should be true OR host groups should be provided
	if config.ApplyGlobally != nil && *config.ApplyGlobally {
		if config.HostGroupCount > 0 {
			panic("Cannot have both apply_globally=true and host groups")
		}
		applyGloballyBlock = "apply_globally = true"
	} else if config.HostGroupCount > 0 {
		var hostGroupRefs []string
		for i := 0; i < config.HostGroupCount; i++ {
			hostGroupName := fmt.Sprintf("hg-%s-%d", randomSuffix, i)

			hostGroupResources += fmt.Sprintf(`
resource "crowdstrike_host_group" "hg_%d" {
  name        = "%s"
  description = "Test host group %d for sensor visibility exclusion"
  type        = "static"
  hostnames   = ["test-host%d-1", "test-host%d-2"]
}
`, i, hostGroupName, i, i, i)
			hostGroupRefs = append(hostGroupRefs, fmt.Sprintf("crowdstrike_host_group.hg_%d.id", i))
		}

		hostGroupsBlock = fmt.Sprintf(`
  host_groups = [%s]`, strings.Join(hostGroupRefs, ", "))
	} else {
		// Default to apply_globally = true if neither is specified
		applyGloballyBlock = "apply_globally = true"
	}

	return fmt.Sprintf(`%s
resource "crowdstrike_sensor_visibility_exclusion" "test" {
  value   = %q
  %s
  %s
  %s
}
`, hostGroupResources, config.Value, config.formatApplyToDescendantProcesses(), applyGloballyBlock, hostGroupsBlock)
}

func (config exclusionConfig) formatApplyToDescendantProcesses() string {
	if config.ApplyToDescendantProcesses == nil {
		return ""
	}

	return fmt.Sprintf("apply_to_descendant_processes = %t", *config.ApplyToDescendantProcesses)
}

func (config exclusionConfig) resourceName() string {
	return "crowdstrike_sensor_visibility_exclusion.test"
}

// TestChecks generates all appropriate test checks based on the exclusion configuration.
func (config exclusionConfig) TestChecks() resource.TestCheckFunc {
	var checks []resource.TestCheckFunc

	checks = append(checks,
		resource.TestCheckResourceAttr("crowdstrike_sensor_visibility_exclusion.test", "value", config.Value),
		resource.TestCheckResourceAttrSet("crowdstrike_sensor_visibility_exclusion.test", "id"),
		resource.TestCheckResourceAttrSet("crowdstrike_sensor_visibility_exclusion.test", "last_updated"),
		resource.TestCheckResourceAttrSet("crowdstrike_sensor_visibility_exclusion.test", "regexp_value"),
		resource.TestCheckResourceAttrSet("crowdstrike_sensor_visibility_exclusion.test", "value_hash"),
		resource.TestCheckResourceAttrSet("crowdstrike_sensor_visibility_exclusion.test", "created_by"),
		resource.TestCheckResourceAttrSet("crowdstrike_sensor_visibility_exclusion.test", "created_on"),
		resource.TestCheckResourceAttrSet("crowdstrike_sensor_visibility_exclusion.test", "modified_by"),
		resource.TestCheckResourceAttrSet("crowdstrike_sensor_visibility_exclusion.test", "last_modified"),
	)

	if config.ApplyToDescendantProcesses != nil {
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_visibility_exclusion.test", "apply_to_descendant_processes", fmt.Sprintf("%t", *config.ApplyToDescendantProcesses)))
	} else {
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_visibility_exclusion.test", "apply_to_descendant_processes", "false"))
	}

	// Check apply_globally and host_groups based on configuration
	if config.ApplyGlobally != nil && *config.ApplyGlobally {
		// Global exclusion - apply_globally should be true, host_groups should be null
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_visibility_exclusion.test", "apply_globally", "true"))
		checks = append(checks, resource.TestCheckNoResourceAttr("crowdstrike_sensor_visibility_exclusion.test", "host_groups"))
	} else if config.HostGroupCount > 0 {
		// Targeted exclusion - apply_globally should be false, host_groups should contain specific groups
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_visibility_exclusion.test", "apply_globally", "false"))
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_visibility_exclusion.test", "host_groups.#", fmt.Sprintf("%d", config.HostGroupCount)))
	} else {
		// Default case - should be global (apply_globally = true)
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_visibility_exclusion.test", "apply_globally", "true"))
		checks = append(checks, resource.TestCheckNoResourceAttr("crowdstrike_sensor_visibility_exclusion.test", "host_groups"))
	}

	return resource.ComposeAggregateTestCheckFunc(checks...)
}

func TestAccSensorVisibilityExclusionResource_Basic(t *testing.T) {
	testCases := []struct {
		name   string
		config exclusionConfig
	}{
		{
			name: "basic_exclusion",
			config: exclusionConfig{
				Value:         "/tmp/test-basic/*",
				ApplyGlobally: utils.Addr(true),
			},
		},
		{
			name: "updated_exclusion",
			config: exclusionConfig{
				Value:         "/tmp/test-updated/*",
				ApplyGlobally: utils.Addr(true),
			},
		},
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			steps = append(steps, resource.TestStep{
				ResourceName:      testCases[0].config.resourceName(),
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

func TestAccSensorVisibilityExclusionResource_DescendantProcesses(t *testing.T) {
	testCases := []struct {
		name   string
		config exclusionConfig
	}{
		{
			name: "descendant_processes_false",
			config: exclusionConfig{
				Value:                      "/opt/app1/bin/*",
				ApplyToDescendantProcesses: utils.Addr(false),
				ApplyGlobally:              utils.Addr(true),
			},
		},
		{
			name: "descendant_processes_true",
			config: exclusionConfig{
				Value:                      "/opt/app2/bin/*",
				ApplyToDescendantProcesses: utils.Addr(true),
				ApplyGlobally:              utils.Addr(true),
			},
		},
		{
			name: "descendant_processes_default",
			config: exclusionConfig{
				Value:         "/opt/app3/bin/*",
				ApplyGlobally: utils.Addr(true),
			},
		},
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			return steps
		}(),
	})
}

func TestAccSensorVisibilityExclusionResource_HostGroups(t *testing.T) {
	testCases := []struct {
		name   string
		config exclusionConfig
	}{
		{
			name: "single_host_group",
			config: exclusionConfig{
				Value:          "/tmp/test-hg-single/*",
				HostGroupCount: 1,
			},
		},
		{
			name: "multiple_host_groups",
			config: exclusionConfig{
				Value:          "/tmp/test-hg-multiple/*",
				HostGroupCount: 2,
			},
		},
		// this will delete the sve
		// {
		// 	name: "global_exclusion",
		// 	config: exclusionConfig{
		// 		Value:         "/tmp/test-hg-global/*",
		// 		ApplyGlobally: utils.Addr(true),
		// 	},
		// },
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			return steps
		}(),
	})
}

func TestAccSensorVisibilityExclusionResource_ComplexConfigurations(t *testing.T) {
	testCases := []struct {
		name   string
		config exclusionConfig
	}{
		{
			name: "complex_with_host_groups_and_descendants",
			config: exclusionConfig{
				Value:                      "/opt/complex-app/bin/*",
				ApplyToDescendantProcesses: utils.Addr(true),
				HostGroupCount:             2,
			},
		},
		// deleting a hg deletes the attached sve
		// {
		// 	name: "windows_path_exclusion",
		// 	config: exclusionConfig{
		// 		Value:         "C:\\Program Files\\MyApp\\*",
		// 		ApplyGlobally: utils.Addr(true),
		// 	},
		// },
		// {
		// 	name: "wildcard_patterns",
		// 	config: exclusionConfig{
		// 		Value:         "/var/log/*.log",
		// 		ApplyGlobally: utils.Addr(true),
		// 	},
		// },
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			return steps
		}(),
	})
}

func TestAccSensorVisibilityExclusionResource_FieldBoundaries(t *testing.T) {
	testCases := []struct {
		name   string
		config exclusionConfig
	}{
		{
			name: "special_characters_in_path",
			config: exclusionConfig{
				Value:         "/tmp/special-chars_123/app-name.test/*",
				ApplyGlobally: utils.Addr(true),
			},
		},
		{
			name: "very_long_path",
			config: exclusionConfig{
				Value:         "/very/long/path/that/goes/deep/into/the/filesystem/structure/with/many/levels/and/contains/a/very/long/directory/name/that/simulates/real/world/usage/scenarios/where/paths/can/be/quite/lengthy/and/complex/application/directory/*",
				ApplyGlobally: utils.Addr(true),
			},
		},
		{
			name: "path_with_spaces_and_unicode",
			config: exclusionConfig{
				Value:         "/Applications/My App with Spaces/Contents/MacOS/测试应用程序/*",
				ApplyGlobally: utils.Addr(true),
			},
		},
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			return steps
		}(),
	})
}

func TestAccSensorVisibilityExclusionResource_Validation(t *testing.T) {
	validationTests := []struct {
		name        string
		config      string
		expectError *regexp.Regexp
	}{
		{
			name: "empty_value",
			config: `
resource "crowdstrike_sensor_visibility_exclusion" "test" {
  value         = ""
  apply_globally = true
}`,
			expectError: regexp.MustCompile("Attribute value string length must be at least 1"),
		},
		{
			name: "invalid_host_group_format",
			config: `
resource "crowdstrike_sensor_visibility_exclusion" "test" {
  value       = "/tmp/test/*"
  host_groups = [""]
}`,
			expectError: regexp.MustCompile("string length must be at least 1"),
		},
		{
			name: "mixed_valid_invalid_host_groups",
			config: `
resource "crowdstrike_sensor_visibility_exclusion" "test" {
  value       = "/tmp/test/*"
  host_groups = ["valid-group-id", ""]
}`,
			expectError: regexp.MustCompile("string length must be at least 1"),
		},
		{
			name: "both_apply_globally_and_host_groups",
			config: `
resource "crowdstrike_sensor_visibility_exclusion" "test" {
  value          = "/tmp/test/*"
  apply_globally = true
  host_groups    = ["group-id-123"]
}`,
			expectError: regexp.MustCompile("Cannot specify both apply_globally=true and host_groups"),
		},
		{
			name: "neither_apply_globally_nor_host_groups",
			config: `
resource "crowdstrike_sensor_visibility_exclusion" "test" {
  value   = "/tmp/test/*"
}`,
			expectError: regexp.MustCompile("Must specify either apply_globally=true or provide host_groups"),
		},
	}

	for _, tc := range validationTests {
		t.Run(tc.name, func(t *testing.T) {
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

func TestAccSensorVisibilityExclusionResource_HostGroupTransitions(t *testing.T) {
	testCases := []struct {
		name   string
		config exclusionConfig
	}{
		{
			name: "global_to_specific_host_groups",
			config: exclusionConfig{
				Value:         "/tmp/test-transition-1/*",
				ApplyGlobally: utils.Addr(true), // Start global
			},
		},
		{
			name: "specific_to_global_host_groups",
			config: exclusionConfig{
				Value:          "/tmp/test-transition-1/*",
				HostGroupCount: 1, // Change to specific
			},
		},
		// doing this results in the hg being deleted which deletes the sve
		// {
		// 	name: "back_to_global",
		// 	config: exclusionConfig{
		// 		Value:         "/tmp/test-transition-1/*",
		// 		ApplyGlobally: utils.Addr(true), // Back to global
		// 	},
		// },
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			return steps
		}(),
	})
}

func TestAccSensorVisibilityExclusionResource_AllPermutations(t *testing.T) {
	// Test matrix of all permutations
	testCases := []struct {
		name   string
		config exclusionConfig
	}{
		// All combinations of descendant_processes + host_groups/apply_globally
		{
			name: "descendant_false_global",
			config: exclusionConfig{
				Value:                      "/opt/matrix-test-1/*",
				ApplyToDescendantProcesses: utils.Addr(false),
				ApplyGlobally:              utils.Addr(true),
			},
		},
		{
			name: "descendant_false_single_group",
			config: exclusionConfig{
				Value:                      "/opt/matrix-test-2/*",
				ApplyToDescendantProcesses: utils.Addr(false),
				HostGroupCount:             1,
			},
		},
		{
			name: "descendant_false_multiple_groups",
			config: exclusionConfig{
				Value:                      "/opt/matrix-test-3/*",
				ApplyToDescendantProcesses: utils.Addr(false),
				HostGroupCount:             2,
			},
		},
		// this will delete the sve
		// {
		// 	name: "descendant_true_global",
		// 	config: exclusionConfig{
		// 		Value:                      "/opt/matrix-test-4/*",
		// 		ApplyToDescendantProcesses: utils.Addr(true),
		// 		ApplyGlobally:              utils.Addr(true),
		// 	},
		// },
		{
			name: "descendant_true_single_group",
			config: exclusionConfig{
				Value:                      "/opt/matrix-test-5/*",
				ApplyToDescendantProcesses: utils.Addr(true),
				HostGroupCount:             1,
			},
		},
		{
			name: "descendant_true_multiple_groups",
			config: exclusionConfig{
				Value:                      "/opt/matrix-test-6/*",
				ApplyToDescendantProcesses: utils.Addr(true),
				HostGroupCount:             2,
			},
		},
		// {
		// 	name: "descendant_default_global",
		// 	config: exclusionConfig{
		// 		Value:         "/opt/matrix-test-7/*",
		// 		ApplyGlobally: utils.Addr(true),
		// 	},
		// },
		{
			name: "descendant_default_single_group",
			config: exclusionConfig{
				Value:          "/opt/matrix-test-8/*",
				HostGroupCount: 1,
			},
		},
		{
			name: "descendant_default_multiple_groups",
			config: exclusionConfig{
				Value:          "/opt/matrix-test-9/*",
				HostGroupCount: 2,
			},
		},
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			return steps
		}(),
	})
}
