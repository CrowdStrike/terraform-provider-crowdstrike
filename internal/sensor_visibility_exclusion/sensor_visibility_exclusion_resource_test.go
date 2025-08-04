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
	Comment                    string
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
  comment = %q
  %s
  %s
  %s
}
`, hostGroupResources, config.Value, config.Comment, config.formatApplyToDescendantProcesses(), applyGloballyBlock, hostGroupsBlock)
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
		resource.TestCheckResourceAttr("crowdstrike_sensor_visibility_exclusion.test", "comment", config.Comment),
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
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_visibility_exclusion.test", "applied_globally", "true"))
	} else if config.HostGroupCount > 0 {
		// Targeted exclusion - apply_globally should be false, host_groups should contain specific groups
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_visibility_exclusion.test", "apply_globally", "false"))
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_visibility_exclusion.test", "host_groups.#", fmt.Sprintf("%d", config.HostGroupCount)))
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_visibility_exclusion.test", "applied_globally", "false"))
	} else {
		// Default case - should be global (apply_globally = true)
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_visibility_exclusion.test", "apply_globally", "true"))
		checks = append(checks, resource.TestCheckNoResourceAttr("crowdstrike_sensor_visibility_exclusion.test", "host_groups"))
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_visibility_exclusion.test", "applied_globally", "true"))
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
				Comment:       "Test basic sensor visibility exclusion",
				ApplyGlobally: utils.Addr(true),
			},
		},
		{
			name: "updated_exclusion",
			config: exclusionConfig{
				Value:         "/tmp/test-updated/*",
				Comment:       "Updated test sensor visibility exclusion",
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
				Comment:                    "Test exclusion without descendant processes",
				ApplyToDescendantProcesses: utils.Addr(false),
				ApplyGlobally:              utils.Addr(true),
			},
		},
		{
			name: "descendant_processes_true",
			config: exclusionConfig{
				Value:                      "/opt/app2/bin/*",
				Comment:                    "Test exclusion with descendant processes",
				ApplyToDescendantProcesses: utils.Addr(true),
				ApplyGlobally:              utils.Addr(true),
			},
		},
		{
			name: "descendant_processes_default",
			config: exclusionConfig{
				Value:         "/opt/app3/bin/*",
				Comment:       "Test exclusion with default descendant processes",
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
				Comment:        "Test sensor visibility exclusion with single host group",
				HostGroupCount: 1,
			},
		},
		{
			name: "multiple_host_groups",
			config: exclusionConfig{
				Value:          "/tmp/test-hg-multiple/*",
				Comment:        "Test sensor visibility exclusion with multiple host groups",
				HostGroupCount: 2,
			},
		},
		{
			name: "global_exclusion",
			config: exclusionConfig{
				Value:         "/tmp/test-hg-global/*",
				Comment:       "Test global sensor visibility exclusion",
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

func TestAccSensorVisibilityExclusionResource_ComplexConfigurations(t *testing.T) {
	testCases := []struct {
		name   string
		config exclusionConfig
	}{
		{
			name: "complex_with_host_groups_and_descendants",
			config: exclusionConfig{
				Value:                      "/opt/complex-app/bin/*",
				Comment:                    "Complex exclusion with host groups and descendant processes",
				ApplyToDescendantProcesses: utils.Addr(true),
				HostGroupCount:             2,
			},
		},
		{
			name: "windows_path_exclusion",
			config: exclusionConfig{
				Value:         "C:\\Program Files\\MyApp\\*",
				Comment:       "Windows path exclusion test",
				ApplyGlobally: utils.Addr(true),
			},
		},
		{
			name: "wildcard_patterns",
			config: exclusionConfig{
				Value:         "/var/log/*.log",
				Comment:       "Wildcard pattern exclusion test",
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

func TestAccSensorVisibilityExclusionResource_FieldBoundaries(t *testing.T) {
	testCases := []struct {
		name   string
		config exclusionConfig
	}{
		{
			name: "minimum_comment",
			config: exclusionConfig{
				Value:         "/tmp/min-comment/*",
				Comment:       "1",
				ApplyGlobally: utils.Addr(true),
			},
		},
		{
			name: "long_comment",
			config: exclusionConfig{
				Value:         "/tmp/long-comment/*",
				Comment:       "This is a very long comment that tests the boundary limits of the comment field. It contains multiple sentences and should be quite lengthy to test how the system handles long comments. This comment is intentionally verbose to ensure comprehensive testing of the field boundaries and validation logic. It includes various punctuation marks, numbers like 123 and 456, and special characters to ensure comprehensive testing.",
				ApplyGlobally: utils.Addr(true),
			},
		},
		{
			name: "special_characters_in_path",
			config: exclusionConfig{
				Value:         "/tmp/special-chars_123/app-name.test/*",
				Comment:       "Test path with special characters and numbers",
				ApplyGlobally: utils.Addr(true),
			},
		},
		{
			name: "very_long_path",
			config: exclusionConfig{
				Value:         "/very/long/path/that/goes/deep/into/the/filesystem/structure/with/many/levels/and/contains/a/very/long/directory/name/that/simulates/real/world/usage/scenarios/where/paths/can/be/quite/lengthy/and/complex/application/directory/*",
				Comment:       "Test with a very long path to ensure system handles it properly",
				ApplyGlobally: utils.Addr(true),
			},
		},
		{
			name: "path_with_spaces_and_unicode",
			config: exclusionConfig{
				Value:         "/Applications/My App with Spaces/Contents/MacOS/测试应用程序/*",
				Comment:       "Test path with spaces and Unicode characters",
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
  comment       = "Empty value test"
  apply_globally = true
}`,
			expectError: regexp.MustCompile("Attribute value string length must be at least 1"),
		},
		{
			name: "invalid_host_group_format",
			config: `
resource "crowdstrike_sensor_visibility_exclusion" "test" {
  value       = "/tmp/test/*"
  comment     = "Invalid host group test"
  host_groups = [""]
}`,
			expectError: regexp.MustCompile("string length must be at least 1"),
		},
		{
			name: "mixed_valid_invalid_host_groups",
			config: `
resource "crowdstrike_sensor_visibility_exclusion" "test" {
  value       = "/tmp/test/*"
  comment     = "Mixed host group test"
  host_groups = ["valid-group-id", ""]
}`,
			expectError: regexp.MustCompile("string length must be at least 1"),
		},
		{
			name: "both_apply_globally_and_host_groups",
			config: `
resource "crowdstrike_sensor_visibility_exclusion" "test" {
  value          = "/tmp/test/*"
  comment        = "Both apply_globally and host_groups"
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
  comment = "Neither apply_globally nor host_groups"
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
				Comment:       "Test transition from global to specific host groups",
				ApplyGlobally: utils.Addr(true), // Start global
			},
		},
		{
			name: "specific_to_global_host_groups",
			config: exclusionConfig{
				Value:          "/tmp/test-transition-1/*",
				Comment:        "Test transition from global to specific host groups",
				HostGroupCount: 1, // Change to specific
			},
		},
		{
			name: "back_to_global",
			config: exclusionConfig{
				Value:         "/tmp/test-transition-1/*",
				Comment:       "Test transition back to global",
				ApplyGlobally: utils.Addr(true), // Back to global
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
				Comment:                    "descendant_false + global",
				ApplyToDescendantProcesses: utils.Addr(false),
				ApplyGlobally:              utils.Addr(true),
			},
		},
		{
			name: "descendant_false_single_group",
			config: exclusionConfig{
				Value:                      "/opt/matrix-test-2/*",
				Comment:                    "descendant_false + single_group",
				ApplyToDescendantProcesses: utils.Addr(false),
				HostGroupCount:             1,
			},
		},
		{
			name: "descendant_false_multiple_groups",
			config: exclusionConfig{
				Value:                      "/opt/matrix-test-3/*",
				Comment:                    "descendant_false + multiple_groups",
				ApplyToDescendantProcesses: utils.Addr(false),
				HostGroupCount:             2,
			},
		},
		{
			name: "descendant_true_global",
			config: exclusionConfig{
				Value:                      "/opt/matrix-test-4/*",
				Comment:                    "descendant_true + global",
				ApplyToDescendantProcesses: utils.Addr(true),
				ApplyGlobally:              utils.Addr(true),
			},
		},
		{
			name: "descendant_true_single_group",
			config: exclusionConfig{
				Value:                      "/opt/matrix-test-5/*",
				Comment:                    "descendant_true + single_group",
				ApplyToDescendantProcesses: utils.Addr(true),
				HostGroupCount:             1,
			},
		},
		{
			name: "descendant_true_multiple_groups",
			config: exclusionConfig{
				Value:                      "/opt/matrix-test-6/*",
				Comment:                    "descendant_true + multiple_groups",
				ApplyToDescendantProcesses: utils.Addr(true),
				HostGroupCount:             2,
			},
		},
		{
			name: "descendant_default_global",
			config: exclusionConfig{
				Value:         "/opt/matrix-test-7/*",
				Comment:       "descendant_default + global",
				ApplyGlobally: utils.Addr(true),
			},
		},
		{
			name: "descendant_default_single_group",
			config: exclusionConfig{
				Value:          "/opt/matrix-test-8/*",
				Comment:        "descendant_default + single_group",
				HostGroupCount: 1,
			},
		},
		{
			name: "descendant_default_multiple_groups",
			config: exclusionConfig{
				Value:          "/opt/matrix-test-9/*",
				Comment:        "descendant_default + multiple_groups",
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
