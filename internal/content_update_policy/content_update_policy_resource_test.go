package contentupdatepolicy_test

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

// ringConfig represents a ring assignment configuration.
type ringConfig struct {
	RingAssignment       string
	DelayHours           *int
	PinnedContentVersion *string
}

// policyConfig represents a complete policy configuration.
type policyConfig struct {
	Name                    string
	Description             string
	Enabled                 *bool
	SensorOperations        ringConfig
	SystemCritical          ringConfig
	VulnerabilityManagement ringConfig
	RapidResponse           ringConfig
	HostGroupCount          int
}

// String implements the Stringer interface and generates Terraform configuration from policyConfig.
func (config *policyConfig) String() string {
	var hostGroupResources string
	var hostGroupsBlock string

	randomSuffix := sdkacctest.RandString(8)
	config.Name = fmt.Sprintf("%s-%s", config.Name, randomSuffix)

	if config.HostGroupCount > 0 {
		var hostGroupRefs []string
		for i := 0; i < config.HostGroupCount; i++ {
			hostGroupName := fmt.Sprintf("hg-%s-%d", randomSuffix, i)

			hostGroupResources += fmt.Sprintf(`
resource "crowdstrike_host_group" "hg_%d" {
  name        = "%s"
  description = "Test host group %d for content update policy"
  type        = "static"
  hostnames   = ["test-host%d-1", "test-host%d-2"]
}
`, i, hostGroupName, i, i, i)
			hostGroupRefs = append(hostGroupRefs, fmt.Sprintf("crowdstrike_host_group.hg_%d.id", i))
		}

		hostGroupsBlock = fmt.Sprintf(`
  host_groups = [%s]`, strings.Join(hostGroupRefs, ", "))
	}

	return fmt.Sprintf(`%s
data "crowdstrike_content_category_versions" "test" {}

resource "crowdstrike_content_update_policy" "test" {
  name        = %q
  description = %q
  %s

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
  
  %s
}
`, hostGroupResources, config.Name, config.Description, config.formatEnabled(),
		config.SensorOperations.RingAssignment, config.SensorOperations.formatDelayHours(), config.SensorOperations.formatPinnedVersion(),
		config.SystemCritical.RingAssignment, config.SystemCritical.formatDelayHours(), config.SystemCritical.formatPinnedVersion(),
		config.VulnerabilityManagement.RingAssignment, config.VulnerabilityManagement.formatDelayHours(), config.VulnerabilityManagement.formatPinnedVersion(),
		config.RapidResponse.RingAssignment, config.RapidResponse.formatDelayHours(), config.RapidResponse.formatPinnedVersion(),
		hostGroupsBlock)
}

func (config policyConfig) formatEnabled() string {
	if config.Enabled == nil {
		return ""
	}

	return fmt.Sprintf("enabled = %t", *config.Enabled)
}

func (config ringConfig) formatDelayHours() string {
	if config.DelayHours == nil {
		return ""
	}
	return fmt.Sprintf("delay_hours     = %d", *config.DelayHours)
}

func (config ringConfig) formatPinnedVersion() string {
	if config.PinnedContentVersion == nil {
		return ""
	}
	return fmt.Sprintf("pinned_content_version = %s", *config.PinnedContentVersion)
}

func (config policyConfig) resourceName() string {
	return "crowdstrike_content_update_policy.test"
}

// TestChecks generates all appropriate test checks based on the policy configuration.
func (config policyConfig) TestChecks() resource.TestCheckFunc {
	var checks []resource.TestCheckFunc

	checks = append(checks,
		resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "name", config.Name),
		resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "description", config.Description),
		resource.TestCheckResourceAttrSet("crowdstrike_content_update_policy.test", "id"),
		resource.TestCheckResourceAttrSet("crowdstrike_content_update_policy.test", "last_updated"),
	)

	if config.Enabled != nil {
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "enabled", fmt.Sprintf("%t", *config.Enabled)))
	} else {
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "enabled", "true"))
	}

	checks = append(checks, config.SensorOperations.generateChecks("sensor_operations")...)
	checks = append(checks, config.SystemCritical.generateChecks("system_critical")...)
	checks = append(checks, config.VulnerabilityManagement.generateChecks("vulnerability_management")...)
	checks = append(checks, config.RapidResponse.generateChecks("rapid_response")...)

	checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "host_groups.#", fmt.Sprintf("%d", config.HostGroupCount)))

	return resource.ComposeAggregateTestCheckFunc(checks...)
}

// generateChecks creates appropriate test checks for a ring configuration.
func (ring ringConfig) generateChecks(category string) []resource.TestCheckFunc {
	var checks []resource.TestCheckFunc

	checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", category+".ring_assignment", ring.RingAssignment))

	if ring.RingAssignment != "ga" {
		checks = append(checks, resource.TestCheckNoResourceAttr("crowdstrike_content_update_policy.test", category+".delay_hours"))
	} else {
		if ring.DelayHours != nil {
			checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", category+".delay_hours", fmt.Sprintf("%d", *ring.DelayHours)))
		} else {
			checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", category+".delay_hours", "0"))
		}
	}

	if ring.PinnedContentVersion != nil {
		checks = append(checks, resource.TestCheckResourceAttrSet("crowdstrike_content_update_policy.test", category+".pinned_content_version"))
	} else {
		checks = append(checks, resource.TestCheckNoResourceAttr("crowdstrike_content_update_policy.test", category+".pinned_content_version"))
	}

	return checks
}

func TestAccContentUpdatePolicyResource_Basic(t *testing.T) {
	testCases := []struct {
		name   string
		config policyConfig
	}{
		{
			name: "basic_policy",
			config: policyConfig{
				Name:        "test-policy-basic",
				Description: "Test content update policy",
				Enabled:     utils.Addr(true),
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
			name: "updated_policy",
			config: policyConfig{
				Name:        "test-policy-updated",
				Description: "Updated test content update policy",
				Enabled:     utils.Addr(false),
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
				steps = append(steps, resource.TestStep{
					ResourceName:      tc.config.resourceName(),
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

func TestAccContentUpdatePolicyResource_Import(t *testing.T) {
	config := policyConfig{
		Name:        "test-policy-import",
		Description: "Test content update policy for import",
		Enabled:     utils.Addr(true),
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
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config.String(),
				Check:  config.TestChecks(),
			},
			{
				ResourceName:      config.resourceName(),
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"last_updated",
				},
			},
		},
	})
}

func TestAccContentUpdatePolicyResource_HostGroups(t *testing.T) {

	testCases := []struct {
		name   string
		config policyConfig
	}{
		{
			name: "single_host_group",
			config: policyConfig{
				Name:           "test-policy-hg",
				Description:    "Test content update policy with host groups",
				Enabled:        utils.Addr(true),
				HostGroupCount: 1,
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
			name: "multiple_host_groups",
			config: policyConfig{
				Name:           "test-policy-hg-updated",
				Description:    "Test content update policy with host groups",
				Enabled:        utils.Addr(true),
				HostGroupCount: 2,
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
			name: "empty_host_groups",
			config: policyConfig{
				Name:           "test-policy-empty-hg",
				Description:    "Test content update policy with empty host groups",
				Enabled:        utils.Addr(true),
				HostGroupCount: 0,
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

func TestAccContentUpdatePolicyResource_PinnedContentVersion(t *testing.T) {
	testCases := []struct {
		name   string
		config policyConfig
	}{
		{
			name: "single_category_pinned",
			config: policyConfig{
				Name:        "test-policy-pinned-single",
				Description: "Test content update policy with single pinned category",
				Enabled:     utils.Addr(true),
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
					RingAssignment: "ea",
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
		},
		{
			name: "all_categories_pinned",
			config: policyConfig{
				Name:        "test-policy-pinned-all",
				Description: "Test content update policy with all categories pinned",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment:       "ga",
					DelayHours:           utils.Addr(24),
					PinnedContentVersion: utils.Addr("data.crowdstrike_content_category_versions.test.sensor_operations[0]"),
				},
				SystemCritical: ringConfig{
					RingAssignment:       "ga",
					DelayHours:           utils.Addr(0),
					PinnedContentVersion: utils.Addr("data.crowdstrike_content_category_versions.test.system_critical[0]"),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment:       "ea",
					PinnedContentVersion: utils.Addr("data.crowdstrike_content_category_versions.test.vulnerability_management[0]"),
				},
				RapidResponse: ringConfig{
					RingAssignment:       "pause",
					PinnedContentVersion: utils.Addr("data.crowdstrike_content_category_versions.test.rapid_response[0]"),
				},
			},
		},
		{
			name: "mixed_pinned_unpinned",
			config: policyConfig{
				Name:        "test-policy-pinned-mixed",
				Description: "Test content update policy with mixed pinned and unpinned categories",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment:       "ga",
					DelayHours:           utils.Addr(24),
					PinnedContentVersion: utils.Addr("data.crowdstrike_content_category_versions.test.sensor_operations[0]"),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ea",
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
				steps = append(steps, resource.TestStep{
					ResourceName:      tc.config.resourceName(),
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

func TestAccContentUpdatePolicyResource_PinnedContentVersionUpdates(t *testing.T) {
	testCases := []struct {
		name   string
		config policyConfig
	}{
		{
			name: "add_pinned_version",
			config: policyConfig{
				Name:        "test-policy-add-pinned",
				Description: "Test adding pinned version to existing policy",
				Enabled:     utils.Addr(true),
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
			config: policyConfig{
				Name:        "test-policy-add-pinned",
				Description: "Test adding pinned version to existing policy",
				Enabled:     utils.Addr(true),
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
			config: policyConfig{
				Name:        "test-policy-add-pinned",
				Description: "Test updating pinned version values",
				Enabled:     utils.Addr(true),
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
			config: policyConfig{
				Name:        "test-policy-add-pinned",
				Description: "Test removing pinned version",
				Enabled:     utils.Addr(true),
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

func TestAccContentUpdatePolicyResource_PinnedContentVersionValidationErrors(t *testing.T) {
	// Test ring assignment change errors with pinned versions
	validationTests := []struct {
		name          string
		initialConfig policyConfig
		updateConfig  policyConfig
		expectError   *regexp.Regexp
	}{
		{
			name: "sensor_operations_ring_assignment_change_blocked",
			initialConfig: policyConfig{
				Name:        "test-policy-ring-change-sensor",
				Description: "Test ring assignment change with pinned version",
				Enabled:     utils.Addr(true),
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
			updateConfig: policyConfig{
				Name:        "test-policy-ring-change-sensor",
				Description: "Test ring assignment change with pinned version",
				Enabled:     utils.Addr(true),
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
			initialConfig: policyConfig{
				Name:        "test-policy-ring-change-system",
				Description: "Test ring assignment change with pinned version",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				SystemCritical: ringConfig{
					RingAssignment:       "ga",
					DelayHours:           utils.Addr(0),
					PinnedContentVersion: utils.Addr("data.crowdstrike_content_category_versions.test.system_critical[0]"),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ea",
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
			updateConfig: policyConfig{
				Name:        "test-policy-ring-change-system",
				Description: "Test ring assignment change with pinned version",
				Enabled:     utils.Addr(true),
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
			initialConfig: policyConfig{
				Name:        "test-policy-delay-change-sensor",
				Description: "Test delay hours change with pinned version",
				Enabled:     utils.Addr(true),
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
			updateConfig: policyConfig{
				Name:        "test-policy-delay-change-sensor",
				Description: "Test delay hours change with pinned version",
				Enabled:     utils.Addr(true),
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
			initialConfig: policyConfig{
				Name:        "test-policy-delay-change-system",
				Description: "Test delay hours change with pinned version",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				SystemCritical: ringConfig{
					RingAssignment:       "ga",
					DelayHours:           utils.Addr(0),
					PinnedContentVersion: utils.Addr("data.crowdstrike_content_category_versions.test.system_critical[0]"),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ea",
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
			updateConfig: policyConfig{
				Name:        "test-policy-delay-change-system",
				Description: "Test delay hours change with pinned version",
				Enabled:     utils.Addr(true),
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
			resource.ParallelTest(t, resource.TestCase{
				PreCheck:                 func() { acctest.PreCheck(t) },
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config: tc.initialConfig.String(),
						Check:  tc.initialConfig.TestChecks(),
					},
					{
						Config:      tc.updateConfig.String(),
						ExpectError: tc.expectError,
					},
				},
			})
		})
	}
}

func TestAccContentUpdatePolicyResource_PinnedContentVersionValidTransitions(t *testing.T) {
	// Test scenarios where pinned version changes should succeed
	testCases := []struct {
		name   string
		config policyConfig
	}{
		{
			name: "initial_state_with_pinned_version",
			config: policyConfig{
				Name:        "test-policy-valid-transition",
				Description: "Test valid transition initial state",
				Enabled:     utils.Addr(true),
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
			config: policyConfig{
				Name:        "test-policy-valid-transition",
				Description: "Test valid transition after removing pinned version",
				Enabled:     utils.Addr(true),
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
			config: policyConfig{
				Name:        "test-policy-valid-transition",
				Description: "Updated description while keeping pinned version",
				Enabled:     utils.Addr(false),
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

func TestAccContentUpdatePolicyResource_RingConfigurations(t *testing.T) {

	testCases := []struct {
		name   string
		config policyConfig
	}{
		{
			name: "all_ga_rings",
			config: policyConfig{
				Name:        "test-policy-all-ga",
				Description: "Test content update policy with all GA rings",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
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
		{
			name: "all_ea_rings",
			config: policyConfig{
				Name:        "test-policy-all-ea",
				Description: "Test content update policy with all EA rings",
				Enabled:     utils.Addr(true),
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
		{
			name: "mixed_configuration",
			config: policyConfig{
				Name:        "test-policy-mixed",
				Description: "Test content update policy with mixed ring assignments",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(12),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ea",
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "pause",
				},
				RapidResponse: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(2),
				},
			},
		},
		{
			name: "various_delay_hours",
			config: policyConfig{
				Name:        "test-policy-delay-variations",
				Description: "Test content update policy with various delay hours",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(1),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(4),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(8),
				},
				RapidResponse: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(72),
				},
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

func TestAccContentUpdatePolicyResource_StateTransitions(t *testing.T) {

	testCases := []struct {
		name   string
		config policyConfig
	}{
		{
			name: "disabled_policy",
			config: policyConfig{
				Name:        "test-policy-transitions-disabled",
				Description: "Test disabled content update policy",
				Enabled:     utils.Addr(false),
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
			name: "enabled_policy",
			config: policyConfig{
				Name:        "test-policy-transitions-enabled",
				Description: "Test enabled content update policy",
				Enabled:     utils.Addr(true),
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
			name: "ea_rings_no_delay",
			config: policyConfig{
				Name:        "test-policy-transitions-ea",
				Description: "Test content update policy with null delay hours for EA rings",
				Enabled:     utils.Addr(true),
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
					RingAssignment: "pause",
				},
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

func TestAccContentUpdatePolicyResource_Validation(t *testing.T) {

	validationTests := []struct {
		name        string
		config      policyConfig
		expectError *regexp.Regexp
	}{
		{
			name: "invalid_delay_with_ea_ring",
			config: policyConfig{
				Name:        "test-policy-invalid",
				Description: "Test content update policy with invalid delay configuration",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ea",
					DelayHours:     utils.Addr(24),
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
			name: "system_critical_cannot_use_pause",
			config: policyConfig{
				Name:        "test-policy-invalid-pause",
				Description: "Test content update policy with invalid system_critical pause",
				Enabled:     utils.Addr(true),
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
			config: policyConfig{
				Name:        "test-policy-invalid-delay-high",
				Description: "Test content update policy with invalid high delay hours",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(73),
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
			name: "multiple_validation_errors",
			config: policyConfig{
				Name:        "test-policy-multi-errors",
				Description: "Test content update policy with multiple validation errors",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment: "ea",
					DelayHours:     utils.Addr(24),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
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
	}

	for _, tc := range validationTests {
		t.Run(tc.name, func(t *testing.T) {
			resource.ParallelTest(t, resource.TestCase{
				PreCheck:                 func() { acctest.PreCheck(t) },
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config:      tc.config.String(),
						ExpectError: tc.expectError,
					},
				},
			})
		})
	}
}

func TestAccContentUpdatePolicyResource_FieldBoundaries(t *testing.T) {

	testCases := []struct {
		name   string
		config policyConfig
	}{
		{
			name: "minimum_description",
			config: policyConfig{
				Name:        "test-policy-min-desc",
				Description: "1",
				Enabled:     utils.Addr(true),
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
			name: "long_description",
			config: policyConfig{
				Name:        "test-policy-long-desc",
				Description: "This is a very long description that tests the boundary limits of the description field. It contains multiple sentences and should be quite lengthy to test how the system handles long descriptions. This description is intentionally verbose to ensure we test the maximum field length handling properly. It includes various punctuation marks, numbers like 123 and 456, and special characters to ensure comprehensive testing of the field boundaries and validation logic.",
				Enabled:     utils.Addr(true),
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
			name: "special_characters",
			config: policyConfig{
				Name:        "test-policy-special-chars_123",
				Description: "Test policy with special characters: !@#$%^&*()_+-={}[]|;:,.<>?",
				Enabled:     utils.Addr(true),
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
