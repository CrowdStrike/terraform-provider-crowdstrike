package cloudsecurity_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

type kacPolicyConfig struct {
	name        string
	description *string
	isEnabled   *bool
	precedence  *int32
	hostGroups  []string
	ruleGroups  []ruleGroupConfig
}

type ruleGroupConfig struct {
	name                 string
	description          *string
	denyOnError          *bool
	imageAssessment      *imageAssessmentConfig
	namespaces           []string
	labels               []labelConfig
	defaultRuleOverrides []defaultRuleOverrideConfig
}

type imageAssessmentConfig struct {
	enabled            bool
	unassessedHandling string
}

type labelConfig struct {
	key      string
	value    string
	operator string
}

type defaultRuleOverrideConfig struct {
	code   string
	action string
}

func (c kacPolicyConfig) String() string {
	config := fmt.Sprintf(`
resource "crowdstrike_cloud_security_kac_policy" "test" {
  name = %q`, c.name)

	if c.description != nil {
		config += fmt.Sprintf(`
  description = %q`, *c.description)
	}

	if c.isEnabled != nil {
		config += fmt.Sprintf(`
  is_enabled = %t`, *c.isEnabled)
	}

	if c.precedence != nil {
		config += fmt.Sprintf(`
  precedence = %d`, *c.precedence)
	}

	if len(c.hostGroups) > 0 {
		config += `
  host_groups = [`
		for i, hg := range c.hostGroups {
			if i > 0 {
				config += `, `
			}
			config += fmt.Sprintf(`%q`, hg)
		}
		config += `]`
	}

	if len(c.ruleGroups) > 0 {
		config += `
  rule_groups = [`
		for i, rg := range c.ruleGroups {
			if i > 0 {
				config += `,`
			}
			config += fmt.Sprintf(`
    {
      name = %q`, rg.name)

			if rg.description != nil {
				config += fmt.Sprintf(`
      description = %q`, *rg.description)
			}

			if rg.denyOnError != nil {
				config += fmt.Sprintf(`
      deny_on_error = %t`, *rg.denyOnError)
			}

			if rg.imageAssessment != nil {
				config += fmt.Sprintf(`
      image_assessment = {
        enabled = %t
        unassessed_handling = %q
      }`, rg.imageAssessment.enabled, rg.imageAssessment.unassessedHandling)
			}

			if len(rg.namespaces) > 0 {
				config += `
      namespaces = [`
				for j, ns := range rg.namespaces {
					if j > 0 {
						config += `, `
					}
					config += fmt.Sprintf(`%q`, ns)
				}
				config += `]`
			}

			if len(rg.labels) > 0 {
				config += `
      labels = [`
				for j, label := range rg.labels {
					if j > 0 {
						config += `,`
					}
					config += fmt.Sprintf(`
        {
          key = %q
          value = %q
          operator = %q
        }`, label.key, label.value, label.operator)
				}
				config += `
      ]`
			}

			if len(rg.defaultRuleOverrides) > 0 {
				config += `
      default_rule_overrides = [`
				for j, override := range rg.defaultRuleOverrides {
					if j > 0 {
						config += `,`
					}
					config += fmt.Sprintf(`
        {
          code = %q
          action = %q
        }`, override.code, override.action)
				}
				config += `
      ]`
			}

			config += `
    }`
		}
		config += `
  ]`
	}

	config += `
}
`
	return config
}

func boolPtr(b bool) *bool       { return &b }
func stringPtr(s string) *string { return &s }
func int32Ptr(i int32) *int32    { return &i }

// TestCloudSecurityKacPolicyResource_Minimal tests creating a KAC policy with minimal configuration.
func TestCloudSecurityKacPolicyResource_Minimal(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := fmt.Sprintf("tfacc-kac-policy-minimal-%s", randomSuffix)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: kacPolicyConfig{name: policyName}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckNoResourceAttr(resourceName, "description"),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"), // should default to false
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

// TestCloudSecurityKacPolicyResource_Basic tests basic CRUD operations for KAC policy resource.
func TestCloudSecurityKacPolicyResource_Basic(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := fmt.Sprintf("tfacc-kac-policy-%s", randomSuffix)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: kacPolicyConfig{
					name:        policyName,
					description: stringPtr("Test KAC policy created by Terraform"),
					isEnabled:   boolPtr(false),
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test KAC policy created by Terraform"),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "id",
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					rs, ok := s.RootModule().Resources[resourceName]
					if !ok {
						return "", fmt.Errorf("Resource not found: %s", resourceName)
					}
					return rs.Primary.Attributes["id"], nil
				},
			},
		},
	})
}

// TestCloudSecurityKacPolicyResource_Update tests updating KAC policy attributes.
func TestCloudSecurityKacPolicyResource_Update(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := fmt.Sprintf("tfacc-kac-policy-%s", randomSuffix)
	updatedPolicyName := fmt.Sprintf("tfacc-kac-policy-updated-%s", randomSuffix)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: kacPolicyConfig{
					name:        policyName,
					description: stringPtr("Test KAC policy created by Terraform"),
					isEnabled:   boolPtr(false),
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test KAC policy created by Terraform"),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				Config: kacPolicyConfig{
					name:        updatedPolicyName,
					description: stringPtr("Updated KAC policy description"),
					isEnabled:   boolPtr(false),
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", updatedPolicyName),
					resource.TestCheckResourceAttr(resourceName, "description", "Updated KAC policy description"),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

// TestCloudSecurityKacPolicyResource_EnabledToggle tests toggling the is_enabled flag.
func TestCloudSecurityKacPolicyResource_EnabledToggle(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := fmt.Sprintf("tfacc-kac-policy-enabled-%s", randomSuffix)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: kacPolicyConfig{
					name:      policyName,
					isEnabled: boolPtr(false),
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				Config: kacPolicyConfig{
					name:      policyName,
					isEnabled: boolPtr(true),
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "true"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				Config: kacPolicyConfig{
					name:      policyName,
					isEnabled: boolPtr(false),
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

// TestCloudSecurityKacPolicyResource_Precedence tests creating and updating KAC policy precedence.
func TestCloudSecurityKacPolicyResource_Precedence(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := fmt.Sprintf("tfacc-kac-policy-precedence-%s", randomSuffix)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: kacPolicyConfig{
					name:        policyName,
					description: stringPtr("Test KAC policy with precedence"),
					isEnabled:   boolPtr(false),
					precedence:  int32Ptr(5),
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test KAC policy with precedence"),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "precedence", "5"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				Config: kacPolicyConfig{
					name:        policyName,
					description: stringPtr("Test KAC policy with updated precedence"),
					isEnabled:   boolPtr(false),
					precedence:  int32Ptr(10),
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test KAC policy with updated precedence"),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "precedence", "10"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

// TestCloudSecurityKacPolicyResource_HostGroups tests creating and updating KAC policy host groups.
func TestCloudSecurityKacPolicyResource_HostGroups(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := fmt.Sprintf("tfacc-kac-policy-hostgroups-%s", randomSuffix)

	// Host group IDs for testing
	// TODO: Replace with host group data source once implemented
	hostGroup1 := "36d2638f17534c11828eff6453c9756b"
	hostGroup2 := "a2b5ab34baee4410817f74430dbb8eaf"
	hostGroup3 := "1aa4e7fdc0c24dfaabbd6a7aa77f0fbd"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: kacPolicyConfig{
					name:        policyName,
					description: stringPtr("Test KAC policy with host groups"),
					isEnabled:   boolPtr(false),
					hostGroups:  []string{hostGroup1, hostGroup2},
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test KAC policy with host groups"),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, "host_groups.*", hostGroup1),
					resource.TestCheckTypeSetElemAttr(resourceName, "host_groups.*", hostGroup2),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				Config: kacPolicyConfig{
					name:        policyName,
					description: stringPtr("Test KAC policy with updated host groups"),
					isEnabled:   boolPtr(false),
					hostGroups:  []string{hostGroup2, hostGroup3}, // Remove hostGroup1, add hostGroup3
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test KAC policy with updated host groups"),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, "host_groups.*", hostGroup2),
					resource.TestCheckTypeSetElemAttr(resourceName, "host_groups.*", hostGroup3),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				Config: kacPolicyConfig{
					name:        policyName,
					description: stringPtr("Test KAC policy with no host groups"),
					isEnabled:   boolPtr(false),
					hostGroups:  []string{}, // Remove all host groups
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test KAC policy with no host groups"),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "0"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

// TestCloudSecurityKacPolicyResource_NameValidation tests name validation.
func TestCloudSecurityKacPolicyResource_NameValidation(t *testing.T) {
	configWithoutName := `resource "crowdstrike_cloud_security_kac_policy" "test" {}`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      configWithoutName,
				ExpectError: regexp.MustCompile("The argument \"name\" is required"),
			},
			{
				Config:      kacPolicyConfig{name: ""}.String(),
				ExpectError: regexp.MustCompile("Attribute name must not be empty"),
			},
		},
	})
}

// TestCloudSecurityKacPolicyResource_SingleRuleGroup tests creating and updating KAC policy rule groups.
func TestCloudSecurityKacPolicyResource_SingleRuleGroup(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := fmt.Sprintf("tfacc-kac-policy-rulegroups-%s", randomSuffix)
	var initialState *terraform.State

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: kacPolicyConfig{
					name:        policyName,
					description: stringPtr("Test KAC policy with rule groups"),
					isEnabled:   boolPtr(false),
					ruleGroups: []ruleGroupConfig{
						{
							name:        "test-rule-group-1",
							description: stringPtr("First test rule group"),
							denyOnError: boolPtr(false),
							imageAssessment: &imageAssessmentConfig{
								enabled:            true,
								unassessedHandling: "Alert",
							},
							namespaces: []string{"test-namespace-1", "test-namespace-2"},
							labels: []labelConfig{
								{
									key:      "environment",
									value:    "test",
									operator: "eq",
								},
							},
							defaultRuleOverrides: []defaultRuleOverrideConfig{
								{
									code:   "TEST_RULE_001",
									action: "Alert",
								},
							},
						},
					},
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test KAC policy with rule groups"),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.name", "test-rule-group-1"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.description", "First test rule group"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.deny_on_error", "false"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.image_assessment.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.image_assessment.unassessed_handling", "Alert"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.namespaces.#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, "rule_groups.0.namespaces.*", "test-namespace-1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "rule_groups.0.namespaces.*", "test-namespace-2"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.labels.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.default_rule_overrides.#", "1"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "rule_groups.0.id"),
					// save initial state for comparing IDs on subsequent updates
					func(s *terraform.State) error {
						initialState = s
						return nil
					},
				),
			},
			{
				Config: kacPolicyConfig{
					name:        policyName,
					description: stringPtr("Test KAC policy with updated rule groups"),
					isEnabled:   boolPtr(false),
					ruleGroups: []ruleGroupConfig{
						{
							name:        "test-rule-group-1-updated",
							description: stringPtr("Updated first test rule group"),
							denyOnError: boolPtr(true),
							imageAssessment: &imageAssessmentConfig{
								enabled:            false,
								unassessedHandling: "Prevent",
							},
							namespaces: []string{"updated-namespace-1"},
							labels: []labelConfig{
								{
									key:      "environment",
									value:    "production",
									operator: "eq",
								},
								{
									key:      "team",
									value:    "security",
									operator: "neq",
								},
							},
							defaultRuleOverrides: []defaultRuleOverrideConfig{
								{
									code:   "TEST_RULE_001",
									action: "Prevent",
								},
								{
									code:   "TEST_RULE_002",
									action: "Alert",
								},
							},
						},
					},
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test KAC policy with updated rule groups"),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.name", "test-rule-group-1-updated"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.description", "Updated first test rule group"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.deny_on_error", "true"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.image_assessment.enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.image_assessment.unassessed_handling", "Prevent"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.namespaces.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "rule_groups.0.namespaces.*", "updated-namespace-1"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.labels.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.default_rule_overrides.#", "2"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					// Verify rule group ID remains the same after update
					testAccCheckNestedObjectIDsUnchanged(resourceName, initialState, []string{"rule_groups.0.id"}),
				),
			},
		},
	})
}

// TestCloudSecurityKacPolicyResource_MultipleRuleGroups tests creating multiple rule groups.
func TestCloudSecurityKacPolicyResource_MultipleRuleGroups(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := fmt.Sprintf("tfacc-kac-policy-multiplerulegroups-%s", randomSuffix)
	var initialState *terraform.State

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: kacPolicyConfig{
					name:        policyName,
					description: stringPtr("Test KAC policy with multiple rule groups"),
					isEnabled:   boolPtr(false),
					ruleGroups: []ruleGroupConfig{
						{
							name:        "production-rule-group",
							description: stringPtr("Production environment rule group"),
							denyOnError: boolPtr(true),
							imageAssessment: &imageAssessmentConfig{
								enabled:            true,
								unassessedHandling: "Prevent",
							},
							namespaces: []string{"production", "prod-*"},
							labels: []labelConfig{
								{
									key:      "environment",
									value:    "production",
									operator: "eq",
								},
							},
						},
						{
							name:        "development-rule-group",
							description: stringPtr("Development environment rule group"),
							denyOnError: boolPtr(false),
							imageAssessment: &imageAssessmentConfig{
								enabled:            false,
								unassessedHandling: "Allow Without Alert",
							},
							namespaces: []string{"development", "dev-*", "staging"},
							labels: []labelConfig{
								{
									key:      "environment",
									value:    "production",
									operator: "neq",
								},
							},
							defaultRuleOverrides: []defaultRuleOverrideConfig{
								{
									code:   "DEV_RULE_001",
									action: "Disabled",
								},
							},
						},
					},
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.#", "2"),
					// First rule group checks
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.name", "production-rule-group"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.description", "Production environment rule group"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.deny_on_error", "true"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.image_assessment.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.image_assessment.unassessed_handling", "Prevent"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.namespaces.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.labels.#", "1"),
					// Second rule group checks
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.name", "development-rule-group"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.description", "Development environment rule group"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.deny_on_error", "false"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.image_assessment.enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.image_assessment.unassessed_handling", "Allow Without Alert"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.namespaces.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.labels.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.default_rule_overrides.#", "1"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "rule_groups.0.id"),
					resource.TestCheckResourceAttrSet(resourceName, "rule_groups.1.id"),
					// save initial state for comparing IDs on subsequent updates
					func(s *terraform.State) error {
						initialState = s
						return nil
					},
				),
			},
			{
				Config: kacPolicyConfig{
					name:        policyName,
					description: stringPtr("Test KAC policy with updated multiple rule groups"),
					isEnabled:   boolPtr(false),
					ruleGroups: []ruleGroupConfig{
						{
							name:        "production-rule-group-updated",
							description: stringPtr("Updated production environment rule group"),
							denyOnError: boolPtr(false), // Changed from true to false
							imageAssessment: &imageAssessmentConfig{
								enabled:            false,   // Changed from true to false
								unassessedHandling: "Alert", // Changed from "Prevent" to "Alert"
							},
							namespaces: []string{"production", "prod-*", "live"}, // Added "live"
							labels: []labelConfig{
								{
									key:      "environment",
									value:    "production",
									operator: "eq",
								},
								{
									key:      "criticality",
									value:    "high",
									operator: "eq",
								},
							},
							defaultRuleOverrides: []defaultRuleOverrideConfig{
								{
									code:   "PROD_RULE_001",
									action: "Alert",
								},
							},
						},
						{
							name:        "development-rule-group-updated",
							description: stringPtr("Updated development environment rule group"),
							denyOnError: boolPtr(true), // Changed from false to true
							imageAssessment: &imageAssessmentConfig{
								enabled:            true,      // Changed from false to true
								unassessedHandling: "Prevent", // Changed from "Allow Without Alert" to "Prevent"
							},
							namespaces: []string{"development", "test"}, // Reduced namespaces
							labels: []labelConfig{
								{
									key:      "environment",
									value:    "development",
									operator: "eq",
								},
							},
							defaultRuleOverrides: []defaultRuleOverrideConfig{
								{
									code:   "DEV_RULE_001",
									action: "Alert", // Changed from "Disabled" to "Alert"
								},
								{
									code:   "DEV_RULE_002",
									action: "Prevent",
								},
							},
						},
					},
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.#", "2"),
					// First rule group updated checks
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.name", "production-rule-group-updated"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.description", "Updated production environment rule group"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.deny_on_error", "false"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.image_assessment.enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.image_assessment.unassessed_handling", "Alert"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.namespaces.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.labels.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.default_rule_overrides.#", "1"),
					// Second rule group updated checks
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.name", "development-rule-group-updated"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.description", "Updated development environment rule group"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.deny_on_error", "true"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.image_assessment.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.image_assessment.unassessed_handling", "Prevent"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.namespaces.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.labels.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.default_rule_overrides.#", "2"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "rule_groups.0.id"),
					resource.TestCheckResourceAttrSet(resourceName, "rule_groups.1.id"),
					// Verify rule group IDs remain the same after update
					testAccCheckNestedObjectIDsUnchanged(resourceName, initialState, []string{"rule_groups.0.id", "rule_groups.1.id"}),
				),
			},
		},
	})
}

// TestCloudSecurityKacPolicyResource_RuleGroupsMinimal tests rule groups with minimal configuration.
func TestCloudSecurityKacPolicyResource_RuleGroupsMinimal(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := fmt.Sprintf("tfacc-kac-policy-minimal-rulegroups-%s", randomSuffix)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: kacPolicyConfig{
					name:        policyName,
					description: stringPtr("Test KAC policy with minimal rule group"),
					isEnabled:   boolPtr(false),
					ruleGroups: []ruleGroupConfig{
						{
							name: "minimal-rule-group",
							// Only required fields, no optional ones
						},
					},
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.name", "minimal-rule-group"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "rule_groups.0.id"),
				),
			},
		},
	})
}

func testAccCheckNestedObjectIDsUnchanged(resourceName string, initialState *terraform.State, idPaths []string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		// Get initial resource
		initialRS, ok := initialState.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found in initial state: %s", resourceName)
		}

		// Get current resource
		currentRS, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found in current state: %s", resourceName)
		}

		// Check each ID path
		for _, idPath := range idPaths {
			initialID := initialRS.Primary.Attributes[idPath]
			currentID := currentRS.Primary.Attributes[idPath]

			if initialID == "" {
				return fmt.Errorf("initial ID not found at path: %s", idPath)
			}

			if currentID != initialID {
				return fmt.Errorf("%s changed: %s -> %s", idPath, initialID, currentID)
			}
		}
		return nil
	}
}
