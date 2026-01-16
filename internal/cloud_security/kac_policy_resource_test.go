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
	name             string
	description      *string
	isEnabled        *bool
	hostGroups       []string
	ruleGroups       []ruleGroupConfig
	defaultRuleGroup *defaultRuleGroupConfig
}

type ruleGroupConfig struct {
	name            string
	description     *string
	denyOnError     *bool
	imageAssessment *imageAssessmentConfig
	namespaces      []string
	labels          []labelConfig
	defaultRules    *defaultRulesConfig
}

type defaultRuleGroupConfig struct {
	denyOnError     *bool
	imageAssessment *imageAssessmentConfig
	defaultRules    *defaultRulesConfig
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

type defaultRulesConfig struct {
	privilegedContainer            *string
	sensitiveDataInEnvironment     *string
	containerRunAsRoot             *string
	containerWithoutResourceLimits *string
	sensitiveHostDirectories       *string
	workloadInDefaultNamespace     *string
	runtimeSocketInContainer       *string
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

	if len(c.hostGroups) > 0 {
		config += `
  host_groups = [`
		for i, hg := range c.hostGroups {
			if i > 0 {
				config += `, `
			}
			config += hg
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

			if rg.defaultRules != nil {
				config += `
      default_rules = {`
				config += rg.defaultRules.renderRules("      ")
				config += `
      }`
			}

			config += `
    }`
		}
		config += `
  ]`
	}

	// Add default_rule_group configuration
	config += c.defaultRuleGroup.render()

	config += `
}
`
	return config
}

func boolPtr(b bool) *bool       { return &b }
func stringPtr(s string) *string { return &s }

func defaultRulePtr(action string) *string {
	return &action
}

func (dr *defaultRulesConfig) renderRules(indent string) string {
	if dr == nil {
		return ""
	}

	config := ""
	if dr.privilegedContainer != nil {
		config += fmt.Sprintf(`
%s  privileged_container = %q`, indent, *dr.privilegedContainer)
	}
	if dr.sensitiveDataInEnvironment != nil {
		config += fmt.Sprintf(`
%s  sensitive_data_in_environment = %q`, indent, *dr.sensitiveDataInEnvironment)
	}
	if dr.containerRunAsRoot != nil {
		config += fmt.Sprintf(`
%s  container_run_as_root = %q`, indent, *dr.containerRunAsRoot)
	}
	if dr.containerWithoutResourceLimits != nil {
		config += fmt.Sprintf(`
%s  container_without_resource_limits = %q`, indent, *dr.containerWithoutResourceLimits)
	}
	if dr.sensitiveHostDirectories != nil {
		config += fmt.Sprintf(`
%s  sensitive_host_directories = %q`, indent, *dr.sensitiveHostDirectories)
	}
	if dr.workloadInDefaultNamespace != nil {
		config += fmt.Sprintf(`
%s  workload_in_default_namespace = %q`, indent, *dr.workloadInDefaultNamespace)
	}
	if dr.runtimeSocketInContainer != nil {
		config += fmt.Sprintf(`
%s  runtime_socket_in_container = %q`, indent, *dr.runtimeSocketInContainer)
	}
	return config
}

func (drg *defaultRuleGroupConfig) render() string {
	if drg == nil {
		return ""
	}

	config := `
  default_rule_group = {`

	if drg.denyOnError != nil {
		config += fmt.Sprintf(`
    deny_on_error = %t`, *drg.denyOnError)
	}

	if drg.imageAssessment != nil {
		config += fmt.Sprintf(`
    image_assessment = {
      enabled = %t
      unassessed_handling = %q
    }`, drg.imageAssessment.enabled, drg.imageAssessment.unassessedHandling)
	}

	if drg.defaultRules != nil {
		config += `
    default_rules = {`
		config += drg.defaultRules.renderRules("    ")
		config += `
    }`
	}

	config += `
  }`
	return config
}

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

func TestCloudSecurityKacPolicyResource_Basic(t *testing.T) {
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
					isEnabled:   boolPtr(true),
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", updatedPolicyName),
					resource.TestCheckResourceAttr(resourceName, "description", "Updated KAC policy description"),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "true"),
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
		},
	})
}

func TestCloudSecurityKacPolicyResource_HostGroups(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := fmt.Sprintf("tfacc-kac-policy-hostgroups-%s", randomSuffix)

	hostGroupsConfig := `
resource "crowdstrike_host_group" "test-hg-1" {
  name        = "tfacc-kac-policy-hg-1"
  description = "test host group for kac policy tf acceptance tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_host_group" "test-hg-2" {
  name        = "tfacc-kac-policy-hg-2"
  description = "test host group for kac policy tf acceptance tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_host_group" "test-hg-3" {
  name        = "tfacc-kac-policy-hg-3"
  description = "test host group for kac policy tf acceptance tests"
  type        = "staticByID"
  host_ids    = []
}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: acctest.ConfigCompose(
					hostGroupsConfig,
					kacPolicyConfig{
						name:        policyName,
						description: stringPtr("Test KAC policy with host groups"),
						isEnabled:   boolPtr(false),
						hostGroups:  []string{"crowdstrike_host_group.test-hg-1.id", "crowdstrike_host_group.test-hg-2.id"},
					}.String(),
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test KAC policy with host groups"),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "2"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "host_groups.*", "crowdstrike_host_group.test-hg-1", "id"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "host_groups.*", "crowdstrike_host_group.test-hg-2", "id"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				Config: acctest.ConfigCompose(
					hostGroupsConfig,
					kacPolicyConfig{
						name:        policyName,
						description: stringPtr("Test KAC policy with updated host groups"),
						isEnabled:   boolPtr(false),
						hostGroups:  []string{"crowdstrike_host_group.test-hg-2.id", "crowdstrike_host_group.test-hg-3.id"}, // Remove hostGroup1, add hostGroup3
					}.String(),
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test KAC policy with updated host groups"),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "2"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "host_groups.*", "crowdstrike_host_group.test-hg-2", "id"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "host_groups.*", "crowdstrike_host_group.test-hg-3", "id"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				Config: acctest.ConfigCompose(
					hostGroupsConfig,
					kacPolicyConfig{
						name:        policyName,
						description: stringPtr("Test KAC policy with no host groups"),
						isEnabled:   boolPtr(false),
						hostGroups:  []string{}, // Remove all host groups
					}.String(),
				),
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

func TestCloudSecurityKacPolicyResource_DefaultRuleGroup(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := fmt.Sprintf("tfacc-kac-policy-defaultrulegroup-%s", randomSuffix)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: kacPolicyConfig{
					name:        policyName,
					description: stringPtr("Test KAC policy with default rule group"),
					isEnabled:   boolPtr(false),
					defaultRuleGroup: &defaultRuleGroupConfig{
						denyOnError: boolPtr(false),
						imageAssessment: &imageAssessmentConfig{
							enabled:            true,
							unassessedHandling: "Alert",
						},
						defaultRules: &defaultRulesConfig{
							workloadInDefaultNamespace: defaultRulePtr("Prevent"),
							runtimeSocketInContainer:   defaultRulePtr("Alert"),
						},
					},
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test KAC policy with default rule group"),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "default_rule_group.id"),
					resource.TestCheckResourceAttr(resourceName, "default_rule_group.deny_on_error", "false"),
					resource.TestCheckResourceAttr(resourceName, "default_rule_group.image_assessment.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "default_rule_group.image_assessment.unassessed_handling", "Alert"),
					resource.TestCheckResourceAttr(resourceName, "default_rule_group.default_rules.workload_in_default_namespace", "Prevent"),
					resource.TestCheckResourceAttr(resourceName, "default_rule_group.default_rules.runtime_socket_in_container", "Alert"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				Config: kacPolicyConfig{
					name:        policyName,
					description: stringPtr("Test KAC policy with default rule group"),
					isEnabled:   boolPtr(false),
					defaultRuleGroup: &defaultRuleGroupConfig{
						denyOnError: boolPtr(true),
						imageAssessment: &imageAssessmentConfig{
							enabled:            false,
							unassessedHandling: "Allow Without Alert",
						},
						defaultRules: &defaultRulesConfig{
							workloadInDefaultNamespace: defaultRulePtr("Alert"),
							runtimeSocketInContainer:   defaultRulePtr("Disabled"),
						},
					},
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test KAC policy with default rule group"),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "default_rule_group.id"),
					resource.TestCheckResourceAttr(resourceName, "default_rule_group.deny_on_error", "true"),
					resource.TestCheckResourceAttr(resourceName, "default_rule_group.image_assessment.enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "default_rule_group.image_assessment.unassessed_handling", "Allow Without Alert"),
					resource.TestCheckResourceAttr(resourceName, "default_rule_group.default_rules.workload_in_default_namespace", "Alert"),
					resource.TestCheckResourceAttr(resourceName, "default_rule_group.default_rules.runtime_socket_in_container", "Disabled"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

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
					name: policyName,
					ruleGroups: []ruleGroupConfig{
						{
							name: "minimal-rule-group",
							// Only required fields, no optional ones
						},
					},
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.name", "minimal-rule-group"),
					resource.TestCheckResourceAttrSet(resourceName, "rule_groups.0.id"),
					// Check default values are set as expected
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.deny_on_error", "false"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.image_assessment.enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.image_assessment.unassessed_handling", "Allow Without Alert"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.namespaces.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "rule_groups.0.namespaces.*", "*"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.labels.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.labels.0.key", "*"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.labels.0.value", "*"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.labels.0.operator", "eq"),
					// Check the first default rule to make sure the default action is set
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.default_rules.privileged_container", "Alert"),
				),
			},
		},
	})
}

func TestCloudSecurityKacPolicyResource_SingleRuleGroup(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := fmt.Sprintf("tfacc-kac-policy-rulegroups-%s", randomSuffix)
	capturedState := make(map[string]string)

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
							defaultRules: &defaultRulesConfig{
								privilegedContainer:        defaultRulePtr("Disabled"),
								sensitiveDataInEnvironment: defaultRulePtr("Prevent"),
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
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.default_rules.privileged_container", "Disabled"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.default_rules.sensitive_data_in_environment", "Prevent"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "rule_groups.0.id"),
					// save initial state for comparing IDs on subsequent updates
					func(s *terraform.State) error {
						rs := s.RootModule().Resources[resourceName]
						if rs == nil {
							return fmt.Errorf("resource not found")
						}

						capturedState["rule_groups.0.id"] = rs.Primary.Attributes["rule_groups.0.id"]

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
							defaultRules: &defaultRulesConfig{
								privilegedContainer: defaultRulePtr("Prevent"),
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
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.default_rules.privileged_container", "Prevent"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.default_rules.sensitive_data_in_environment", "Alert"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					// Verify rule group ID remains the same after update
					testAccCheckNestedObjectIDsUnchanged(resourceName, capturedState, []string{"rule_groups.0.id"}),
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
							description: stringPtr("Updated first test rule group - optional attributes removed"),
						},
					},
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test KAC policy with updated rule groups"),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.name", "test-rule-group-1-updated"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.description", "Updated first test rule group - optional attributes removed"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.deny_on_error", "false"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.image_assessment.enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.image_assessment.unassessed_handling", "Allow Without Alert"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.namespaces.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "rule_groups.0.namespaces.*", "*"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.labels.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.labels.0.key", "*"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.labels.0.value", "*"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.labels.0.operator", "eq"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.default_rules.privileged_container", "Alert"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.default_rules.sensitive_data_in_environment", "Alert"),
					// Verify rule group ID remains the same after update
					testAccCheckNestedObjectIDsUnchanged(resourceName, capturedState, []string{"rule_groups.0.id"}),
				),
			},
		},
	})
}

func TestCloudSecurityKacPolicyResource_MultipleRuleGroups(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := fmt.Sprintf("tfacc-kac-policy-multiplerulegroups-%s", randomSuffix)
	capturedState := make(map[string]string)

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
							defaultRules: &defaultRulesConfig{
								containerRunAsRoot:             defaultRulePtr("Disabled"),
								containerWithoutResourceLimits: defaultRulePtr("Disabled"),
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
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.default_rules.container_run_as_root", "Disabled"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.default_rules.container_without_resource_limits", "Disabled"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "rule_groups.0.id"),
					resource.TestCheckResourceAttrSet(resourceName, "rule_groups.1.id"),
					// save initial state for comparing IDs on subsequent updates
					func(s *terraform.State) error {
						rs := s.RootModule().Resources[resourceName]
						if rs == nil {
							return fmt.Errorf("resource not found")
						}

						capturedState["rule_groups.0.id"] = rs.Primary.Attributes["rule_groups.0.id"]
						capturedState["rule_groups.1.id"] = rs.Primary.Attributes["rule_groups.1.id"]

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
							defaultRules: &defaultRulesConfig{
								sensitiveHostDirectories: defaultRulePtr("Prevent"),
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
							defaultRules: &defaultRulesConfig{
								containerRunAsRoot:             defaultRulePtr("Alert"),
								containerWithoutResourceLimits: defaultRulePtr("Prevent"),
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
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.default_rules.sensitive_host_directories", "Prevent"),
					// Second rule group updated checks
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.name", "development-rule-group-updated"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.description", "Updated development environment rule group"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.deny_on_error", "true"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.image_assessment.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.image_assessment.unassessed_handling", "Prevent"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.namespaces.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.labels.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.default_rules.container_run_as_root", "Alert"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.default_rules.container_without_resource_limits", "Prevent"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "rule_groups.0.id"),
					resource.TestCheckResourceAttrSet(resourceName, "rule_groups.1.id"),
					// Verify rule group IDs remain the same after update
					testAccCheckNestedObjectIDsUnchanged(resourceName, capturedState, []string{"rule_groups.0.id", "rule_groups.1.id"}),
				),
			},
		},
	})
}

func TestCloudSecurityKacPolicyResource_ComplexRuleGroupsWithReorder(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := fmt.Sprintf("tfacc-kac-policy-complex-%s", randomSuffix)
	capturedState := make(map[string]string)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: kacPolicyConfig{
					name:        policyName,
					description: stringPtr("Test KAC policy with multiple rule groups and default rule group"),
					isEnabled:   boolPtr(false),
					ruleGroups: []ruleGroupConfig{
						{
							name:        "rule-group-1",
							description: stringPtr("Rule group 1"),
							denyOnError: boolPtr(true),
							imageAssessment: &imageAssessmentConfig{
								enabled:            true,
								unassessedHandling: "Prevent",
							},
							namespaces: []string{"alpha", "alpha-*"},
							labels: []labelConfig{
								{
									key:      "environment",
									value:    "alpha",
									operator: "eq",
								},
							},
							defaultRules: &defaultRulesConfig{
								privilegedContainer: defaultRulePtr("Prevent"),
							},
						},
						{
							name:        "rule-group-2",
							description: stringPtr("Rule group 2"),
							denyOnError: boolPtr(false),
							imageAssessment: &imageAssessmentConfig{
								enabled:            true,
								unassessedHandling: "Alert",
							},
							namespaces: []string{"beta", "stage-*"},
							labels: []labelConfig{
								{
									key:      "environment",
									value:    "beta",
									operator: "eq",
								},
							},
							defaultRules: &defaultRulesConfig{
								containerRunAsRoot: defaultRulePtr("Alert"),
							},
						},
					},
					defaultRuleGroup: &defaultRuleGroupConfig{
						denyOnError: boolPtr(false),
						imageAssessment: &imageAssessmentConfig{
							enabled:            true,
							unassessedHandling: "Alert",
						},
						defaultRules: &defaultRulesConfig{
							workloadInDefaultNamespace: defaultRulePtr("Prevent"),
							runtimeSocketInContainer:   defaultRulePtr("Disabled"),
							sensitiveHostDirectories:   defaultRulePtr("Prevent"),
						},
					},
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test KAC policy with multiple rule groups and default rule group"),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"),
					// Rule groups checks
					resource.TestCheckResourceAttr(resourceName, "rule_groups.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.name", "rule-group-1"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.deny_on_error", "true"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.image_assessment.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.image_assessment.unassessed_handling", "Prevent"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.default_rules.privileged_container", "Prevent"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.name", "rule-group-2"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.deny_on_error", "false"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.image_assessment.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.image_assessment.unassessed_handling", "Alert"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.default_rules.container_run_as_root", "Alert"),
					// Default rule group checks
					resource.TestCheckResourceAttrSet(resourceName, "default_rule_group.id"),
					resource.TestCheckResourceAttr(resourceName, "default_rule_group.deny_on_error", "false"),
					resource.TestCheckResourceAttr(resourceName, "default_rule_group.image_assessment.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "default_rule_group.image_assessment.unassessed_handling", "Alert"),
					resource.TestCheckResourceAttr(resourceName, "default_rule_group.default_rules.workload_in_default_namespace", "Prevent"),
					resource.TestCheckResourceAttr(resourceName, "default_rule_group.default_rules.runtime_socket_in_container", "Disabled"),
					resource.TestCheckResourceAttr(resourceName, "default_rule_group.default_rules.sensitive_host_directories", "Prevent"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "rule_groups.0.id"),
					resource.TestCheckResourceAttrSet(resourceName, "rule_groups.1.id"),
					// Capture initial state
					func(s *terraform.State) error {
						rs := s.RootModule().Resources[resourceName]
						if rs == nil {
							return fmt.Errorf("resource not found")
						}
						capturedState["rule_groups.0.id"] = rs.Primary.Attributes["rule_groups.0.id"]
						capturedState["rule_groups.1.id"] = rs.Primary.Attributes["rule_groups.1.id"]
						capturedState["default_rule_group.id"] = rs.Primary.Attributes["default_rule_group.id"]
						return nil
					},
				),
			},
			{
				// Reorder rule groups and update default rule group
				Config: kacPolicyConfig{
					name:        policyName,
					description: stringPtr("Test KAC policy with reordered rule groups and updated default rule group"),
					isEnabled:   boolPtr(false),
					ruleGroups: []ruleGroupConfig{
						{
							// new rule group in position 1
							name:        "new-rule-group",
							description: stringPtr("New rule group"),
						},
						{
							// rule-group-2 stays in position 2
							name:        "rule-group-2-renamed",
							description: stringPtr("Updated rule group 2"),
							denyOnError: boolPtr(true), // Changed from false to true
							imageAssessment: &imageAssessmentConfig{
								enabled:            false,     // Changed from true to false
								unassessedHandling: "Prevent", // Changed from "Alert" to "Prevent"
							},
							namespaces: []string{"beta", "stage-*", "test"}, // Added "test"
							labels: []labelConfig{
								{
									key:      "environment",
									value:    "beta",
									operator: "eq",
								},
								{
									key:      "team",
									value:    "qa",
									operator: "eq",
								},
							},
							defaultRules: &defaultRulesConfig{
								containerRunAsRoot:             defaultRulePtr("Prevent"),  // Changed from "Alert" to "Prevent"
								containerWithoutResourceLimits: defaultRulePtr("Disabled"), // New rule
							},
						},
						{
							// rule-group-1 moves to position 3
							name:        "rule-group-1",
							description: stringPtr("Reordered rule group 1"),
							denyOnError: boolPtr(false),
							imageAssessment: &imageAssessmentConfig{
								enabled:            true,
								unassessedHandling: "Alert",
							},
							namespaces: []string{"alpha"},
							labels: []labelConfig{
								{
									key:      "environment",
									value:    "alpha",
									operator: "eq",
								},
							},
							defaultRules: &defaultRulesConfig{
								privilegedContainer:        defaultRulePtr("Prevent"), // Changed from "Prevent" to "Alert"
								sensitiveDataInEnvironment: defaultRulePtr("Prevent"), // New rule
							},
						},
					},
					defaultRuleGroup: &defaultRuleGroupConfig{
						denyOnError: boolPtr(true), // Changed from false to true
						imageAssessment: &imageAssessmentConfig{
							enabled:            true,
							unassessedHandling: "Prevent", // Changed from "Alert" to "Prevent"
						},
						defaultRules: &defaultRulesConfig{
							workloadInDefaultNamespace:     defaultRulePtr("Alert"),   // Changed from "Prevent" to "Alert"
							runtimeSocketInContainer:       defaultRulePtr("Prevent"), // Changed from "Alert" to "Prevent"
							sensitiveHostDirectories:       defaultRulePtr("Alert"),   // Changed from "Prevent" to "Alert"
							containerWithoutResourceLimits: defaultRulePtr("Prevent"), // New rule
						},
					},
				}.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test KAC policy with reordered rule groups and updated default rule group"),
					resource.TestCheckResourceAttr(resourceName, "is_enabled", "false"),
					// Verify rule groups are reordered (new-rule-group now first, rule-group-2 still second, and rule-group-1 third)
					resource.TestCheckResourceAttr(resourceName, "rule_groups.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.name", "new-rule-group"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.description", "New rule group"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.deny_on_error", "false"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.image_assessment.enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.image_assessment.unassessed_handling", "Allow Without Alert"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.namespaces.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.labels.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.default_rules.container_run_as_root", "Alert"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.0.default_rules.container_without_resource_limits", "Alert"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.name", "rule-group-2-renamed"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.description", "Updated rule group 2"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.deny_on_error", "true"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.image_assessment.enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.image_assessment.unassessed_handling", "Prevent"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.namespaces.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.labels.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.default_rules.container_run_as_root", "Prevent"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.1.default_rules.container_without_resource_limits", "Disabled"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.2.name", "rule-group-1"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.2.description", "Reordered rule group 1"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.2.deny_on_error", "false"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.2.image_assessment.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.2.image_assessment.unassessed_handling", "Alert"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.2.namespaces.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.2.labels.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.2.default_rules.privileged_container", "Prevent"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.2.default_rules.sensitive_data_in_environment", "Prevent"),
					// Verify default rule group updates
					resource.TestCheckResourceAttrSet(resourceName, "default_rule_group.id"),
					resource.TestCheckResourceAttr(resourceName, "default_rule_group.deny_on_error", "true"),
					resource.TestCheckResourceAttr(resourceName, "default_rule_group.image_assessment.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "default_rule_group.image_assessment.unassessed_handling", "Prevent"),
					resource.TestCheckResourceAttr(resourceName, "default_rule_group.default_rules.workload_in_default_namespace", "Alert"),
					resource.TestCheckResourceAttr(resourceName, "default_rule_group.default_rules.runtime_socket_in_container", "Prevent"),
					resource.TestCheckResourceAttr(resourceName, "default_rule_group.default_rules.sensitive_host_directories", "Alert"),
					resource.TestCheckResourceAttr(resourceName, "default_rule_group.default_rules.container_without_resource_limits", "Prevent"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "rule_groups.0.id"),
					resource.TestCheckResourceAttrSet(resourceName, "rule_groups.1.id"),
					resource.TestCheckResourceAttrSet(resourceName, "rule_groups.2.id"),
					// Verify that rule group IDs remain the same despite reordering (they should be stable)
					func(s *terraform.State) error {
						currentRS, ok := s.RootModule().Resources[resourceName]
						if !ok {
							return fmt.Errorf("resource not found in current state: %s", resourceName)
						}

						ruleGroupIdReorderedMap := map[string]string{
							"rule_groups.0.id": "rule_groups.2.id", // first rule group becomes the third rule group
							"rule_groups.1.id": "rule_groups.1.id", // second rule group stays in the second position
						}

						for originalIdPath, newIdPath := range ruleGroupIdReorderedMap {
							initialID := capturedState[originalIdPath]
							currentID := currentRS.Primary.Attributes[newIdPath]

							if initialID == "" {
								return fmt.Errorf("initial ID not found at path: %s", originalIdPath)
							}

							if currentID != initialID {
								return fmt.Errorf("%s does not equal %s: %s -> %s", originalIdPath, newIdPath, initialID, currentID)
							}
						}

						return nil
					},
				),
			},
		},
	})
}

func testAccCheckNestedObjectIDsUnchanged(resourceName string, initialState map[string]string, idPaths []string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		// Get current resource
		currentRS, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found in current state: %s", resourceName)
		}

		// Check each ID path
		for _, idPath := range idPaths {
			initialID := initialState[idPath]
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
