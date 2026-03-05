package cloudsecurity_test

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	tfjson "github.com/hashicorp/terraform-json"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

type kacPolicyConfig struct {
	name             string
	description      *string
	enabled          *bool
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
	customRules     []customRuleConfig
}

type defaultRuleGroupConfig struct {
	denyOnError     *bool
	imageAssessment *imageAssessmentConfig
	defaultRules    *defaultRulesConfig
	customRules     []customRuleConfig
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

type customRuleConfig struct {
	id     string
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

	if c.enabled != nil {
		config += fmt.Sprintf(`
  enabled = %t`, *c.enabled)
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

			if len(rg.customRules) > 0 {
				config += `
      custom_rules = [`
				for i, cr := range rg.customRules {
					if i > 0 {
						config += `,`
					}
					config += fmt.Sprintf(`
        {
          id     = %s
          action = %q
        }`, cr.id, cr.action)
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

	config += c.defaultRuleGroup.render()
	config += `
}
`
	return config
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

	if len(drg.customRules) > 0 {
		config += `
    custom_rules = [`
		for i, cr := range drg.customRules {
			if i > 0 {
				config += `,`
			}
			config += fmt.Sprintf(`
      {
        id     = %s
        action = %q
      }`, cr.id, cr.action)
		}
		config += `
    ]`
	}

	config += `
  }`
	return config
}

func TestCloudSecurityKacPolicyResource_Minimal(t *testing.T) {
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: kacPolicyConfig{name: policyName}.String(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(policyName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
				},
			},
		},
	})
}

func TestCloudSecurityKacPolicyResource_Basic(t *testing.T) {
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	updatedPolicyName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: kacPolicyConfig{
					name:        policyName,
					description: utils.Addr("Test KAC policy created by Terraform"),
					enabled:     utils.Addr(false),
				}.String(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(policyName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Test KAC policy created by Terraform")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
				},
			},
			{
				Config: kacPolicyConfig{
					name:        updatedPolicyName,
					description: utils.Addr("Updated KAC policy description"),
					enabled:     utils.Addr(true),
				}.String(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(updatedPolicyName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Updated KAC policy description")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "id",
				ImportStateVerifyIgnore:              []string{"last_updated"},
			},
		},
	})
}

func TestCloudSecurityKacPolicyResource_EnabledToggle(t *testing.T) {
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: kacPolicyConfig{
					name:    policyName,
					enabled: utils.Addr(true),
				}.String(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(policyName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
				},
			},
			{
				Config: kacPolicyConfig{
					name:    policyName,
					enabled: utils.Addr(false),
				}.String(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(policyName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
				},
			},
			{
				Config: kacPolicyConfig{
					name:    policyName,
					enabled: utils.Addr(true),
				}.String(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(policyName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
				},
			},
		},
	})
}

func TestCloudSecurityKacPolicyResource_HostGroups(t *testing.T) {
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	hostGroupsConfig := fmt.Sprintf(`
resource "crowdstrike_host_group" "test-hg-1" {
  name        = "%[1]s-1"
  description = "test host group for kac policy tf acceptance tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_host_group" "test-hg-2" {
  name        = "%[1]s-2"
  description = "test host group for kac policy tf acceptance tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_host_group" "test-hg-3" {
  name        = "%[1]s-3"
  description = "test host group for kac policy tf acceptance tests"
  type        = "staticByID"
  host_ids    = []
}
`, policyName)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: acctest.ConfigCompose(
					hostGroupsConfig,
					kacPolicyConfig{
						name:        policyName,
						description: utils.Addr("Test KAC policy with host groups"),
						enabled:     utils.Addr(false),
						hostGroups:  []string{"crowdstrike_host_group.test-hg-1.id", "crowdstrike_host_group.test-hg-2.id"},
					}.String(),
				),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(policyName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Test KAC policy with host groups")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(2)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
				},
			},
			{
				Config: acctest.ConfigCompose(
					hostGroupsConfig,
					kacPolicyConfig{
						name:        policyName,
						description: utils.Addr("Test KAC policy with updated host groups"),
						enabled:     utils.Addr(false),
						hostGroups:  []string{"crowdstrike_host_group.test-hg-2.id", "crowdstrike_host_group.test-hg-3.id"},
					}.String(),
				),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(policyName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Test KAC policy with updated host groups")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(2)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
				},
			},
			{
				Config: acctest.ConfigCompose(
					hostGroupsConfig,
					kacPolicyConfig{
						name:        policyName,
						description: utils.Addr("Test KAC policy with no host groups"),
						enabled:     utils.Addr(false),
						hostGroups:  []string{},
					}.String(),
				),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(policyName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Test KAC policy with no host groups")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
				},
			},
		},
	})
}

func TestCloudSecurityKacPolicyResource_NameValidation(t *testing.T) {
	configWithoutName := `resource "crowdstrike_cloud_security_kac_policy" "test" {}`

	resource.ParallelTest(t, resource.TestCase{
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
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: kacPolicyConfig{
					name:        policyName,
					description: utils.Addr("Test KAC policy with default rule group"),
					enabled:     utils.Addr(false),
					defaultRuleGroup: &defaultRuleGroupConfig{
						denyOnError: utils.Addr(false),
						imageAssessment: &imageAssessmentConfig{
							enabled:            true,
							unassessedHandling: "Alert",
						},
						defaultRules: &defaultRulesConfig{
							workloadInDefaultNamespace: utils.Addr("Prevent"),
							runtimeSocketInContainer:   utils.Addr("Alert"),
						},
					},
				}.String(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(policyName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Test KAC policy with default rule group")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("deny_on_error"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("image_assessment").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("image_assessment").AtMapKey("unassessed_handling"), knownvalue.StringExact("Alert")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("default_rules").AtMapKey("workload_in_default_namespace"), knownvalue.StringExact("Prevent")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("default_rules").AtMapKey("runtime_socket_in_container"), knownvalue.StringExact("Alert")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
				},
			},
			{
				Config: kacPolicyConfig{
					name:        policyName,
					description: utils.Addr("Test KAC policy with default rule group"),
					enabled:     utils.Addr(false),
					defaultRuleGroup: &defaultRuleGroupConfig{
						denyOnError: utils.Addr(true),
						imageAssessment: &imageAssessmentConfig{
							enabled:            true,
							unassessedHandling: "Prevent",
						},
						defaultRules: &defaultRulesConfig{
							workloadInDefaultNamespace: utils.Addr("Alert"),
							runtimeSocketInContainer:   utils.Addr("Disabled"),
						},
					},
				}.String(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(policyName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Test KAC policy with default rule group")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("deny_on_error"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("image_assessment").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("image_assessment").AtMapKey("unassessed_handling"), knownvalue.StringExact("Prevent")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("default_rules").AtMapKey("workload_in_default_namespace"), knownvalue.StringExact("Alert")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("default_rules").AtMapKey("runtime_socket_in_container"), knownvalue.StringExact("Disabled")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
				},
			},
			{
				Config: kacPolicyConfig{
					name:        policyName,
					description: utils.Addr("Test KAC policy with default rule group"),
					enabled:     utils.Addr(false),
				}.String(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(policyName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Test KAC policy with default rule group")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("id"), knownvalue.NotNull()),
					// All optional default rule group attributes should revert back to their default values
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("deny_on_error"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("image_assessment").AtMapKey("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("image_assessment").AtMapKey("unassessed_handling"), knownvalue.StringExact("Allow Without Alert")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("default_rules").AtMapKey("workload_in_default_namespace"), knownvalue.StringExact("Alert")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("default_rules").AtMapKey("runtime_socket_in_container"), knownvalue.StringExact("Alert")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
				},
			},
		},
	})
}

func TestCloudSecurityKacPolicyResource_RuleGroupsMinimal(t *testing.T) {
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: kacPolicyConfig{
					name: policyName,
					ruleGroups: []ruleGroupConfig{
						{
							name: "minimal-rule-group",
						},
					},
				}.String(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(policyName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("name"), knownvalue.StringExact("minimal-rule-group")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("id"), knownvalue.NotNull()),
					// Check default values are set as expected
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("deny_on_error"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("image_assessment").AtMapKey("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("image_assessment").AtMapKey("unassessed_handling"), knownvalue.StringExact("Allow Without Alert")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("namespaces"), knownvalue.SetSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("labels"), knownvalue.SetSizeExact(1)),
					// Check the first default rule to make sure the default action is set
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("default_rules").AtMapKey("privileged_container"), knownvalue.StringExact("Alert")),
				},
			},
		},
	})
}

func TestCloudSecurityKacPolicyResource_SingleRuleGroup(t *testing.T) {
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	capturedState := make(map[string]string)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: kacPolicyConfig{
					name:        policyName,
					description: utils.Addr("Test KAC policy with rule groups"),
					enabled:     utils.Addr(false),
					ruleGroups: []ruleGroupConfig{
						{
							name:        "test-rule-group-1",
							description: utils.Addr("First test rule group"),
							denyOnError: utils.Addr(false),
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
								privilegedContainer:        utils.Addr("Disabled"),
								sensitiveDataInEnvironment: utils.Addr("Prevent"),
							},
						},
					},
				}.String(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(policyName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Test KAC policy with rule groups")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("name"), knownvalue.StringExact("test-rule-group-1")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("description"), knownvalue.StringExact("First test rule group")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("deny_on_error"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("image_assessment").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("image_assessment").AtMapKey("unassessed_handling"), knownvalue.StringExact("Alert")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("namespaces"), knownvalue.SetSizeExact(2)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("labels"), knownvalue.SetSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("default_rules").AtMapKey("privileged_container"), knownvalue.StringExact("Disabled")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("default_rules").AtMapKey("sensitive_data_in_environment"), knownvalue.StringExact("Prevent")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("id"), knownvalue.NotNull()),
				},
				Check: resource.ComposeAggregateTestCheckFunc(
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
					description: utils.Addr("Test KAC policy with updated rule groups"),
					enabled:     utils.Addr(false),
					ruleGroups: []ruleGroupConfig{
						{
							name:        "test-rule-group-1-updated",
							description: utils.Addr("Updated first test rule group"),
							denyOnError: utils.Addr(true),
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
								privilegedContainer: utils.Addr("Prevent"),
							},
						},
					},
				}.String(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(policyName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Test KAC policy with updated rule groups")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("name"), knownvalue.StringExact("test-rule-group-1-updated")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("description"), knownvalue.StringExact("Updated first test rule group")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("deny_on_error"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("image_assessment").AtMapKey("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("image_assessment").AtMapKey("unassessed_handling"), knownvalue.StringExact("Prevent")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("namespaces"), knownvalue.SetSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("labels"), knownvalue.SetSizeExact(2)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("default_rules").AtMapKey("privileged_container"), knownvalue.StringExact("Prevent")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("default_rules").AtMapKey("sensitive_data_in_environment"), knownvalue.StringExact("Alert")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verify rule group ID remains the same after update
					testAccCheckNestedObjectIDsUnchanged(resourceName, capturedState, []string{"rule_groups.0.id"}),
				),
			},
			{
				Config: kacPolicyConfig{
					name:        policyName,
					description: utils.Addr("Test KAC policy with updated rule groups"),
					enabled:     utils.Addr(false),
					ruleGroups: []ruleGroupConfig{
						{
							name:        "test-rule-group-1-updated",
							description: utils.Addr("Updated first test rule group - optional attributes removed"),
						},
					},
				}.String(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(policyName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Test KAC policy with updated rule groups")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("name"), knownvalue.StringExact("test-rule-group-1-updated")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("description"), knownvalue.StringExact("Updated first test rule group - optional attributes removed")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("deny_on_error"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("image_assessment").AtMapKey("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("image_assessment").AtMapKey("unassessed_handling"), knownvalue.StringExact("Allow Without Alert")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("namespaces"), knownvalue.SetSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("labels"), knownvalue.SetSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("default_rules").AtMapKey("privileged_container"), knownvalue.StringExact("Alert")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("default_rules").AtMapKey("sensitive_data_in_environment"), knownvalue.StringExact("Alert")),
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verify rule group ID remains the same after update
					testAccCheckNestedObjectIDsUnchanged(resourceName, capturedState, []string{"rule_groups.0.id"}),
				),
			},
		},
	})
}

func TestCloudSecurityKacPolicyResource_MultipleRuleGroups(t *testing.T) {
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	capturedState := make(map[string]string)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: kacPolicyConfig{
					name:        policyName,
					description: utils.Addr("Test KAC policy with multiple rule groups"),
					enabled:     utils.Addr(false),
					ruleGroups: []ruleGroupConfig{
						{
							name:        "production-rule-group",
							description: utils.Addr("Production environment rule group"),
							denyOnError: utils.Addr(true),
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
							description: utils.Addr("Development environment rule group"),
							denyOnError: utils.Addr(false),
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
								containerRunAsRoot:             utils.Addr("Disabled"),
								containerWithoutResourceLimits: utils.Addr("Disabled"),
							},
						},
					},
				}.String(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(policyName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups"), knownvalue.ListSizeExact(2)),
					// First rule group checks
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("name"), knownvalue.StringExact("production-rule-group")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("description"), knownvalue.StringExact("Production environment rule group")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("deny_on_error"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("image_assessment").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("image_assessment").AtMapKey("unassessed_handling"), knownvalue.StringExact("Prevent")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("namespaces"), knownvalue.SetSizeExact(2)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("labels"), knownvalue.SetSizeExact(1)),
					// Second rule group checks
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("name"), knownvalue.StringExact("development-rule-group")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("description"), knownvalue.StringExact("Development environment rule group")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("deny_on_error"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("image_assessment").AtMapKey("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("image_assessment").AtMapKey("unassessed_handling"), knownvalue.StringExact("Allow Without Alert")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("namespaces"), knownvalue.SetSizeExact(3)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("labels"), knownvalue.SetSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("default_rules").AtMapKey("container_run_as_root"), knownvalue.StringExact("Disabled")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("default_rules").AtMapKey("container_without_resource_limits"), knownvalue.StringExact("Disabled")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("id"), knownvalue.NotNull()),
				},
				Check: resource.ComposeAggregateTestCheckFunc(
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
					description: utils.Addr("Test KAC policy with updated multiple rule groups"),
					enabled:     utils.Addr(false),
					ruleGroups: []ruleGroupConfig{
						{
							name:        "production-rule-group-updated",
							description: utils.Addr("Updated production environment rule group"),
							denyOnError: utils.Addr(false),
							imageAssessment: &imageAssessmentConfig{
								enabled:            false,
								unassessedHandling: "Alert",
							},
							namespaces: []string{"production", "prod-*", "live"},
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
								sensitiveHostDirectories: utils.Addr("Prevent"),
							},
						},
						{
							name:        "development-rule-group-updated",
							description: utils.Addr("Updated development environment rule group"),
							denyOnError: utils.Addr(true),
							imageAssessment: &imageAssessmentConfig{
								enabled:            true,
								unassessedHandling: "Prevent",
							},
							namespaces: []string{"development", "test"},
							labels: []labelConfig{
								{
									key:      "environment",
									value:    "development",
									operator: "eq",
								},
							},
							defaultRules: &defaultRulesConfig{
								containerRunAsRoot:             utils.Addr("Alert"),
								containerWithoutResourceLimits: utils.Addr("Prevent"),
							},
						},
					},
				}.String(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(policyName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups"), knownvalue.ListSizeExact(2)),
					// First rule group updated checks
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("name"), knownvalue.StringExact("production-rule-group-updated")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("description"), knownvalue.StringExact("Updated production environment rule group")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("deny_on_error"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("image_assessment").AtMapKey("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("image_assessment").AtMapKey("unassessed_handling"), knownvalue.StringExact("Alert")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("namespaces"), knownvalue.SetSizeExact(3)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("labels"), knownvalue.SetSizeExact(2)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("default_rules").AtMapKey("sensitive_host_directories"), knownvalue.StringExact("Prevent")),
					// Second rule group updated checks
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("name"), knownvalue.StringExact("development-rule-group-updated")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("description"), knownvalue.StringExact("Updated development environment rule group")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("deny_on_error"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("image_assessment").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("image_assessment").AtMapKey("unassessed_handling"), knownvalue.StringExact("Prevent")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("namespaces"), knownvalue.SetSizeExact(2)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("labels"), knownvalue.SetSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("default_rules").AtMapKey("container_run_as_root"), knownvalue.StringExact("Alert")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("default_rules").AtMapKey("container_without_resource_limits"), knownvalue.StringExact("Prevent")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("id"), knownvalue.NotNull()),
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verify rule group IDs remain the same after update
					testAccCheckNestedObjectIDsUnchanged(resourceName, capturedState, []string{"rule_groups.0.id", "rule_groups.1.id"}),
				),
			},
		},
	})
}

func TestCloudSecurityKacPolicyResource_ComplexRuleGroupsWithReorder(t *testing.T) {
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	policyName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	capturedState := make(map[string]string)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: kacPolicyConfig{
					name:        policyName,
					description: utils.Addr("Test KAC policy with multiple rule groups and default rule group"),
					enabled:     utils.Addr(false),
					ruleGroups: []ruleGroupConfig{
						{
							name:        "rule-group-1",
							description: utils.Addr("Rule group 1"),
							denyOnError: utils.Addr(true),
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
								privilegedContainer: utils.Addr("Prevent"),
							},
						},
						{
							name:        "rule-group-2",
							description: utils.Addr("Rule group 2"),
							denyOnError: utils.Addr(false),
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
								containerRunAsRoot: utils.Addr("Alert"),
							},
						},
					},
					defaultRuleGroup: &defaultRuleGroupConfig{
						denyOnError: utils.Addr(false),
						imageAssessment: &imageAssessmentConfig{
							enabled:            true,
							unassessedHandling: "Alert",
						},
						defaultRules: &defaultRulesConfig{
							workloadInDefaultNamespace: utils.Addr("Prevent"),
							runtimeSocketInContainer:   utils.Addr("Disabled"),
							sensitiveHostDirectories:   utils.Addr("Prevent"),
						},
					},
				}.String(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(policyName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Test KAC policy with multiple rule groups and default rule group")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					// Rule groups checks
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups"), knownvalue.ListSizeExact(2)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("name"), knownvalue.StringExact("rule-group-1")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("deny_on_error"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("image_assessment").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("image_assessment").AtMapKey("unassessed_handling"), knownvalue.StringExact("Prevent")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("default_rules").AtMapKey("privileged_container"), knownvalue.StringExact("Prevent")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("name"), knownvalue.StringExact("rule-group-2")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("deny_on_error"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("image_assessment").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("image_assessment").AtMapKey("unassessed_handling"), knownvalue.StringExact("Alert")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("default_rules").AtMapKey("container_run_as_root"), knownvalue.StringExact("Alert")),
					// Default rule group checks
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("deny_on_error"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("image_assessment").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("image_assessment").AtMapKey("unassessed_handling"), knownvalue.StringExact("Alert")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("default_rules").AtMapKey("workload_in_default_namespace"), knownvalue.StringExact("Prevent")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("default_rules").AtMapKey("runtime_socket_in_container"), knownvalue.StringExact("Disabled")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("default_rules").AtMapKey("sensitive_host_directories"), knownvalue.StringExact("Prevent")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("id"), knownvalue.NotNull()),
				},
				Check: resource.ComposeAggregateTestCheckFunc(
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
					description: utils.Addr("Test KAC policy with reordered rule groups and updated default rule group"),
					enabled:     utils.Addr(false),
					ruleGroups: []ruleGroupConfig{
						{
							// new rule group in position 1
							name:        "new-rule-group",
							description: utils.Addr("New rule group"),
						},
						{
							// rule-group-2 stays in position 2
							name:        "rule-group-2-renamed",
							description: utils.Addr("Updated rule group 2"),
							denyOnError: utils.Addr(true),
							imageAssessment: &imageAssessmentConfig{
								enabled:            false,
								unassessedHandling: "Prevent",
							},
							namespaces: []string{"beta", "stage-*", "test"},
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
								containerRunAsRoot:             utils.Addr("Prevent"),
								containerWithoutResourceLimits: utils.Addr("Disabled"),
							},
						},
						{
							// rule-group-1 moves to position 3
							name:        "rule-group-1",
							description: utils.Addr("Reordered rule group 1"),
							denyOnError: utils.Addr(false),
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
								privilegedContainer:        utils.Addr("Prevent"),
								sensitiveDataInEnvironment: utils.Addr("Prevent"),
							},
						},
					},
					defaultRuleGroup: &defaultRuleGroupConfig{
						denyOnError: utils.Addr(true),
						imageAssessment: &imageAssessmentConfig{
							enabled:            true,
							unassessedHandling: "Prevent",
						},
						defaultRules: &defaultRulesConfig{
							workloadInDefaultNamespace:     utils.Addr("Alert"),
							runtimeSocketInContainer:       utils.Addr("Prevent"),
							sensitiveHostDirectories:       utils.Addr("Alert"),
							containerWithoutResourceLimits: utils.Addr("Prevent"),
						},
					},
				}.String(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(policyName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Test KAC policy with reordered rule groups and updated default rule group")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					// Verify rule groups are reordered (new-rule-group now first, rule-group-2 still second, and rule-group-1 third)
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups"), knownvalue.ListSizeExact(3)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("name"), knownvalue.StringExact("new-rule-group")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("description"), knownvalue.StringExact("New rule group")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("deny_on_error"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("image_assessment").AtMapKey("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("image_assessment").AtMapKey("unassessed_handling"), knownvalue.StringExact("Allow Without Alert")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("namespaces"), knownvalue.SetSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("labels"), knownvalue.SetSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("default_rules").AtMapKey("container_run_as_root"), knownvalue.StringExact("Alert")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("default_rules").AtMapKey("container_without_resource_limits"), knownvalue.StringExact("Alert")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("name"), knownvalue.StringExact("rule-group-2-renamed")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("description"), knownvalue.StringExact("Updated rule group 2")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("deny_on_error"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("image_assessment").AtMapKey("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("image_assessment").AtMapKey("unassessed_handling"), knownvalue.StringExact("Prevent")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("namespaces"), knownvalue.SetSizeExact(3)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("labels"), knownvalue.SetSizeExact(2)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("default_rules").AtMapKey("container_run_as_root"), knownvalue.StringExact("Prevent")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("default_rules").AtMapKey("container_without_resource_limits"), knownvalue.StringExact("Disabled")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(2).AtMapKey("name"), knownvalue.StringExact("rule-group-1")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(2).AtMapKey("description"), knownvalue.StringExact("Reordered rule group 1")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(2).AtMapKey("deny_on_error"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(2).AtMapKey("image_assessment").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(2).AtMapKey("image_assessment").AtMapKey("unassessed_handling"), knownvalue.StringExact("Alert")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(2).AtMapKey("namespaces"), knownvalue.SetSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(2).AtMapKey("labels"), knownvalue.SetSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(2).AtMapKey("default_rules").AtMapKey("privileged_container"), knownvalue.StringExact("Prevent")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(2).AtMapKey("default_rules").AtMapKey("sensitive_data_in_environment"), knownvalue.StringExact("Prevent")),
					// Verify default rule group updates
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("deny_on_error"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("image_assessment").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("image_assessment").AtMapKey("unassessed_handling"), knownvalue.StringExact("Prevent")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("default_rules").AtMapKey("workload_in_default_namespace"), knownvalue.StringExact("Alert")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("default_rules").AtMapKey("runtime_socket_in_container"), knownvalue.StringExact("Prevent")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("default_rules").AtMapKey("sensitive_host_directories"), knownvalue.StringExact("Alert")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("default_rules").AtMapKey("container_without_resource_limits"), knownvalue.StringExact("Prevent")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(2).AtMapKey("id"), knownvalue.NotNull()),
				},
				Check: resource.ComposeAggregateTestCheckFunc(
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

func TestCloudSecurityKacPolicyResource_CustomRules(t *testing.T) {
	policyName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	customRule1Name := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	customRule2Name := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	customRulesConfig := fmt.Sprintf(`
resource "crowdstrike_cloud_security_kac_custom_rule" "test_rule_1" {
  name        = %[1]q
  description = "Test custom rule 1 for KAC policy"
  severity    = "high"
  logic       = <<EOF
package crowdstrike

import rego.v1

default result := "fail"

result := "pass" if {
	input.metadata.name == "test-pod"
}
EOF
}

resource "crowdstrike_cloud_security_kac_custom_rule" "test_rule_2" {
  name        = %[2]q
  description = "Test custom rule 2 for KAC policy"
  severity    = "medium"
  logic       = <<EOF
package crowdstrike

import rego.v1

default result := "fail"

result := "pass" if {
	input.metadata.name == "staging-pod"
}
EOF
}
`, customRule1Name, customRule2Name)

	customRule1ResourceName := "crowdstrike_cloud_security_kac_custom_rule.test_rule_1"
	customRule2ResourceName := "crowdstrike_cloud_security_kac_custom_rule.test_rule_2"

	rg1CustomRulesPath := tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("custom_rules")
	rg2CustomRulesPath := tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("custom_rules")
	defaultRGCustomRulesPath := tfjsonpath.New("default_rule_group").AtMapKey("custom_rules")

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Step 1: Create policy without custom rules
			{
				Config: acctest.ConfigCompose(
					customRulesConfig,
					kacPolicyConfig{
						name: policyName,
						ruleGroups: []ruleGroupConfig{
							{
								name:        "rule-group-1",
								description: utils.Addr("First rule group"),
							},
							{
								name:        "rule-group-2",
								description: utils.Addr("Second rule group"),
							},
						},
					}.String(),
				),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(policyName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups"), knownvalue.ListSizeExact(2)),
					statecheck.ExpectKnownValue(resourceName, rg1CustomRulesPath, knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, rg2CustomRulesPath, knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, defaultRGCustomRulesPath, knownvalue.Null()),
				},
			},
			// Step 2: Add custom rules to existing policy
			{
				Config: acctest.ConfigCompose(
					customRulesConfig,
					kacPolicyConfig{
						name: policyName,
						ruleGroups: []ruleGroupConfig{
							{
								name:        "rule-group-1",
								description: utils.Addr("First rule group with custom rule"),
								customRules: []customRuleConfig{
									{
										id:     "crowdstrike_cloud_security_kac_custom_rule.test_rule_1.id",
										action: "Alert",
									},
								},
							},
							{
								name:        "rule-group-2",
								description: utils.Addr("Second rule group"),
							},
						},
						defaultRuleGroup: &defaultRuleGroupConfig{
							customRules: []customRuleConfig{
								{
									id:     "crowdstrike_cloud_security_kac_custom_rule.test_rule_1.id",
									action: "Prevent",
								},
							},
						},
					}.String(),
				),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(policyName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups"), knownvalue.ListSizeExact(2)),

					// rule-group-1: test_rule_1 explicitly set to Alert
					statecheck.ExpectKnownValue(resourceName, rg1CustomRulesPath, knownvalue.SetSizeExact(1)),
					expectCustomRuleAction{resourceName, rg1CustomRulesPath, customRule1ResourceName, "Alert"},

					// rule-group-2: test_rule_1 propagated as Disabled
					statecheck.ExpectKnownValue(resourceName, rg2CustomRulesPath, knownvalue.SetSizeExact(1)),
					expectCustomRuleAction{resourceName, rg2CustomRulesPath, customRule1ResourceName, "Disabled"},

					// default rule group: test_rule_1 explicitly set to Prevent
					statecheck.ExpectKnownValue(resourceName, defaultRGCustomRulesPath, knownvalue.SetSizeExact(1)),
					expectCustomRuleAction{resourceName, defaultRGCustomRulesPath, customRule1ResourceName, "Prevent"},
				},
			},
			// Step 3: Update custom rule actions and add another custom rule
			{
				Config: acctest.ConfigCompose(
					customRulesConfig,
					kacPolicyConfig{
						name: policyName,
						ruleGroups: []ruleGroupConfig{
							{
								name:        "rule-group-1",
								description: utils.Addr("First rule group with custom rule"),
								customRules: []customRuleConfig{
									{
										id:     "crowdstrike_cloud_security_kac_custom_rule.test_rule_1.id",
										action: "Prevent", // Changed from Alert
									},
									{
										id:     "crowdstrike_cloud_security_kac_custom_rule.test_rule_2.id",
										action: "Disabled",
									},
								},
							},
							{
								name:        "rule-group-2",
								description: utils.Addr("Second rule group"),
								customRules: []customRuleConfig{
									{
										id:     "crowdstrike_cloud_security_kac_custom_rule.test_rule_1.id",
										action: "Alert", // Changed from default action
									},
									{
										id:     "crowdstrike_cloud_security_kac_custom_rule.test_rule_2.id",
										action: "Disabled",
									},
								},
							},
						},
						defaultRuleGroup: &defaultRuleGroupConfig{
							customRules: []customRuleConfig{
								{
									id:     "crowdstrike_cloud_security_kac_custom_rule.test_rule_1.id",
									action: "Disabled", // Changed from Alert
								},
								{
									id:     "crowdstrike_cloud_security_kac_custom_rule.test_rule_2.id",
									action: "Prevent", // New custom rule added to default rule group
								},
							},
						},
					}.String(),
				),
				ConfigStateChecks: []statecheck.StateCheck{
					// rule-group-1: test_rule_1=Prevent, test_rule_2=Disabled
					statecheck.ExpectKnownValue(resourceName, rg1CustomRulesPath, knownvalue.SetSizeExact(2)),
					expectCustomRuleAction{resourceName, rg1CustomRulesPath, customRule1ResourceName, "Prevent"},
					expectCustomRuleAction{resourceName, rg1CustomRulesPath, customRule2ResourceName, "Disabled"},

					// rule-group-2: test_rule_1=Alert, test_rule_2=Disabled
					statecheck.ExpectKnownValue(resourceName, rg2CustomRulesPath, knownvalue.SetSizeExact(2)),
					expectCustomRuleAction{resourceName, rg2CustomRulesPath, customRule1ResourceName, "Alert"},
					expectCustomRuleAction{resourceName, rg2CustomRulesPath, customRule2ResourceName, "Disabled"},

					// default rule group: test_rule_1=Disabled, test_rule_2=Prevent
					statecheck.ExpectKnownValue(resourceName, defaultRGCustomRulesPath, knownvalue.SetSizeExact(2)),
					expectCustomRuleAction{resourceName, defaultRGCustomRulesPath, customRule1ResourceName, "Disabled"},
					expectCustomRuleAction{resourceName, defaultRGCustomRulesPath, customRule2ResourceName, "Prevent"},
				},
			},
			// Step 4: Remove one custom rule
			{
				Config: acctest.ConfigCompose(
					customRulesConfig,
					kacPolicyConfig{
						name: policyName,
						ruleGroups: []ruleGroupConfig{
							{
								name:        "rule-group-1",
								description: utils.Addr("First rule group with custom rule"),
								customRules: []customRuleConfig{
									{
										id:     "crowdstrike_cloud_security_kac_custom_rule.test_rule_2.id",
										action: "Alert",
									},
								},
							},
							{
								name:        "rule-group-2",
								description: utils.Addr("Second rule group"),
								customRules: []customRuleConfig{
									{
										id:     "crowdstrike_cloud_security_kac_custom_rule.test_rule_2.id",
										action: "Prevent",
									},
								},
							},
						},
						defaultRuleGroup: &defaultRuleGroupConfig{
							// Remove custom_rules to revert all custom rules to default action
						},
					}.String(),
				),
				ConfigStateChecks: []statecheck.StateCheck{
					// rule-group-1: test_rule_2=Alert
					statecheck.ExpectKnownValue(resourceName, rg1CustomRulesPath, knownvalue.SetSizeExact(1)),
					expectCustomRuleAction{resourceName, rg1CustomRulesPath, customRule2ResourceName, "Alert"},

					// rule-group-2: test_rule_2=Prevent
					statecheck.ExpectKnownValue(resourceName, rg2CustomRulesPath, knownvalue.SetSizeExact(1)),
					expectCustomRuleAction{resourceName, rg2CustomRulesPath, customRule2ResourceName, "Prevent"},

					// default rule group: test_rule_2 propagated as Disabled
					statecheck.ExpectKnownValue(resourceName, defaultRGCustomRulesPath, knownvalue.SetSizeExact(1)),
					expectCustomRuleAction{resourceName, defaultRGCustomRulesPath, customRule2ResourceName, "Disabled"},
				},
			},
			// Step 5: Import validation
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "id",
				ImportStateVerifyIgnore:              []string{"last_updated"},
			},
			// Step 6: Remove all custom rules
			{
				Config: acctest.ConfigCompose(
					customRulesConfig,
					kacPolicyConfig{
						name: policyName,
						ruleGroups: []ruleGroupConfig{
							{
								name:        "rule-group-1",
								description: utils.Addr("Rule group without custom rules"),
							},
							{
								name:        "rule-group-2",
								description: utils.Addr("Second rule group"),
							},
						},
					}.String(),
				),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(policyName)),
					statecheck.ExpectKnownValue(resourceName, rg1CustomRulesPath, knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, rg2CustomRulesPath, knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, defaultRGCustomRulesPath, knownvalue.Null()),
				},
			},
		},
	})
}

func TestCloudSecurityKacPolicyResource_CustomRulesValidation(t *testing.T) {
	policyName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_cloud_security_kac_policy.test"
	customRule1Name := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	customRule2Name := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	customRulesConfig := fmt.Sprintf(`
resource "crowdstrike_cloud_security_kac_custom_rule" "test_rule_1" {
  name        = %[1]q
  description = "Test custom rule 1 for KAC policy"
  severity    = "high"
  logic       = <<EOF
package crowdstrike

import rego.v1

default result := "fail"

result := "pass" if {
	input.metadata.name == "test-pod"
}
EOF
}

resource "crowdstrike_cloud_security_kac_custom_rule" "test_rule_2" {
  name        = %[2]q
  description = "Test custom rule 2 for KAC policy"
  severity    = "medium"
  logic       = <<EOF
package crowdstrike

import rego.v1

default result := "fail"

result := "pass" if {
	input.metadata.name == "staging-pod"
}
EOF
}
`, customRule1Name, customRule2Name)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Step 1: Test validation error when rule groups have different custom rules
			{
				Config: acctest.ConfigCompose(
					customRulesConfig,
					kacPolicyConfig{
						name: policyName,
						ruleGroups: []ruleGroupConfig{
							{
								name:        "rule-group-1",
								description: utils.Addr("First rule group with 2 custom rules"),
								customRules: []customRuleConfig{
									{
										id:     "crowdstrike_cloud_security_kac_custom_rule.test_rule_1.id",
										action: "Alert",
									},
									{
										id:     "crowdstrike_cloud_security_kac_custom_rule.test_rule_2.id",
										action: "Alert",
									},
								},
							},
							{
								name:        "rule-group-2",
								description: utils.Addr("Second rule group with only 1 custom rule"),
								customRules: []customRuleConfig{
									{
										id:     "crowdstrike_cloud_security_kac_custom_rule.test_rule_1.id",
										action: "Prevent",
									},
								},
							},
						},
					}.String(),
				),
				ExpectError: regexp.MustCompile(`Rule group "rule-group-2" has 1 custom rule\(s\)`),
			},
			// Step 2: Test validation error when default rule group has incomplete custom rules
			{
				Config: acctest.ConfigCompose(
					customRulesConfig,
					kacPolicyConfig{
						name: policyName,
						ruleGroups: []ruleGroupConfig{
							{
								name:        "rule-group-1",
								description: utils.Addr("Rule group with 2 custom rules"),
								customRules: []customRuleConfig{
									{
										id:     "crowdstrike_cloud_security_kac_custom_rule.test_rule_1.id",
										action: "Alert",
									},
									{
										id:     "crowdstrike_cloud_security_kac_custom_rule.test_rule_2.id",
										action: "Alert",
									},
								},
							},
						},
						defaultRuleGroup: &defaultRuleGroupConfig{
							customRules: []customRuleConfig{
								{
									id:     "crowdstrike_cloud_security_kac_custom_rule.test_rule_1.id",
									action: "Prevent",
								},
							},
						},
					}.String(),
				),
				ExpectError: regexp.MustCompile(`Rule group "Default" has 1 custom rule\(s\)`),
			},
			// Step 3: Test successful creation when custom rules are only defined in the default rule group
			{
				Config: acctest.ConfigCompose(
					customRulesConfig,
					kacPolicyConfig{
						name: policyName,
						ruleGroups: []ruleGroupConfig{
							{
								name:        "rule-group-1",
								description: utils.Addr("First rule group"),
							},
							{
								name:        "rule-group-2",
								description: utils.Addr("Second rule group"),
							},
						},
						defaultRuleGroup: &defaultRuleGroupConfig{
							customRules: []customRuleConfig{
								{
									id:     "crowdstrike_cloud_security_kac_custom_rule.test_rule_1.id",
									action: "Alert",
								},
								{
									id:     "crowdstrike_cloud_security_kac_custom_rule.test_rule_2.id",
									action: "Prevent",
								},
							},
						},
					}.String(),
				),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(policyName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups"), knownvalue.ListSizeExact(2)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("custom_rules"), knownvalue.SetSizeExact(2)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("custom_rules"), knownvalue.SetSizeExact(2)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("default_rule_group").AtMapKey("custom_rules"), knownvalue.SetSizeExact(2)),
					// Verify propagated rule groups have Disabled actions
					expectCustomRuleAction{resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("custom_rules"), "crowdstrike_cloud_security_kac_custom_rule.test_rule_1", "Disabled"},
					expectCustomRuleAction{resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(0).AtMapKey("custom_rules"), "crowdstrike_cloud_security_kac_custom_rule.test_rule_2", "Disabled"},
					expectCustomRuleAction{resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("custom_rules"), "crowdstrike_cloud_security_kac_custom_rule.test_rule_1", "Disabled"},
					expectCustomRuleAction{resourceName, tfjsonpath.New("rule_groups").AtSliceIndex(1).AtMapKey("custom_rules"), "crowdstrike_cloud_security_kac_custom_rule.test_rule_2", "Disabled"},
					// Verify default rule group has explicitly set actions
					expectCustomRuleAction{resourceName, tfjsonpath.New("default_rule_group").AtMapKey("custom_rules"), "crowdstrike_cloud_security_kac_custom_rule.test_rule_1", "Alert"},
					expectCustomRuleAction{resourceName, tfjsonpath.New("default_rule_group").AtMapKey("custom_rules"), "crowdstrike_cloud_security_kac_custom_rule.test_rule_2", "Prevent"},
				},
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

type expectCustomRuleAction struct {
	resourceAddress     string
	collectionPath      tfjsonpath.Path
	ruleResourceAddress string
	expectedAction      string
}

func (e expectCustomRuleAction) CheckState(_ context.Context, req statecheck.CheckStateRequest, resp *statecheck.CheckStateResponse) {
	var targetResource, ruleResource *tfjson.StateResource

	for _, r := range req.State.Values.RootModule.Resources {
		if r.Address == e.resourceAddress {
			targetResource = r
		}
		if r.Address == e.ruleResourceAddress {
			ruleResource = r
		}
	}

	if targetResource == nil {
		resp.Error = fmt.Errorf("resource %s not found in state", e.resourceAddress)
		return
	}
	if ruleResource == nil {
		resp.Error = fmt.Errorf("resource %s not found in state", e.ruleResourceAddress)
		return
	}

	ruleID, ok := ruleResource.AttributeValues["id"].(string)
	if !ok {
		resp.Error = fmt.Errorf("resource %s has no string id attribute", e.ruleResourceAddress)
		return
	}

	result, err := tfjsonpath.Traverse(targetResource.AttributeValues, e.collectionPath)
	if err != nil {
		resp.Error = fmt.Errorf("failed to traverse path %s: %w", e.collectionPath.String(), err)
		return
	}

	customRules, ok := result.([]any)
	if !ok {
		resp.Error = fmt.Errorf("expected []any at path %s, got %T", e.collectionPath.String(), result)
		return
	}

	for _, item := range customRules {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if obj["id"] == ruleID {
			if obj["action"] != e.expectedAction {
				resp.Error = fmt.Errorf(
					"custom rule %s in %s: expected action %q, got %q",
					e.ruleResourceAddress, e.collectionPath.String(), e.expectedAction, obj["action"],
				)
			}
			return
		}
	}

	resp.Error = fmt.Errorf("custom rule with ID %s (%s) not found in %s", ruleID, e.ruleResourceAddress, e.collectionPath.String())
}
