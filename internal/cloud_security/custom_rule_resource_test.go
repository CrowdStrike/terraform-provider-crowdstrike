package cloudsecurity_test

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// skipIfRegoNotEnabled skips the test if the ENABLE_REGO_TESTS environment variable is not set.
// This is used for tests that use custom Rego logic, which requires the custom policy feature
// flag to be enabled in the CrowdStrike environment.
// To enable these tests, set: export ENABLE_REGO_TESTS=1.
func skipIfRegoNotEnabled(t *testing.T) {
	if os.Getenv("ENABLE_REGO_TESTS") == "" {
		t.Skip("Skipping test: ENABLE_REGO_TESTS environment variable not set. These tests require the custom policy feature flag to be enabled for your CID.")
	}
}

type ruleBaseConfig struct {
	ruleNamePrefix  string
	description     []string
	subdomain       string
	domain          string
	severity        []string
	remediationInfo [][]string
	controls        []control
	logic           []string
	alertInfo       [][]string
	attackTypes     [][]string
}

type ruleCustomConfig struct {
	ruleBaseConfig
	parentId      string
	cloudProvider string
	cloudPlatform string
	resourceType  string
	parentRule    dataRuleConfig
}

type control struct {
	authority string
	code      string
}

var commonConfig = ruleBaseConfig{
	ruleNamePrefix: acctest.ResourcePrefix,
	description: []string{
		"This is a description",
		"This is an updated description",
	},
	subdomain: "IOM",
	domain:    "CSPM",
	severity:  []string{"critical", "informational"},
	remediationInfo: [][]string{
		{"This is the first step", "This is the second step"},
		{"This is the first step", "This is the second step", "This is the third step."},
	},
	controls: []control{
		{
			authority: "CIS",
			code:      "791",
		},
		{
			authority: "CIS",
			code:      "98",
		},
	},
	logic: []string{
		"package crowdstrike\ndefault result = \"pass\"\nresult = \"fail\" if {\n input.tags[_] == \"catch-me\"\n }",
		"package crowdstrike\ndefault result = \"pass\"\nresult = \"fail\" if {\n input.tags[_] == \"catch-me-again\"\n }",
	},
	alertInfo: [][]string{
		{
			"List all Auto Scaling Groups in the account.",
			"Check if multiple instance types are included in the configuration.",
			"Check if multiple availability zones are configured.",
		},
		{
			"Check if multiple instance types are included in the configuration.",
			"List all Auto Scaling Groups in the account.",
			"Check if multiple availability zones are configured.",
			"Alert when any of the above conditions are met.",
		},
	},
	attackTypes: [][]string{
		{"Look it's an attack type"},
		{"Look it's an attack type", "This is a second attack type"},
	},
}

var awsCopyConfig = ruleCustomConfig{
	ruleBaseConfig: commonConfig,
	parentId:       "0473a26b-7f29-43c7-9581-105f8c9c0b7d",
	cloudProvider:  "AWS",
	cloudPlatform:  "AWS",
	resourceType:   "AWS::EC2::Instance",
	parentRule:     awsConfig,
}

var azureCopyConfig = ruleCustomConfig{
	ruleBaseConfig: commonConfig,
	parentId:       "1c9516e9-490b-461c-8644-9239ff3cf0d3",
	cloudProvider:  "Azure",
	cloudPlatform:  "Azure",
	resourceType:   "Microsoft.Compute/virtualMachines",
	parentRule:     azureConfig,
}

var gcpCopyConfig = ruleCustomConfig{
	ruleBaseConfig: commonConfig,
	parentId:       "0260ffa9-eb65-42f4-a02a-7456d280049a",
	cloudProvider:  "GCP",
	cloudPlatform:  "GCP",
	resourceType:   "sqladmin.googleapis.com/Instance",
	parentRule:     gcpConfig,
}

// AWS Tests.
func TestCloudSecurityCustomRuleResource_AWS_Copy(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleCopyTests(awsCopyConfig, "AWS"),
	})
}

func TestCloudSecurityCustomRuleResource_AWS_Rego(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleLogicTests(awsCopyConfig, "AWS_Rego"),
	})
}

func TestCloudSecurityCustomRuleResource_AWS_Minimal(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateMinimalRuleCopyTests(awsCopyConfig, "AWS_Min"),
	})
}

func TestCloudSecurityCustomRuleResource_AWS_MinimalRego(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateMinimalRuleLogicTests(awsCopyConfig, "AWS_Min_Rego"),
	})
}

func TestCloudSecurityCustomRuleResource_AWS_DefinedToOmitted(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleCopyDefinedToOmittedTests(awsCopyConfig, "AWS_Omit"),
	})
}

func TestCloudSecurityCustomRuleResource_AWS_RegoDefinedToOmitted(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleRegoDefinedToOmittedTests(awsCopyConfig, "AWS_Omit_Rego"),
	})
}

func TestCloudSecurityCustomRuleResource_AWS_RegoDefinedToEmpty(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleRegoDefinedToEmptyTests(awsCopyConfig, "AWS_Empty_Rego"),
	})
}

func TestCloudSecurityCustomRuleResource_AWS_CopyDefinedToEmpty(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleCopyDefinedToEmptyTests(awsCopyConfig),
	})
}

func TestCloudSecurityCustomRuleResource_AWS_CopyDefinedAttackType(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleCopyDefinedAttackTypeTests(awsCopyConfig),
	})
}

func TestCloudSecurityCustomRuleResource_AWS_CopyInheritToEmptyToInherit(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleCopyInheritToEmptyToInheritTests(awsCopyConfig, "AWS_InheritCycle"),
	})
}

func TestCloudSecurityCustomRuleResource_AWS_CopyEmptyOnCreate(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleCopyEmptyOnCreateTests(awsCopyConfig, "AWS_EmptyCreate"),
	})
}

// Runtime/IOM Field Validation Tests.
func TestCloudSecurityCustomRuleResource_Runtime_IOM_DisabledFields(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuntimeIOMDisabledFieldsTests(),
	})
}

func TestCloudSecurityCustomRuleResource_Runtime_IOM_ValidConfiguration(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuntimeIOMValidConfigurationTests(),
	})
}

func TestCloudSecurityCustomRuleResource_CSPM_IOM_RequiredFields(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateCSPMIOMRequiredFieldsTests(),
	})
}

func TestCloudSecurityCustomRuleResource_NewFields_BackwardCompatibility(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateNewFieldsBackwardCompatibilityTests(),
	})
}

// Azure Tests.
func TestCloudSecurityCustomRuleResource_Azure_Copy(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleCopyTests(azureCopyConfig, "Azure"),
	})
}

func TestCloudSecurityCustomRuleResource_Azure_Rego(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleLogicTests(azureCopyConfig, "Azure_Rego"),
	})
}

func TestCloudSecurityCustomRuleResource_Azure_Minimal(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateMinimalRuleCopyTests(azureCopyConfig, "Azure_Min"),
	})
}

func TestCloudSecurityCustomRuleResource_Azure_MinimalRego(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateMinimalRuleLogicTests(azureCopyConfig, "Azure_Min_Rego"),
	})
}

func TestCloudSecurityCustomRuleResource_Azure_DefinedToOmitted(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleCopyDefinedToOmittedTests(azureCopyConfig, "Azure_Omit"),
	})
}

func TestCloudSecurityCustomRuleResource_Azure_RegoDefinedToOmitted(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleRegoDefinedToOmittedTests(azureCopyConfig, "Azure_Omit_Rego"),
	})
}

func TestCloudSecurityCustomRuleResource_Azure_RegoDefinedToEmpty(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleRegoDefinedToEmptyTests(azureCopyConfig, "Azure_Empty_Rego"),
	})
}

func TestCloudSecurityCustomRuleResource_Azure_CopyDefinedToEmpty(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleCopyDefinedToEmptyTests(azureCopyConfig),
	})
}

func TestCloudSecurityCustomRuleResource_Azure_CopyDefinedAttackType(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleCopyDefinedAttackTypeTests(azureCopyConfig),
	})
}

func TestCloudSecurityCustomRuleResource_Azure_CopyInheritToEmptyToInherit(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleCopyInheritToEmptyToInheritTests(azureCopyConfig, "Azure_InheritCycle"),
	})
}

func TestCloudSecurityCustomRuleResource_Azure_CopyEmptyOnCreate(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleCopyEmptyOnCreateTests(azureCopyConfig, "Azure_EmptyCreate"),
	})
}

// GCP Tests.
func TestCloudSecurityCustomRuleResource_GCP_Copy(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleCopyTests(gcpCopyConfig, "GCP"),
	})
}

func TestCloudSecurityCustomRuleResource_GCP_Rego(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleLogicTests(gcpCopyConfig, "GCP_Rego"),
	})
}

func TestCloudSecurityCustomRuleResource_GCP_Minimal(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateMinimalRuleCopyTests(gcpCopyConfig, "GCP_Min"),
	})
}

func TestCloudSecurityCustomRuleResource_GCP_MinimalRego(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateMinimalRuleLogicTests(gcpCopyConfig, "GCP_Min_Rego"),
	})
}

func TestCloudSecurityCustomRuleResource_GCP_DefinedToOmitted(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleCopyDefinedToOmittedTests(gcpCopyConfig, "GCP_Omit"),
	})
}

func TestCloudSecurityCustomRuleResource_GCP_RegoDefinedToOmitted(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleRegoDefinedToOmittedTests(gcpCopyConfig, "GCP_Omit_Rego"),
	})
}

func TestCloudSecurityCustomRuleResource_GCP_RegoDefinedToEmpty(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleRegoDefinedToEmptyTests(gcpCopyConfig, "GCP_Empty_Rego"),
	})
}

func TestCloudSecurityCustomRuleResource_GCP_CopyDefinedToEmpty(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleCopyDefinedToEmptyTests(gcpCopyConfig),
	})
}

func TestCloudSecurityCustomRuleResource_GCP_CopyDefinedAttackType(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleCopyDefinedAttackTypeTests(gcpCopyConfig),
	})
}

func TestCloudSecurityCustomRuleResource_GCP_CopyInheritToEmptyToInherit(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleCopyInheritToEmptyToInheritTests(gcpCopyConfig, "GCP_InheritCycle"),
	})
}

func TestCloudSecurityCustomRuleResource_GCP_CopyEmptyOnCreate(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleCopyEmptyOnCreateTests(gcpCopyConfig, "GCP_EmptyCreate"),
	})
}

// In-place updates of user defined remediation_info, alert_info, and controls for duplicate rules.
func generateRuleCopyTests(config ruleCustomConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	randomSuffix := sdkacctest.RandString(8)
	ruleName = fmt.Sprintf("tfacc_%s_%s", ruleName, randomSuffix)
	resourceName := "crowdstrike_cloud_security_custom_rule.rule" + "_" + ruleName

	for i := range 2 {
		alertInfo := strings.Join([]string{
			`"` + strings.Join(config.alertInfo[i], `","`) + `"`,
		}, "")
		remediationInfo := strings.Join([]string{
			`"` + strings.Join(config.remediationInfo[i], `","`) + `"`,
		}, "")
		resourceStep := resource.TestStep{
			Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "rule_%s" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  severity         = "%s"
  remediation_info = [%s]
  controls = [
    %s
  ]
  alert_info     = [%s]
  parent_rule_id = one(data.crowdstrike_cloud_security_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_security_rules" "rule_%[1]s" {
  rule_name = "%[10]s"
  benchmark = "%[11]s"
}
`, ruleName, config.resourceType, config.ruleNamePrefix+ruleName, config.description[i],
				config.cloudProvider, config.severity[i], remediationInfo,
				testGenerateControlBlock(config.controls[i]), alertInfo,
				config.parentRule.ruleName, config.parentRule.benchmark),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(resourceName, "subdomain", config.subdomain),
				resource.TestCheckResourceAttr(resourceName, "domain", config.domain),
				resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
				resource.TestCheckResourceAttr(resourceName, "name", config.ruleNamePrefix+ruleName),
				resource.TestCheckResourceAttr(resourceName, "description", config.description[i]),
				resource.TestCheckResourceAttr(resourceName, "cloud_platform", config.cloudPlatform),
				resource.TestCheckResourceAttr(resourceName, "cloud_provider", config.cloudProvider),
				resource.TestCheckResourceAttr(resourceName, "severity", config.severity[i]),
				resource.TestCheckResourceAttr(resourceName, "controls.0.authority", config.ruleBaseConfig.controls[i].authority),
				resource.TestCheckResourceAttr(resourceName, "controls.0.code", config.ruleBaseConfig.controls[i].code),
				resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("alert_info.%d", len(config.alertInfo[i])-1), config.alertInfo[i][len(config.alertInfo[i])-1]),
				resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("remediation_info.%d", len(config.remediationInfo[i])-1), config.remediationInfo[i][len(config.remediationInfo[i])-1]),
				resource.TestCheckResourceAttrSet(resourceName, "id"),
				resource.TestCheckResourceAttrSet(resourceName, "parent_rule_id"),
			),
		}

		importTestStep := resource.TestStep{
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
		}

		steps = append(steps, resourceStep)
		steps = append(steps, importTestStep)
	}

	return steps
}

// In-place updates of user defined remediation_info, alert_info, controls, and attack_types.
func generateRuleLogicTests(config ruleCustomConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	randomSuffix := sdkacctest.RandString(8)
	ruleName = fmt.Sprintf("tfacc_%s_%s", ruleName, randomSuffix)
	resourceName := "crowdstrike_cloud_security_custom_rule.rule" + "_" + ruleName

	for i := range 2 {
		alertInfo := strings.Join([]string{
			`"` + strings.Join(config.alertInfo[i], `","`) + `"`,
		}, "")
		remediationInfo := strings.Join([]string{
			`"` + strings.Join(config.remediationInfo[i], `","`) + `"`,
		}, "")
		attackTypes := strings.Join([]string{
			`"` + strings.Join(config.attackTypes[i], `","`) + `"`,
		}, "")
		resourceStep := resource.TestStep{
			Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "rule_%s" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  severity         = "%s"
  remediation_info = [%s]
  logic = <<EOF
%s
EOF
  alert_info = [%s]
  controls = [
    %s
  ]
  attack_types = [%s]
}
`, ruleName, config.resourceType, config.ruleNamePrefix+ruleName, config.description[i],
				config.cloudProvider, config.severity[i], remediationInfo, config.logic[i],
				alertInfo, testGenerateControlBlock(config.controls[i]), attackTypes),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(resourceName, "subdomain", config.subdomain),
				resource.TestCheckResourceAttr(resourceName, "domain", config.domain),
				resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
				resource.TestCheckResourceAttr(resourceName, "name", config.ruleNamePrefix+ruleName),
				resource.TestCheckResourceAttr(resourceName, "description", config.description[i]),
				resource.TestCheckResourceAttr(resourceName, "cloud_platform", config.cloudPlatform),
				resource.TestCheckResourceAttr(resourceName, "cloud_provider", config.cloudProvider),
				resource.TestCheckResourceAttr(resourceName, "severity", config.severity[i]),
				resource.TestCheckResourceAttr(resourceName, "logic", config.logic[i]+"\n"),
				resource.TestCheckResourceAttr(resourceName, "controls.0.authority", config.ruleBaseConfig.controls[i].authority),
				resource.TestCheckResourceAttr(resourceName, "controls.0.code", config.ruleBaseConfig.controls[i].code),
				resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("alert_info.%d", len(config.alertInfo[i])-1), config.alertInfo[i][len(config.alertInfo[i])-1]),
				resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("remediation_info.%d", len(config.remediationInfo[i])-1), config.remediationInfo[i][len(config.remediationInfo[i])-1]),
				resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("attack_types.%d", len(config.attackTypes[i])-1), config.attackTypes[i][len(config.attackTypes[i])-1]),
				resource.TestCheckResourceAttrSet(resourceName, "id"),
			),
		}

		importTestStep := resource.TestStep{
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
		}

		steps = append(steps, resourceStep)
		steps = append(steps, importTestStep)

	}

	return steps
}

// Minimum configuration for duplicate rules.
func generateMinimalRuleCopyTests(config ruleCustomConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	randomSuffix := sdkacctest.RandString(8)
	ruleName = fmt.Sprintf("tfacc_%s_%s", ruleName, randomSuffix)
	resourceName := "crowdstrike_cloud_security_custom_rule.rule" + "_" + ruleName

	for i := range 2 {
		newStep := resource.TestStep{
			Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "rule_%s" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  parent_rule_id   = one(data.crowdstrike_cloud_security_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_security_rules" "rule_%[1]s" {
  rule_name = "%[6]s"
  benchmark = "%[7]s"
}
`, ruleName, config.resourceType, config.ruleNamePrefix+ruleName, config.description[i],
				config.cloudProvider, config.parentRule.ruleName, config.parentRule.benchmark),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(resourceName, "subdomain", config.subdomain),
				resource.TestCheckResourceAttr(resourceName, "domain", config.domain),
				resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
				resource.TestCheckResourceAttr(resourceName, "name", config.ruleNamePrefix+ruleName),
				resource.TestCheckResourceAttr(resourceName, "description", config.description[i]),
				resource.TestCheckResourceAttr(resourceName, "cloud_platform", config.cloudPlatform),
				resource.TestCheckResourceAttr(resourceName, "cloud_provider", config.cloudProvider),
				resource.TestMatchResourceAttr(resourceName, "controls.#", regexp.MustCompile(`^[1-9]\d*$`)),
				resource.TestMatchResourceAttr(resourceName, "alert_info.#", regexp.MustCompile(`^[1-9]\d*$`)),
				resource.TestMatchResourceAttr(resourceName, "remediation_info.#", regexp.MustCompile(`^[1-9]\d*$`)),
				resource.TestCheckResourceAttrSet(resourceName, "id"),
				resource.TestCheckResourceAttrSet(resourceName, "parent_rule_id"),
				resource.TestCheckResourceAttrSet(resourceName, "severity"),
			),
		}
		steps = append(steps, newStep)
	}

	return steps
}

// Minimum configuration for rego rules.
func generateMinimalRuleLogicTests(config ruleCustomConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	randomSuffix := sdkacctest.RandString(8)
	ruleName = fmt.Sprintf("tfacc_%s_%s", ruleName, randomSuffix)
	resourceName := "crowdstrike_cloud_security_custom_rule.rule" + "_" + ruleName

	for i := range 2 {
		resourceStep := resource.TestStep{
			Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "rule_%s" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  logic = <<EOF
%s
EOF
}
`, ruleName, config.resourceType, config.ruleNamePrefix+ruleName, config.description[i],
				config.cloudProvider, config.logic[i]),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(resourceName, "subdomain", config.subdomain),
				resource.TestCheckResourceAttr(resourceName, "domain", config.domain),
				resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
				resource.TestCheckResourceAttr(resourceName, "name", config.ruleNamePrefix+ruleName),
				resource.TestCheckResourceAttr(resourceName, "description", config.description[i]),
				resource.TestCheckResourceAttr(resourceName, "cloud_platform", config.cloudPlatform),
				resource.TestCheckResourceAttr(resourceName, "cloud_provider", config.cloudProvider),
				resource.TestCheckResourceAttr(resourceName, "logic", config.logic[i]+"\n"),
				resource.TestCheckResourceAttrSet(resourceName, "id"),
				resource.TestCheckResourceAttrSet(resourceName, "severity"),
			),
		}

		importTestStep := resource.TestStep{
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
		}

		steps = append(steps, resourceStep)
		steps = append(steps, importTestStep)
	}

	return steps
}

// Ensure duplicate rules will inherit fields from parent when fields are omitted in-place.
func generateRuleCopyDefinedToOmittedTests(config ruleCustomConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	randomSuffix := sdkacctest.RandString(8)
	ruleName = fmt.Sprintf("tfacc_%s_%s", ruleName, randomSuffix)
	resourceName := "crowdstrike_cloud_security_custom_rule.rule" + "_" + ruleName + "_definedToOmitted"

	alertInfo := strings.Join([]string{
		`"` + strings.Join(config.alertInfo[0], `","`) + `"`,
	}, "")
	remediationInfo := strings.Join([]string{
		`"` + strings.Join(config.remediationInfo[0], `","`) + `"`,
	}, "")

	definedStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "rule_%s_definedToOmitted" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  severity         = "%s"
  remediation_info = [%s]
  controls = [
    %s
  ]
  alert_info       = [%s]
  parent_rule_id   = one(data.crowdstrike_cloud_security_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_security_rules" "rule_%[1]s" {
  rule_name = "%[10]s"
  benchmark = "%[11]s"
}
`, ruleName, config.resourceType, config.ruleNamePrefix+ruleName, config.description[0],
			config.cloudProvider, config.severity[0], remediationInfo,
			testGenerateControlBlock(config.controls[0]), alertInfo,
			config.parentRule.ruleName, config.parentRule.benchmark),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(resourceName, "subdomain", config.subdomain),
			resource.TestCheckResourceAttr(resourceName, "domain", config.domain),
			resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(resourceName, "name", config.ruleNamePrefix+ruleName),
			resource.TestCheckResourceAttr(resourceName, "description", config.description[0]),
			resource.TestCheckResourceAttr(resourceName, "cloud_platform", config.cloudPlatform),
			resource.TestCheckResourceAttr(resourceName, "cloud_provider", config.cloudProvider),
			resource.TestCheckResourceAttr(resourceName, "severity", config.severity[0]),
			resource.TestCheckResourceAttr(resourceName, "controls.0.authority", config.ruleBaseConfig.controls[0].authority),
			resource.TestCheckResourceAttr(resourceName, "controls.0.code", config.ruleBaseConfig.controls[0].code),
			resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("alert_info.%d", len(config.alertInfo[0])-1), config.alertInfo[0][len(config.alertInfo[0])-1]),
			resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("remediation_info.%d", len(config.remediationInfo[0])-1), config.remediationInfo[0][len(config.remediationInfo[0])-1]),
			resource.TestCheckResourceAttrSet(resourceName, "id"),
			resource.TestCheckResourceAttrSet(resourceName, "parent_rule_id"),
		),
	}

	undefinedStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "rule_%s_definedToOmitted" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  severity         = "%s"
  parent_rule_id   = one(data.crowdstrike_cloud_security_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_security_rules" "rule_%[1]s" {
  rule_name = "%[7]s"
  benchmark = "%[8]s"
}
`, ruleName, config.resourceType, config.ruleNamePrefix+ruleName, config.description[0],
			config.cloudProvider, config.severity[0], config.parentRule.ruleName, config.parentRule.benchmark),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(resourceName, "subdomain", config.subdomain),
			resource.TestCheckResourceAttr(resourceName, "domain", config.domain),
			resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(resourceName, "name", config.ruleNamePrefix+ruleName),
			resource.TestCheckResourceAttr(resourceName, "description", config.description[0]),
			resource.TestCheckResourceAttr(resourceName, "cloud_platform", config.cloudPlatform),
			resource.TestCheckResourceAttr(resourceName, "cloud_provider", config.cloudProvider),
			resource.TestCheckResourceAttr(resourceName, "severity", config.severity[0]),
			resource.TestMatchResourceAttr(resourceName, "controls.#", regexp.MustCompile(`^[1-9]\d*$`)),
			resource.TestMatchResourceAttr(resourceName, "alert_info.#", regexp.MustCompile(`^[1-9]\d*$`)),
			resource.TestMatchResourceAttr(resourceName, "remediation_info.#", regexp.MustCompile(`^[1-9]\d*$`)),
			resource.TestCheckResourceAttrSet(resourceName, "id"),
			resource.TestCheckResourceAttrSet(resourceName, "parent_rule_id"),
		),
	}

	steps = append(steps, definedStep)
	steps = append(steps, undefinedStep)

	return steps
}

// Duplicate rules can only be set to empty on update.
func generateRuleCopyDefinedToEmptyTests(config ruleCustomConfig) []resource.TestStep {
	var steps []resource.TestStep
	randomSuffix := sdkacctest.RandString(8)
	resourceName := fmt.Sprintf("tfacc_definedToEmptyCopyRule_%s", randomSuffix)
	fullResourceName := fmt.Sprintf("crowdstrike_cloud_security_custom_rule.%s", resourceName)

	alertInfo := strings.Join([]string{
		`"` + strings.Join(config.alertInfo[0], `","`) + `"`,
	}, "")
	remediationInfo := strings.Join([]string{
		`"` + strings.Join(config.remediationInfo[0], `","`) + `"`,
	}, "")

	definedStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "%s" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  severity         = "%s"
  remediation_info = [%s]
  controls = [
    %s
  ]
  alert_info     = [%s]
  parent_rule_id = one(data.crowdstrike_cloud_security_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_security_rules" "rule_%[1]s" {
  rule_name = "%[10]s"
  benchmark = "%[11]s"
}
`, resourceName, config.resourceType, config.ruleNamePrefix+resourceName, config.description[0],
			config.cloudProvider, config.severity[0], remediationInfo,
			testGenerateControlBlock(config.controls[0]), alertInfo,
			config.parentRule.ruleName, config.parentRule.benchmark),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(fullResourceName, "subdomain", config.subdomain),
			resource.TestCheckResourceAttr(fullResourceName, "domain", config.domain),
			resource.TestCheckResourceAttr(fullResourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(fullResourceName, "name", config.ruleNamePrefix+resourceName),
			resource.TestCheckResourceAttr(fullResourceName, "description", config.description[0]),
			resource.TestCheckResourceAttr(fullResourceName, "cloud_platform", config.cloudPlatform),
			resource.TestCheckResourceAttr(fullResourceName, "cloud_provider", config.cloudProvider),
			resource.TestCheckResourceAttr(fullResourceName, "severity", config.severity[0]),
			resource.TestCheckResourceAttr(fullResourceName, "controls.0.authority", config.ruleBaseConfig.controls[0].authority),
			resource.TestCheckResourceAttr(fullResourceName, "controls.0.code", config.ruleBaseConfig.controls[0].code),
			resource.TestCheckResourceAttr(fullResourceName, fmt.Sprintf("alert_info.%d", len(config.alertInfo[0])-1), config.alertInfo[0][len(config.alertInfo[0])-1]),
			resource.TestCheckResourceAttr(fullResourceName, fmt.Sprintf("remediation_info.%d", len(config.remediationInfo[0])-1), config.remediationInfo[0][len(config.remediationInfo[0])-1]),
			resource.TestCheckResourceAttrSet(fullResourceName, "id"),
			resource.TestCheckResourceAttrSet(fullResourceName, "parent_rule_id"),
		),
	}

	undefinedStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "%s" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  severity         = "%s"
  controls         = []
  remediation_info = []
  alert_info       = []
  parent_rule_id   = one(data.crowdstrike_cloud_security_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_security_rules" "rule_%[1]s" {
  rule_name = "%[9]s"
  benchmark = "%[10]s"
}
`, resourceName, config.resourceType, config.ruleNamePrefix+resourceName, config.description[0],
			config.cloudProvider, config.severity[0], testGenerateControlBlock(config.controls[0]),
			remediationInfo, config.parentRule.ruleName, config.parentRule.benchmark),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(fullResourceName, "subdomain", config.subdomain),
			resource.TestCheckResourceAttr(fullResourceName, "domain", config.domain),
			resource.TestCheckResourceAttr(fullResourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(fullResourceName, "name", config.ruleNamePrefix+resourceName),
			resource.TestCheckResourceAttr(fullResourceName, "description", config.description[0]),
			resource.TestCheckResourceAttr(fullResourceName, "cloud_platform", config.cloudPlatform),
			resource.TestCheckResourceAttr(fullResourceName, "cloud_provider", config.cloudProvider),
			resource.TestCheckResourceAttr(fullResourceName, "severity", config.severity[0]),
			resource.TestCheckResourceAttr(fullResourceName, "controls.#", "0"),
			resource.TestCheckResourceAttr(fullResourceName, "alert_info.#", "0"),
			resource.TestCheckResourceAttr(fullResourceName, "remediation_info.#", "0"),
			resource.TestCheckResourceAttrSet(fullResourceName, "id"),
			resource.TestCheckResourceAttrSet(fullResourceName, "parent_rule_id"),
		),
	}

	steps = append(steps, definedStep)
	steps = append(steps, undefinedStep)

	// Required config to perform deletion after test
	steps = append(steps, definedStep)

	return steps
}

// Validating fields set to empty when omitted in-place.
func generateRuleRegoDefinedToOmittedTests(config ruleCustomConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	randomSuffix := sdkacctest.RandString(8)
	ruleName = fmt.Sprintf("tfacc_%s_%s", ruleName, randomSuffix)
	resourceName := "crowdstrike_cloud_security_custom_rule.rule" + "_" + ruleName + "_definedToOmitted"

	alertInfo := strings.Join([]string{
		`"` + strings.Join(config.alertInfo[0], `","`) + `"`,
	}, "")
	remediationInfo := strings.Join([]string{
		`"` + strings.Join(config.remediationInfo[0], `","`) + `"`,
	}, "")

	definedStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "rule_%s_definedToOmitted" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  severity         = "%s"
  remediation_info = [%s]
  controls = [
    %s
  ]
  alert_info = [%s]
  logic = <<EOF
%s
EOF
}
`, ruleName, config.resourceType, config.ruleNamePrefix+ruleName, config.description[0],
			config.cloudProvider, config.severity[0], remediationInfo,
			testGenerateControlBlock(config.controls[0]), alertInfo, config.logic[0]),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(resourceName, "subdomain", config.subdomain),
			resource.TestCheckResourceAttr(resourceName, "domain", config.domain),
			resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(resourceName, "name", config.ruleNamePrefix+ruleName),
			resource.TestCheckResourceAttr(resourceName, "description", config.description[0]),
			resource.TestCheckResourceAttr(resourceName, "cloud_platform", config.cloudPlatform),
			resource.TestCheckResourceAttr(resourceName, "cloud_provider", config.cloudProvider),
			resource.TestCheckResourceAttr(resourceName, "severity", config.severity[0]),
			resource.TestCheckResourceAttr(resourceName, "logic", config.logic[0]+"\n"),
			resource.TestCheckResourceAttr(resourceName, "controls.0.authority", config.ruleBaseConfig.controls[0].authority),
			resource.TestCheckResourceAttr(resourceName, "controls.0.code", config.ruleBaseConfig.controls[0].code),
			resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("alert_info.%d", len(config.alertInfo[0])-1), config.alertInfo[0][len(config.alertInfo[0])-1]),
			resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("remediation_info.%d", len(config.remediationInfo[0])-1), config.remediationInfo[0][len(config.remediationInfo[0])-1]),
			resource.TestCheckResourceAttrSet(resourceName, "id"),
		),
	}

	undefinedStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "rule_%s_definedToOmitted" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  severity         = "%s"
  logic = <<EOF
%s
EOF
}
`, ruleName, config.resourceType, config.ruleNamePrefix+ruleName, config.description[0],
			config.cloudProvider, config.severity[0], config.logic[0]),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(resourceName, "subdomain", config.subdomain),
			resource.TestCheckResourceAttr(resourceName, "domain", config.domain),
			resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(resourceName, "name", config.ruleNamePrefix+ruleName),
			resource.TestCheckResourceAttr(resourceName, "description", config.description[0]),
			resource.TestCheckResourceAttr(resourceName, "cloud_platform", config.cloudPlatform),
			resource.TestCheckResourceAttr(resourceName, "cloud_provider", config.cloudProvider),
			resource.TestCheckResourceAttr(resourceName, "severity", config.severity[0]),
			resource.TestCheckResourceAttr(resourceName, "logic", config.logic[0]+"\n"),
			resource.TestCheckResourceAttr(resourceName, "controls.#", "0"),
			resource.TestCheckResourceAttr(resourceName, "alert_info.#", "0"),
			resource.TestCheckResourceAttr(resourceName, "remediation_info.#", "0"),
			resource.TestCheckResourceAttrSet(resourceName, "id"),
		),
	}

	steps = append(steps, definedStep)
	steps = append(steps, undefinedStep)

	return steps
}

// Validating fields set to empty when set to empty list/set in-place.
func generateRuleRegoDefinedToEmptyTests(config ruleCustomConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	randomSuffix := sdkacctest.RandString(8)
	ruleName = fmt.Sprintf("tfacc_%s_%s", ruleName, randomSuffix)
	resourceName := "crowdstrike_cloud_security_custom_rule.rule" + "_" + ruleName + "_definedToEmpty"

	alertInfo := strings.Join([]string{
		`"` + strings.Join(config.alertInfo[0], `","`) + `"`,
	}, "")
	remediationInfo := strings.Join([]string{
		`"` + strings.Join(config.remediationInfo[0], `","`) + `"`,
	}, "")

	definedStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "rule_%s_definedToEmpty" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  severity         = "%s"
  remediation_info = [%s]
  controls = [
    %s
  ]
  alert_info = [%s]
  logic = <<EOF
%s
EOF
}
`, ruleName, config.resourceType, config.ruleNamePrefix+ruleName, config.description[0],
			config.cloudProvider, config.severity[0], remediationInfo,
			testGenerateControlBlock(config.controls[0]), alertInfo, config.logic[0]),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(resourceName, "subdomain", config.subdomain),
			resource.TestCheckResourceAttr(resourceName, "domain", config.domain),
			resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(resourceName, "name", config.ruleNamePrefix+ruleName),
			resource.TestCheckResourceAttr(resourceName, "description", config.description[0]),
			resource.TestCheckResourceAttr(resourceName, "cloud_platform", config.cloudPlatform),
			resource.TestCheckResourceAttr(resourceName, "cloud_provider", config.cloudProvider),
			resource.TestCheckResourceAttr(resourceName, "severity", config.severity[0]),
			resource.TestCheckResourceAttr(resourceName, "logic", config.logic[0]+"\n"),
			resource.TestCheckResourceAttr(resourceName, "controls.0.authority", config.ruleBaseConfig.controls[0].authority),
			resource.TestCheckResourceAttr(resourceName, "controls.0.code", config.ruleBaseConfig.controls[0].code),
			resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("alert_info.%d", len(config.alertInfo[0])-1), config.alertInfo[0][len(config.alertInfo[0])-1]),
			resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("remediation_info.%d", len(config.remediationInfo[0])-1), config.remediationInfo[0][len(config.remediationInfo[0])-1]),
			resource.TestCheckResourceAttrSet(resourceName, "id"),
		),
	}

	undefinedStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "rule_%s_definedToEmpty" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  severity         = "%s"
  logic = <<EOF
%s
EOF
  controls         = []
  alert_info       = []
  remediation_info = []
}
`, ruleName, config.resourceType, config.ruleNamePrefix+ruleName, config.description[0],
			config.cloudProvider, config.severity[0], config.logic[0]),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(resourceName, "subdomain", config.subdomain),
			resource.TestCheckResourceAttr(resourceName, "domain", config.domain),
			resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(resourceName, "name", config.ruleNamePrefix+ruleName),
			resource.TestCheckResourceAttr(resourceName, "description", config.description[0]),
			resource.TestCheckResourceAttr(resourceName, "cloud_platform", config.cloudPlatform),
			resource.TestCheckResourceAttr(resourceName, "cloud_provider", config.cloudProvider),
			resource.TestCheckResourceAttr(resourceName, "severity", config.severity[0]),
			resource.TestCheckResourceAttr(resourceName, "logic", config.logic[0]+"\n"),
			resource.TestCheckResourceAttr(resourceName, "controls.#", "0"),
			resource.TestCheckResourceAttr(resourceName, "alert_info.#", "0"),
			resource.TestCheckResourceAttr(resourceName, "remediation_info.#", "0"),
			resource.TestCheckResourceAttrSet(resourceName, "id"),
		),
	}

	steps = append(steps, definedStep)
	steps = append(steps, undefinedStep)

	return steps
}

// Validate attack_types cannot be set for duplicate rules.
func generateRuleCopyDefinedAttackTypeTests(config ruleCustomConfig) []resource.TestStep {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := fmt.Sprintf("tfacc_definedToEmptyAttackTypesCopyRule_%s", randomSuffix)

	alertInfo := strings.Join([]string{
		`"` + strings.Join(config.alertInfo[0], `","`) + `"`,
	}, "")
	remediationInfo := strings.Join([]string{
		`"` + strings.Join(config.remediationInfo[0], `","`) + `"`,
	}, "")

	return []resource.TestStep{
		{
			Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "%s" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  severity         = "%s"
  remediation_info = [%s]
  controls = [
    %s
  ]
  alert_info     = [%s]
  attack_types   = ["test"]
  parent_rule_id = one(data.crowdstrike_cloud_security_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_security_rules" "rule_%[1]s" {
  rule_name = "%[10]s"
  benchmark = "%[11]s"
}
`, resourceName, config.resourceType, config.ruleNamePrefix+resourceName, config.description[0],
				config.cloudProvider, config.severity[0], remediationInfo,
				testGenerateControlBlock(config.controls[0]), alertInfo,
				config.parentRule.ruleName, config.parentRule.benchmark),
			ExpectError: regexp.MustCompile(
				"Invalid Attribute Combination",
			),
			PlanOnly: true,
		},
	}
}

func testGenerateControlBlock(c control) string {
	return fmt.Sprintf(`
    {
		authority = "%s"
		code = "%s"
	}
	`, c.authority, c.code)
}

// Test inheritance cycle: inherit from parent -> set to empty -> inherit from parent again.
func generateRuleCopyInheritToEmptyToInheritTests(config ruleCustomConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	randomSuffix := sdkacctest.RandString(8)
	ruleName = fmt.Sprintf("tfacc_%s_%s", ruleName, randomSuffix)
	resourceName := "crowdstrike_cloud_security_custom_rule.rule" + "_" + ruleName

	// Step 1: Create minimal copy rule - should inherit controls, remediation_info, and alert_info from parent
	inheritStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "rule_%s" {
  resource_type  = "%s"
  name           = "%s"
  description    = "%s - Step 1"
  cloud_provider = "%s"
  severity       = "%s"
  parent_rule_id = one(data.crowdstrike_cloud_security_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_security_rules" "rule_%[1]s" {
  rule_name = "%[7]s"
  benchmark = "%[8]s"
}
`, ruleName, config.resourceType, config.ruleNamePrefix+ruleName,
			config.description[0], config.cloudProvider, config.severity[0],
			config.parentRule.ruleName, config.parentRule.benchmark),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(resourceName, "subdomain", config.subdomain),
			resource.TestCheckResourceAttr(resourceName, "domain", config.domain),
			resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(resourceName, "name", config.ruleNamePrefix+ruleName),
			resource.TestCheckResourceAttr(resourceName, "description", config.description[0]+" - Step 1"),
			resource.TestCheckResourceAttr(resourceName, "cloud_platform", config.cloudPlatform),
			resource.TestCheckResourceAttr(resourceName, "cloud_provider", config.cloudProvider),
			resource.TestCheckResourceAttr(resourceName, "severity", config.severity[0]),
			resource.TestMatchResourceAttr(resourceName, "controls.#", regexp.MustCompile(`^[1-9]\d*$`)),         // Should have inherited controls
			resource.TestMatchResourceAttr(resourceName, "alert_info.#", regexp.MustCompile(`^[1-9]\d*$`)),       // Should have inherited alert_info
			resource.TestMatchResourceAttr(resourceName, "remediation_info.#", regexp.MustCompile(`^[1-9]\d*$`)), // Should have inherited remediation_info
			resource.TestCheckResourceAttrSet(resourceName, "id"),
			resource.TestCheckResourceAttrSet(resourceName, "parent_rule_id"),
		),
	}

	// Step 2: Set all fields to empty arrays - should override inherited values
	emptyStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "rule_%s" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s - Step 2"
  cloud_provider   = "%s"
  severity         = "%s"
  controls         = []
  remediation_info = []
  alert_info       = []
  parent_rule_id   = one(data.crowdstrike_cloud_security_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_security_rules" "rule_%[1]s" {
  rule_name = "%[7]s"
  benchmark = "%[8]s"
}
`, ruleName, config.resourceType, config.ruleNamePrefix+ruleName,
			config.description[0], config.cloudProvider, config.severity[0],
			config.parentRule.ruleName, config.parentRule.benchmark),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(resourceName, "subdomain", config.subdomain),
			resource.TestCheckResourceAttr(resourceName, "domain", config.domain),
			resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(resourceName, "name", config.ruleNamePrefix+ruleName),
			resource.TestCheckResourceAttr(resourceName, "description", config.description[0]+" - Step 2"),
			resource.TestCheckResourceAttr(resourceName, "cloud_platform", config.cloudPlatform),
			resource.TestCheckResourceAttr(resourceName, "cloud_provider", config.cloudProvider),
			resource.TestCheckResourceAttr(resourceName, "severity", config.severity[0]),
			resource.TestCheckResourceAttr(resourceName, "controls.#", "0"),         // Should be empty
			resource.TestCheckResourceAttr(resourceName, "alert_info.#", "0"),       // Should be empty
			resource.TestCheckResourceAttr(resourceName, "remediation_info.#", "0"), // Should be empty
			resource.TestCheckResourceAttrSet(resourceName, "id"),
			resource.TestCheckResourceAttrSet(resourceName, "parent_rule_id"),
		),
	}

	// Step 3: Remove the explicit fields - should inherit from parent again
	inheritAgainStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "rule_%s" {
  resource_type  = "%s"
  name           = "%s"
  description    = "%s - Step 3"
  cloud_provider = "%s"
  severity       = "%s"
  parent_rule_id = one(data.crowdstrike_cloud_security_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_security_rules" "rule_%[1]s" {
  rule_name = "%[7]s"
  benchmark = "%[8]s"
}
`, ruleName, config.resourceType, config.ruleNamePrefix+ruleName,
			config.description[0], config.cloudProvider, config.severity[0],
			config.parentRule.ruleName, config.parentRule.benchmark),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(resourceName, "subdomain", config.subdomain),
			resource.TestCheckResourceAttr(resourceName, "domain", config.domain),
			resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(resourceName, "name", config.ruleNamePrefix+ruleName),
			resource.TestCheckResourceAttr(resourceName, "description", config.description[0]+" - Step 3"),
			resource.TestCheckResourceAttr(resourceName, "cloud_platform", config.cloudPlatform),
			resource.TestCheckResourceAttr(resourceName, "cloud_provider", config.cloudProvider),
			resource.TestCheckResourceAttr(resourceName, "severity", config.severity[0]),
			resource.TestMatchResourceAttr(resourceName, "controls.#", regexp.MustCompile(`^[1-9]\d*$`)),         // Should have inherited controls again
			resource.TestMatchResourceAttr(resourceName, "alert_info.#", regexp.MustCompile(`^[1-9]\d*$`)),       // Should have inherited alert_info again
			resource.TestMatchResourceAttr(resourceName, "remediation_info.#", regexp.MustCompile(`^[1-9]\d*$`)), // Should have inherited remediation_info again
			resource.TestCheckResourceAttrSet(resourceName, "id"),
			resource.TestCheckResourceAttrSet(resourceName, "parent_rule_id"),
		),
	}

	steps = append(steps, inheritStep)
	steps = append(steps, emptyStep)
	steps = append(steps, inheritAgainStep)

	return steps
}

// Test creating a rule with empty arrays from the start and verify no plan changes on refresh.
func generateRuleCopyEmptyOnCreateTests(config ruleCustomConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	randomSuffix := sdkacctest.RandString(8)
	ruleName = fmt.Sprintf("tfacc_%s_%s", ruleName, randomSuffix)
	resourceName := "crowdstrike_cloud_security_custom_rule.rule" + "_" + ruleName

	configStr := fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "rule_%s" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  severity         = "%s"
  controls         = []
  remediation_info = []
  alert_info       = []
  parent_rule_id   = one(data.crowdstrike_cloud_security_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_security_rules" "rule_%[1]s" {
  rule_name = "%[7]s"
  benchmark = "%[8]s"
}
`, ruleName, config.resourceType, config.ruleNamePrefix+ruleName,
		config.description[0], config.cloudProvider, config.severity[0],
		config.parentRule.ruleName, config.parentRule.benchmark)

	createStep := resource.TestStep{
		Config: configStr,
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(resourceName, "subdomain", config.subdomain),
			resource.TestCheckResourceAttr(resourceName, "domain", config.domain),
			resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(resourceName, "name", config.ruleNamePrefix+ruleName),
			resource.TestCheckResourceAttr(resourceName, "description", config.description[0]),
			resource.TestCheckResourceAttr(resourceName, "cloud_platform", config.cloudPlatform),
			resource.TestCheckResourceAttr(resourceName, "cloud_provider", config.cloudProvider),
			resource.TestCheckResourceAttr(resourceName, "severity", config.severity[0]),
			resource.TestCheckResourceAttr(resourceName, "controls.#", "0"),
			resource.TestCheckResourceAttr(resourceName, "alert_info.#", "0"),
			resource.TestCheckResourceAttr(resourceName, "remediation_info.#", "0"),
			resource.TestCheckResourceAttrSet(resourceName, "id"),
			resource.TestCheckResourceAttrSet(resourceName, "parent_rule_id"),
		),
	}

	refreshPlanStep := resource.TestStep{
		Config:             configStr,
		PlanOnly:           true,
		ExpectNonEmptyPlan: false,
	}

	importTestStep := resource.TestStep{
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
	}

	steps = append(steps, createStep)
	steps = append(steps, refreshPlanStep)
	steps = append(steps, importTestStep)

	return steps
}

// Test generator functions for Runtime/IOM field validation

// Test that validates fields are disabled for Runtime domain with IOM subdomain.
func generateRuntimeIOMDisabledFieldsTests() []resource.TestStep {
	randomSuffix := sdkacctest.RandString(8)

	// Test 1: Try to configure alert_info - should fail
	alertInfoStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "runtime_alert_info_%s" {
  name         = "Test Runtime Alert Info %s"
  description  = "Test rule with alert_info for Runtime/IOM"
  domain       = "Runtime"
  subdomain    = "IOM"
  alert_info   = ["This should fail"]
  logic = <<EOF
package crowdstrike
default result = "pass"
result = "fail" if {
    input.runtime.process.name == "test"
}
EOF
}
`, randomSuffix, randomSuffix),
		ExpectError: regexp.MustCompile("alert_info is not allowed when domain is 'Runtime' and subdomain is 'IOM'"),
		PlanOnly:    true,
	}

	// Test 2: Try to configure controls - should fail
	controlsStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "runtime_controls_%s" {
  name         = "Test Runtime Controls %s"
  description  = "Test rule with controls for Runtime/IOM"
  domain       = "Runtime"
  subdomain    = "IOM"
  controls = [
    {
      authority = "CIS"
      code      = "123"
    }
  ]
  logic = <<EOF
package crowdstrike
default result = "pass"
result = "fail" if {
    input.runtime.process.name == "test"
}
EOF
}
`, randomSuffix, randomSuffix),
		ExpectError: regexp.MustCompile("controls is not allowed when domain is 'Runtime' and subdomain is 'IOM'"),
		PlanOnly:    true,
	}

	// Test 3: Try to configure parent_rule_id - should fail
	parentRuleStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "runtime_parent_%s" {
  name           = "Test Runtime Parent Rule %s"
  description    = "Test rule with parent_rule_id for Runtime/IOM"
  domain         = "Runtime"
  subdomain      = "IOM"
  parent_rule_id = "0473a26b-7f29-43c7-9581-105f8c9c0b7d"
}
`, randomSuffix, randomSuffix),
		ExpectError: regexp.MustCompile("parent_rule_id is not allowed when domain is 'Runtime' and subdomain is 'IOM'"),
		PlanOnly:    true,
	}

	// Test 4: Try to configure resource_type - should fail
	resourceTypeStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "runtime_resource_type_%s" {
  name          = "Test Runtime Resource Type %s"
  description   = "Test rule with resource_type for Runtime/IOM"
  domain        = "Runtime"
  subdomain     = "IOM"
  resource_type = "AWS::EC2::Instance"
  logic = <<EOF
package crowdstrike
default result = "pass"
result = "fail" if {
    input.runtime.process.name == "test"
}
EOF
}
`, randomSuffix, randomSuffix),
		ExpectError: regexp.MustCompile("resource_type is not allowed when domain is 'Runtime' and subdomain is 'IOM'"),
		PlanOnly:    true,
	}

	return []resource.TestStep{alertInfoStep, controlsStep, parentRuleStep, resourceTypeStep}
}

// Test that validates a valid Runtime/IOM configuration works.
func generateRuntimeIOMValidConfigurationTests() []resource.TestStep {
	randomSuffix := sdkacctest.RandString(8)
	ruleName := fmt.Sprintf("tfacc_runtime_valid_%s", randomSuffix)
	resourceName := fmt.Sprintf("crowdstrike_cloud_security_custom_rule.%s", ruleName)

	validStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "%s" {
  name        = "Test Valid Runtime Rule %s"
  description = "Valid Runtime/IOM rule"
  domain      = "Runtime"
  subdomain   = "IOM"
  severity    = "high"
  logic = <<EOF
package crowdstrike
default result = "pass"
result = "fail" if {
    input.runtime.process.name == "malicious"
}
EOF
}
`, ruleName, randomSuffix),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(resourceName, "domain", "Runtime"),
			resource.TestCheckResourceAttr(resourceName, "subdomain", "IOM"),
			resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("Test Valid Runtime Rule %s", randomSuffix)),
			resource.TestCheckResourceAttr(resourceName, "description", "Valid Runtime/IOM rule"),
			resource.TestCheckResourceAttr(resourceName, "severity", "high"),
			resource.TestCheckResourceAttr(resourceName, "rule_provider", "Kubernetes"), // Should default to Kubernetes
			resource.TestCheckResourceAttr(resourceName, "rule_platform", "Kubernetes"), // Should default to Kubernetes
			resource.TestCheckResourceAttrSet(resourceName, "id"),
		),
	}

	return []resource.TestStep{validStep}
}

// Test that validates CSPM/IOM required fields.
func generateCSPMIOMRequiredFieldsTests() []resource.TestStep {
	randomSuffix := sdkacctest.RandString(8)

	// Test 1: Missing resource_type - should fail
	missingResourceTypeStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "cspm_missing_resource_type_%s" {
  name           = "Test CSPM Missing Resource Type %s"
  description    = "Test rule missing resource_type for CSPM/IOM"
  domain         = "CSPM"
  subdomain      = "IOM"
  rule_provider  = "AWS"
  logic = <<EOF
package crowdstrike
default result = "pass"
result = "fail" if {
    input.tags[_] == "test"
}
EOF
}
`, randomSuffix, randomSuffix),
		ExpectError: regexp.MustCompile("resource_type is required when domain is 'CSPM' and subdomain is 'IOM'"),
		PlanOnly:    true,
	}

	// Test 2: Missing rule_provider - should fail
	missingProviderStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "cspm_missing_provider_%s" {
  name          = "Test CSPM Missing Provider %s"
  description   = "Test rule missing rule_provider for CSPM/IOM"
  domain        = "CSPM"
  subdomain     = "IOM"
  resource_type = "AWS::EC2::Instance"
  logic = <<EOF
package crowdstrike
default result = "pass"
result = "fail" if {
    input.tags[_] == "test"
}
EOF
}
`, randomSuffix, randomSuffix),
		ExpectError: regexp.MustCompile(`(?s)rule_provider\s+\(or\s+deprecated\s+cloud_provider\)\s+is\s+required\s+when\s+domain\s+is\s+'CSPM'\s+and\s+subdomain\s+is\s+'IOM'`),
		PlanOnly:    true,
	}

	// Test 3: Valid CSPM/IOM configuration - should pass
	validStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "cspm_valid_%s" {
  name          = "Test Valid CSPM Rule %s"
  description   = "Valid CSPM/IOM rule"
  domain        = "CSPM"
  subdomain     = "IOM"
  resource_type = "AWS::EC2::Instance"
  rule_provider = "AWS"
  severity      = "critical"
  logic = <<EOF
package crowdstrike
default result = "pass"
result = "fail" if {
    input.tags[_] == "test"
}
EOF
}
`, randomSuffix, randomSuffix),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(fmt.Sprintf("crowdstrike_cloud_security_custom_rule.cspm_valid_%s", randomSuffix), "domain", "CSPM"),
			resource.TestCheckResourceAttr(fmt.Sprintf("crowdstrike_cloud_security_custom_rule.cspm_valid_%s", randomSuffix), "subdomain", "IOM"),
			resource.TestCheckResourceAttr(fmt.Sprintf("crowdstrike_cloud_security_custom_rule.cspm_valid_%s", randomSuffix), "resource_type", "AWS::EC2::Instance"),
			resource.TestCheckResourceAttr(fmt.Sprintf("crowdstrike_cloud_security_custom_rule.cspm_valid_%s", randomSuffix), "rule_provider", "AWS"),
			resource.TestCheckResourceAttrSet(fmt.Sprintf("crowdstrike_cloud_security_custom_rule.cspm_valid_%s", randomSuffix), "id"),
		),
	}

	return []resource.TestStep{missingResourceTypeStep, missingProviderStep, validStep}
}

// Test backward compatibility between new and deprecated fields.
func generateNewFieldsBackwardCompatibilityTests() []resource.TestStep {
	randomSuffix := sdkacctest.RandString(8)

	// Test 1: Using new fields (rule_provider, rule_platform)
	newFieldsStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "new_fields_%s" {
  name          = "Test New Fields %s"
  description   = "Test rule using new field names"
  domain        = "CSPM"
  subdomain     = "IOM"
  resource_type = "AWS::EC2::Instance"
  rule_provider = "AWS"
  rule_platform = "AWS"
  severity      = "high"
  logic = <<EOF
package crowdstrike
default result = "pass"
result = "fail" if {
    input.tags[_] == "test"
}
EOF
}
`, randomSuffix, randomSuffix),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(fmt.Sprintf("crowdstrike_cloud_security_custom_rule.new_fields_%s", randomSuffix), "rule_provider", "AWS"),
			resource.TestCheckResourceAttr(fmt.Sprintf("crowdstrike_cloud_security_custom_rule.new_fields_%s", randomSuffix), "rule_platform", "AWS"),
			resource.TestCheckResourceAttrSet(fmt.Sprintf("crowdstrike_cloud_security_custom_rule.new_fields_%s", randomSuffix), "id"),
		),
	}

	// Test 2: Using deprecated fields (cloud_provider, cloud_platform)
	deprecatedFieldsStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "deprecated_fields_%s" {
  name           = "Test Deprecated Fields %s"
  description    = "Test rule using deprecated field names"
  domain         = "CSPM"
  subdomain      = "IOM"
  resource_type  = "Microsoft.Compute/virtualMachines"
  cloud_provider = "Azure"
  cloud_platform = "Azure"
  severity       = "medium"
  logic = <<EOF
package crowdstrike
default result = "pass"
result = "fail" if {
    input.tags[_] == "test"
}
EOF
}
`, randomSuffix, randomSuffix),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(fmt.Sprintf("crowdstrike_cloud_security_custom_rule.deprecated_fields_%s", randomSuffix), "cloud_provider", "Azure"),
			resource.TestCheckResourceAttr(fmt.Sprintf("crowdstrike_cloud_security_custom_rule.deprecated_fields_%s", randomSuffix), "cloud_platform", "Azure"),
			resource.TestCheckResourceAttrSet(fmt.Sprintf("crowdstrike_cloud_security_custom_rule.deprecated_fields_%s", randomSuffix), "id"),
		),
	}

	// Test 3: Conflicting fields - should fail
	conflictingFieldsStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_custom_rule" "conflicting_fields_%s" {
  name           = "Test Conflicting Fields %s"
  description    = "Test rule with conflicting field names"
  domain         = "CSPM"
  subdomain      = "IOM"
  resource_type  = "AWS::EC2::Instance"
  rule_provider  = "AWS"
  cloud_provider = "AWS"
  severity       = "critical"
  logic = <<EOF
package crowdstrike
default result = "pass"
result = "fail" if {
    input.tags[_] == "test"
}
EOF
}
`, randomSuffix, randomSuffix),
		ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		PlanOnly:    true,
	}

	return []resource.TestStep{newFieldsStep, deprecatedFieldsStep, conflictingFieldsStep}
}
