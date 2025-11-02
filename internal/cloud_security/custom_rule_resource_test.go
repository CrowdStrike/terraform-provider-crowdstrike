package cloudsecurity_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

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
	ruleNamePrefix: "Terraform Automated Test ",
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
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleRegoDefinedToOmittedTests(awsCopyConfig, "AWS_Omit_Rego"),
	})
}

func TestCloudSecurityCustomRuleResource_AWS_RegoDefinedToEmpty(t *testing.T) {
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

// Azure Tests.
func TestCloudSecurityCustomRuleResource_Azure_Copy(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleCopyTests(azureCopyConfig, "Azure"),
	})
}

func TestCloudSecurityCustomRuleResource_Azure_Rego(t *testing.T) {
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
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleRegoDefinedToOmittedTests(azureCopyConfig, "Azure_Omit_Rego"),
	})
}

func TestCloudSecurityCustomRuleResource_Azure_RegoDefinedToEmpty(t *testing.T) {
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
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateRuleRegoDefinedToOmittedTests(gcpCopyConfig, "GCP_Omit_Rego"),
	})
}

func TestCloudSecurityCustomRuleResource_GCP_RegoDefinedToEmpty(t *testing.T) {
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
			`"` + strings.Join(config.ruleBaseConfig.alertInfo[i], `","`) + `"`,
		}, "")
		remediationInfo := strings.Join([]string{
			`"` + strings.Join(config.ruleBaseConfig.remediationInfo[i], `","`) + `"`,
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
`, ruleName, config.resourceType, config.ruleBaseConfig.ruleNamePrefix+ruleName, config.ruleBaseConfig.description[i],
				config.cloudProvider, config.severity[i], remediationInfo,
				testGenerateControlBlock(config.ruleBaseConfig.controls[i]), alertInfo,
				config.parentRule.ruleName, config.parentRule.benchmark),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(resourceName, "subdomain", config.ruleBaseConfig.subdomain),
				resource.TestCheckResourceAttr(resourceName, "domain", config.ruleBaseConfig.domain),
				resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
				resource.TestCheckResourceAttr(resourceName, "name", config.ruleBaseConfig.ruleNamePrefix+ruleName),
				resource.TestCheckResourceAttr(resourceName, "description", config.ruleBaseConfig.description[i]),
				resource.TestCheckResourceAttr(resourceName, "cloud_platform", config.cloudPlatform),
				resource.TestCheckResourceAttr(resourceName, "cloud_provider", config.cloudProvider),
				resource.TestCheckResourceAttr(resourceName, "severity", config.severity[i]),
				resource.TestCheckResourceAttr(resourceName, "controls.0.authority", config.ruleBaseConfig.controls[i].authority),
				resource.TestCheckResourceAttr(resourceName, "controls.0.code", config.ruleBaseConfig.controls[i].code),
				resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("alert_info.%d", len(config.ruleBaseConfig.alertInfo[i])-1), config.ruleBaseConfig.alertInfo[i][len(config.ruleBaseConfig.alertInfo[i])-1]),
				resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("remediation_info.%d", len(config.ruleBaseConfig.remediationInfo[i])-1), config.ruleBaseConfig.remediationInfo[i][len(config.ruleBaseConfig.remediationInfo[i])-1]),
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
			`"` + strings.Join(config.ruleBaseConfig.alertInfo[i], `","`) + `"`,
		}, "")
		remediationInfo := strings.Join([]string{
			`"` + strings.Join(config.ruleBaseConfig.remediationInfo[i], `","`) + `"`,
		}, "")
		attackTypes := strings.Join([]string{
			`"` + strings.Join(config.ruleBaseConfig.attackTypes[i], `","`) + `"`,
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
`, ruleName, config.resourceType, config.ruleBaseConfig.ruleNamePrefix+ruleName, config.ruleBaseConfig.description[i],
				config.cloudProvider, config.ruleBaseConfig.severity[i], remediationInfo, config.ruleBaseConfig.logic[i],
				alertInfo, testGenerateControlBlock(config.ruleBaseConfig.controls[i]), attackTypes),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(resourceName, "subdomain", config.ruleBaseConfig.subdomain),
				resource.TestCheckResourceAttr(resourceName, "domain", config.ruleBaseConfig.domain),
				resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
				resource.TestCheckResourceAttr(resourceName, "name", config.ruleBaseConfig.ruleNamePrefix+ruleName),
				resource.TestCheckResourceAttr(resourceName, "description", config.ruleBaseConfig.description[i]),
				resource.TestCheckResourceAttr(resourceName, "cloud_platform", config.cloudPlatform),
				resource.TestCheckResourceAttr(resourceName, "cloud_provider", config.cloudProvider),
				resource.TestCheckResourceAttr(resourceName, "severity", config.ruleBaseConfig.severity[i]),
				resource.TestCheckResourceAttr(resourceName, "logic", config.ruleBaseConfig.logic[i]+"\n"),
				resource.TestCheckResourceAttr(resourceName, "controls.0.authority", config.ruleBaseConfig.controls[i].authority),
				resource.TestCheckResourceAttr(resourceName, "controls.0.code", config.ruleBaseConfig.controls[i].code),
				resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("alert_info.%d", len(config.ruleBaseConfig.alertInfo[i])-1), config.ruleBaseConfig.alertInfo[i][len(config.ruleBaseConfig.alertInfo[i])-1]),
				resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("remediation_info.%d", len(config.ruleBaseConfig.remediationInfo[i])-1), config.ruleBaseConfig.remediationInfo[i][len(config.ruleBaseConfig.remediationInfo[i])-1]),
				resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("attack_types.%d", len(config.ruleBaseConfig.attackTypes[i])-1), config.ruleBaseConfig.attackTypes[i][len(config.ruleBaseConfig.attackTypes[i])-1]),
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
`, ruleName, config.resourceType, config.ruleBaseConfig.ruleNamePrefix+ruleName, config.ruleBaseConfig.description[i],
				config.cloudProvider, config.parentRule.ruleName, config.parentRule.benchmark),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(resourceName, "subdomain", config.ruleBaseConfig.subdomain),
				resource.TestCheckResourceAttr(resourceName, "domain", config.ruleBaseConfig.domain),
				resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
				resource.TestCheckResourceAttr(resourceName, "name", config.ruleBaseConfig.ruleNamePrefix+ruleName),
				resource.TestCheckResourceAttr(resourceName, "description", config.ruleBaseConfig.description[i]),
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
`, ruleName, config.resourceType, config.ruleBaseConfig.ruleNamePrefix+ruleName, config.ruleBaseConfig.description[i],
				config.cloudProvider, config.ruleBaseConfig.logic[i]),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(resourceName, "subdomain", config.ruleBaseConfig.subdomain),
				resource.TestCheckResourceAttr(resourceName, "domain", config.ruleBaseConfig.domain),
				resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
				resource.TestCheckResourceAttr(resourceName, "name", config.ruleBaseConfig.ruleNamePrefix+ruleName),
				resource.TestCheckResourceAttr(resourceName, "description", config.ruleBaseConfig.description[i]),
				resource.TestCheckResourceAttr(resourceName, "cloud_platform", config.cloudPlatform),
				resource.TestCheckResourceAttr(resourceName, "cloud_provider", config.cloudProvider),
				resource.TestCheckResourceAttr(resourceName, "logic", config.ruleBaseConfig.logic[i]+"\n"),
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
		`"` + strings.Join(config.ruleBaseConfig.alertInfo[0], `","`) + `"`,
	}, "")
	remediationInfo := strings.Join([]string{
		`"` + strings.Join(config.ruleBaseConfig.remediationInfo[0], `","`) + `"`,
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
`, ruleName, config.resourceType, config.ruleBaseConfig.ruleNamePrefix+ruleName, config.ruleBaseConfig.description[0],
			config.cloudProvider, config.severity[0], remediationInfo,
			testGenerateControlBlock(config.ruleBaseConfig.controls[0]), alertInfo,
			config.parentRule.ruleName, config.parentRule.benchmark),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(resourceName, "subdomain", config.ruleBaseConfig.subdomain),
			resource.TestCheckResourceAttr(resourceName, "domain", config.ruleBaseConfig.domain),
			resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(resourceName, "name", config.ruleBaseConfig.ruleNamePrefix+ruleName),
			resource.TestCheckResourceAttr(resourceName, "description", config.ruleBaseConfig.description[0]),
			resource.TestCheckResourceAttr(resourceName, "cloud_platform", config.cloudPlatform),
			resource.TestCheckResourceAttr(resourceName, "cloud_provider", config.cloudProvider),
			resource.TestCheckResourceAttr(resourceName, "severity", config.severity[0]),
			resource.TestCheckResourceAttr(resourceName, "controls.0.authority", config.ruleBaseConfig.controls[0].authority),
			resource.TestCheckResourceAttr(resourceName, "controls.0.code", config.ruleBaseConfig.controls[0].code),
			resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("alert_info.%d", len(config.ruleBaseConfig.alertInfo[0])-1), config.ruleBaseConfig.alertInfo[0][len(config.ruleBaseConfig.alertInfo[0])-1]),
			resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("remediation_info.%d", len(config.ruleBaseConfig.remediationInfo[0])-1), config.ruleBaseConfig.remediationInfo[0][len(config.ruleBaseConfig.remediationInfo[0])-1]),
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
`, ruleName, config.resourceType, config.ruleBaseConfig.ruleNamePrefix+ruleName, config.ruleBaseConfig.description[0],
			config.cloudProvider, config.severity[0], config.parentRule.ruleName, config.parentRule.benchmark),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(resourceName, "subdomain", config.ruleBaseConfig.subdomain),
			resource.TestCheckResourceAttr(resourceName, "domain", config.ruleBaseConfig.domain),
			resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(resourceName, "name", config.ruleBaseConfig.ruleNamePrefix+ruleName),
			resource.TestCheckResourceAttr(resourceName, "description", config.ruleBaseConfig.description[0]),
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
		`"` + strings.Join(config.ruleBaseConfig.alertInfo[0], `","`) + `"`,
	}, "")
	remediationInfo := strings.Join([]string{
		`"` + strings.Join(config.ruleBaseConfig.remediationInfo[0], `","`) + `"`,
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
`, resourceName, config.resourceType, config.ruleBaseConfig.ruleNamePrefix+resourceName, config.ruleBaseConfig.description[0],
			config.cloudProvider, config.severity[0], remediationInfo,
			testGenerateControlBlock(config.ruleBaseConfig.controls[0]), alertInfo,
			config.parentRule.ruleName, config.parentRule.benchmark),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(fullResourceName, "subdomain", config.ruleBaseConfig.subdomain),
			resource.TestCheckResourceAttr(fullResourceName, "domain", config.ruleBaseConfig.domain),
			resource.TestCheckResourceAttr(fullResourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(fullResourceName, "name", config.ruleBaseConfig.ruleNamePrefix+resourceName),
			resource.TestCheckResourceAttr(fullResourceName, "description", config.ruleBaseConfig.description[0]),
			resource.TestCheckResourceAttr(fullResourceName, "cloud_platform", config.cloudPlatform),
			resource.TestCheckResourceAttr(fullResourceName, "cloud_provider", config.cloudProvider),
			resource.TestCheckResourceAttr(fullResourceName, "severity", config.severity[0]),
			resource.TestCheckResourceAttr(fullResourceName, "controls.0.authority", config.ruleBaseConfig.controls[0].authority),
			resource.TestCheckResourceAttr(fullResourceName, "controls.0.code", config.ruleBaseConfig.controls[0].code),
			resource.TestCheckResourceAttr(fullResourceName, fmt.Sprintf("alert_info.%d", len(config.ruleBaseConfig.alertInfo[0])-1), config.ruleBaseConfig.alertInfo[0][len(config.ruleBaseConfig.alertInfo[0])-1]),
			resource.TestCheckResourceAttr(fullResourceName, fmt.Sprintf("remediation_info.%d", len(config.ruleBaseConfig.remediationInfo[0])-1), config.ruleBaseConfig.remediationInfo[0][len(config.ruleBaseConfig.remediationInfo[0])-1]),
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
`, resourceName, config.resourceType, config.ruleBaseConfig.ruleNamePrefix+resourceName, config.ruleBaseConfig.description[0],
			config.cloudProvider, config.severity[0], testGenerateControlBlock(config.ruleBaseConfig.controls[0]),
			remediationInfo, config.parentRule.ruleName, config.parentRule.benchmark),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(fullResourceName, "subdomain", config.ruleBaseConfig.subdomain),
			resource.TestCheckResourceAttr(fullResourceName, "domain", config.ruleBaseConfig.domain),
			resource.TestCheckResourceAttr(fullResourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(fullResourceName, "name", config.ruleBaseConfig.ruleNamePrefix+resourceName),
			resource.TestCheckResourceAttr(fullResourceName, "description", config.ruleBaseConfig.description[0]),
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
		`"` + strings.Join(config.ruleBaseConfig.alertInfo[0], `","`) + `"`,
	}, "")
	remediationInfo := strings.Join([]string{
		`"` + strings.Join(config.ruleBaseConfig.remediationInfo[0], `","`) + `"`,
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
`, ruleName, config.resourceType, config.ruleBaseConfig.ruleNamePrefix+ruleName, config.ruleBaseConfig.description[0],
			config.cloudProvider, config.severity[0], remediationInfo,
			testGenerateControlBlock(config.ruleBaseConfig.controls[0]), alertInfo, config.ruleBaseConfig.logic[0]),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(resourceName, "subdomain", config.ruleBaseConfig.subdomain),
			resource.TestCheckResourceAttr(resourceName, "domain", config.ruleBaseConfig.domain),
			resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(resourceName, "name", config.ruleBaseConfig.ruleNamePrefix+ruleName),
			resource.TestCheckResourceAttr(resourceName, "description", config.ruleBaseConfig.description[0]),
			resource.TestCheckResourceAttr(resourceName, "cloud_platform", config.cloudPlatform),
			resource.TestCheckResourceAttr(resourceName, "cloud_provider", config.cloudProvider),
			resource.TestCheckResourceAttr(resourceName, "severity", config.severity[0]),
			resource.TestCheckResourceAttr(resourceName, "logic", config.ruleBaseConfig.logic[0]+"\n"),
			resource.TestCheckResourceAttr(resourceName, "controls.0.authority", config.ruleBaseConfig.controls[0].authority),
			resource.TestCheckResourceAttr(resourceName, "controls.0.code", config.ruleBaseConfig.controls[0].code),
			resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("alert_info.%d", len(config.ruleBaseConfig.alertInfo[0])-1), config.ruleBaseConfig.alertInfo[0][len(config.ruleBaseConfig.alertInfo[0])-1]),
			resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("remediation_info.%d", len(config.ruleBaseConfig.remediationInfo[0])-1), config.ruleBaseConfig.remediationInfo[0][len(config.ruleBaseConfig.remediationInfo[0])-1]),
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
`, ruleName, config.resourceType, config.ruleBaseConfig.ruleNamePrefix+ruleName, config.ruleBaseConfig.description[0],
			config.cloudProvider, config.severity[0], config.ruleBaseConfig.logic[0]),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(resourceName, "subdomain", config.ruleBaseConfig.subdomain),
			resource.TestCheckResourceAttr(resourceName, "domain", config.ruleBaseConfig.domain),
			resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(resourceName, "name", config.ruleBaseConfig.ruleNamePrefix+ruleName),
			resource.TestCheckResourceAttr(resourceName, "description", config.ruleBaseConfig.description[0]),
			resource.TestCheckResourceAttr(resourceName, "cloud_platform", config.cloudPlatform),
			resource.TestCheckResourceAttr(resourceName, "cloud_provider", config.cloudProvider),
			resource.TestCheckResourceAttr(resourceName, "severity", config.severity[0]),
			resource.TestCheckResourceAttr(resourceName, "logic", config.ruleBaseConfig.logic[0]+"\n"),
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
		`"` + strings.Join(config.ruleBaseConfig.alertInfo[0], `","`) + `"`,
	}, "")
	remediationInfo := strings.Join([]string{
		`"` + strings.Join(config.ruleBaseConfig.remediationInfo[0], `","`) + `"`,
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
`, ruleName, config.resourceType, config.ruleBaseConfig.ruleNamePrefix+ruleName, config.ruleBaseConfig.description[0],
			config.cloudProvider, config.severity[0], remediationInfo,
			testGenerateControlBlock(config.ruleBaseConfig.controls[0]), alertInfo, config.ruleBaseConfig.logic[0]),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(resourceName, "subdomain", config.ruleBaseConfig.subdomain),
			resource.TestCheckResourceAttr(resourceName, "domain", config.ruleBaseConfig.domain),
			resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(resourceName, "name", config.ruleBaseConfig.ruleNamePrefix+ruleName),
			resource.TestCheckResourceAttr(resourceName, "description", config.ruleBaseConfig.description[0]),
			resource.TestCheckResourceAttr(resourceName, "cloud_platform", config.cloudPlatform),
			resource.TestCheckResourceAttr(resourceName, "cloud_provider", config.cloudProvider),
			resource.TestCheckResourceAttr(resourceName, "severity", config.severity[0]),
			resource.TestCheckResourceAttr(resourceName, "logic", config.ruleBaseConfig.logic[0]+"\n"),
			resource.TestCheckResourceAttr(resourceName, "controls.0.authority", config.ruleBaseConfig.controls[0].authority),
			resource.TestCheckResourceAttr(resourceName, "controls.0.code", config.ruleBaseConfig.controls[0].code),
			resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("alert_info.%d", len(config.ruleBaseConfig.alertInfo[0])-1), config.ruleBaseConfig.alertInfo[0][len(config.ruleBaseConfig.alertInfo[0])-1]),
			resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("remediation_info.%d", len(config.ruleBaseConfig.remediationInfo[0])-1), config.ruleBaseConfig.remediationInfo[0][len(config.ruleBaseConfig.remediationInfo[0])-1]),
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
`, ruleName, config.resourceType, config.ruleBaseConfig.ruleNamePrefix+ruleName, config.ruleBaseConfig.description[0],
			config.cloudProvider, config.severity[0], config.ruleBaseConfig.logic[0]),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(resourceName, "subdomain", config.ruleBaseConfig.subdomain),
			resource.TestCheckResourceAttr(resourceName, "domain", config.ruleBaseConfig.domain),
			resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(resourceName, "name", config.ruleBaseConfig.ruleNamePrefix+ruleName),
			resource.TestCheckResourceAttr(resourceName, "description", config.ruleBaseConfig.description[0]),
			resource.TestCheckResourceAttr(resourceName, "cloud_platform", config.cloudPlatform),
			resource.TestCheckResourceAttr(resourceName, "cloud_provider", config.cloudProvider),
			resource.TestCheckResourceAttr(resourceName, "severity", config.severity[0]),
			resource.TestCheckResourceAttr(resourceName, "logic", config.ruleBaseConfig.logic[0]+"\n"),
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
		`"` + strings.Join(config.ruleBaseConfig.alertInfo[0], `","`) + `"`,
	}, "")
	remediationInfo := strings.Join([]string{
		`"` + strings.Join(config.ruleBaseConfig.remediationInfo[0], `","`) + `"`,
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
`, resourceName, config.resourceType, config.ruleBaseConfig.ruleNamePrefix+resourceName, config.ruleBaseConfig.description[0],
				config.cloudProvider, config.severity[0], remediationInfo,
				testGenerateControlBlock(config.ruleBaseConfig.controls[0]), alertInfo,
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
`, ruleName, config.resourceType, config.ruleBaseConfig.ruleNamePrefix+ruleName,
			config.ruleBaseConfig.description[0], config.cloudProvider, config.severity[0],
			config.parentRule.ruleName, config.parentRule.benchmark),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(resourceName, "subdomain", config.ruleBaseConfig.subdomain),
			resource.TestCheckResourceAttr(resourceName, "domain", config.ruleBaseConfig.domain),
			resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(resourceName, "name", config.ruleBaseConfig.ruleNamePrefix+ruleName),
			resource.TestCheckResourceAttr(resourceName, "description", config.ruleBaseConfig.description[0]+" - Step 1"),
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
`, ruleName, config.resourceType, config.ruleBaseConfig.ruleNamePrefix+ruleName,
			config.ruleBaseConfig.description[0], config.cloudProvider, config.severity[0],
			config.parentRule.ruleName, config.parentRule.benchmark),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(resourceName, "subdomain", config.ruleBaseConfig.subdomain),
			resource.TestCheckResourceAttr(resourceName, "domain", config.ruleBaseConfig.domain),
			resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(resourceName, "name", config.ruleBaseConfig.ruleNamePrefix+ruleName),
			resource.TestCheckResourceAttr(resourceName, "description", config.ruleBaseConfig.description[0]+" - Step 2"),
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
`, ruleName, config.resourceType, config.ruleBaseConfig.ruleNamePrefix+ruleName,
			config.ruleBaseConfig.description[0], config.cloudProvider, config.severity[0],
			config.parentRule.ruleName, config.parentRule.benchmark),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(resourceName, "subdomain", config.ruleBaseConfig.subdomain),
			resource.TestCheckResourceAttr(resourceName, "domain", config.ruleBaseConfig.domain),
			resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(resourceName, "name", config.ruleBaseConfig.ruleNamePrefix+ruleName),
			resource.TestCheckResourceAttr(resourceName, "description", config.ruleBaseConfig.description[0]+" - Step 3"),
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
`, ruleName, config.resourceType, config.ruleBaseConfig.ruleNamePrefix+ruleName,
		config.ruleBaseConfig.description[0], config.cloudProvider, config.severity[0],
		config.parentRule.ruleName, config.parentRule.benchmark)

	createStep := resource.TestStep{
		Config: configStr,
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(resourceName, "subdomain", config.ruleBaseConfig.subdomain),
			resource.TestCheckResourceAttr(resourceName, "domain", config.ruleBaseConfig.domain),
			resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(resourceName, "name", config.ruleBaseConfig.ruleNamePrefix+ruleName),
			resource.TestCheckResourceAttr(resourceName, "description", config.ruleBaseConfig.description[0]),
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
