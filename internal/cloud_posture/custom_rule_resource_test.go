package cloudposture_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
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

func TestCloudPostureCustomRuleResource(t *testing.T) {
	var steps []resource.TestStep

	// Steps that don't produce resources
	steps = append(steps, generateRuleCopyDefinedAttackTypeTests(awsCopyConfig)...)

	// Steps that produce resources that require destroy
	steps = append(steps, generateRuleCopyTests(awsCopyConfig, "AWS")...)
	steps = append(steps, generateRuleCopyTests(azureCopyConfig, "Azure")...)
	steps = append(steps, generateRuleCopyTests(gcpCopyConfig, "GCP")...)
	steps = append(steps, generateRuleLogicTests(awsCopyConfig, "AWS_Rego")...)
	steps = append(steps, generateRuleLogicTests(azureCopyConfig, "Azure_Rego")...)
	steps = append(steps, generateRuleLogicTests(gcpCopyConfig, "GCP_Rego")...)
	steps = append(steps, generateMinimalRuleCopyTests(awsCopyConfig, "AWS_Min")...)
	steps = append(steps, generateMinimalRuleCopyTests(azureCopyConfig, "Azure_Min")...)
	steps = append(steps, generateMinimalRuleCopyTests(gcpCopyConfig, "GCP_Min")...)
	steps = append(steps, generateMinimalRuleLogicTests(awsCopyConfig, "AWS_Min_Rego")...)
	steps = append(steps, generateMinimalRuleLogicTests(azureCopyConfig, "Azure_Min_Rego")...)
	steps = append(steps, generateMinimalRuleLogicTests(gcpCopyConfig, "GCP_Min_Rego")...)
	steps = append(steps, generateRuleCopyDefinedToOmittedTests(awsCopyConfig, "AWS_Omit")...)
	steps = append(steps, generateRuleCopyDefinedToOmittedTests(azureCopyConfig, "Azure_Omit")...)
	steps = append(steps, generateRuleCopyDefinedToOmittedTests(gcpCopyConfig, "GCP_Omit")...)
	steps = append(steps, generateRuleRegoDefinedToOmittedTests(awsCopyConfig, "AWS_Omit_Rego")...)
	steps = append(steps, generateRuleRegoDefinedToOmittedTests(azureCopyConfig, "Azure_Omit_Rego")...)
	steps = append(steps, generateRuleRegoDefinedToOmittedTests(gcpCopyConfig, "GCP_Omit_Rego")...)
	steps = append(steps, generateRuleRegoDefinedToEmptyTests(awsCopyConfig, "AWS_Empty_Rego")...)
	steps = append(steps, generateRuleRegoDefinedToEmptyTests(azureCopyConfig, "Azure_Empty_Rego")...)
	steps = append(steps, generateRuleRegoDefinedToEmptyTests(gcpCopyConfig, "GCP_Empty_Rego")...)
	steps = append(steps, generateRuleCopyDefinedToEmptyAlertInfoTests(awsCopyConfig)...)
	steps = append(steps, generateRuleCopyDefinedToEmptyRemediationInfoTests(awsCopyConfig)...)
	steps = append(steps, generateRuleCopyDefinedToEmptyControlsTests(awsCopyConfig)...)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    steps,
	})
}

// In-place updates of user defined remediation_info, alert_info, and controls for duplicate rules
func generateRuleCopyTests(config ruleCustomConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	resourceName := "crowdstrike_cloud_posture_custom_rule.rule" + "_" + ruleName

	for i := range 2 {
		alertInfo := strings.Join([]string{
			`"` + strings.Join(config.ruleBaseConfig.alertInfo[i], `","`) + `"`,
		}, "")
		remediationInfo := strings.Join([]string{
			`"` + strings.Join(config.ruleBaseConfig.remediationInfo[i], `","`) + `"`,
		}, "")
		newStep := resource.TestStep{
			Config: fmt.Sprintf(`
resource "crowdstrike_cloud_posture_custom_rule" "rule_%s" {
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
  parent_rule_id = one(data.crowdstrike_cloud_posture_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_posture_rules" "rule_%[1]s" {
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
		steps = append(steps, newStep)
	}

	return steps
}

// In-place updates of user defined remediation_info, alert_info, controls, and attack_types
func generateRuleLogicTests(config ruleCustomConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	resourceName := "crowdstrike_cloud_posture_custom_rule.rule" + "_" + ruleName

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
resource "crowdstrike_cloud_posture_custom_rule" "rule_%s" {
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

// Minimum configuration for duplicate rules
func generateMinimalRuleCopyTests(config ruleCustomConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	resourceName := "crowdstrike_cloud_posture_custom_rule.rule" + "_" + ruleName

	for i := range 2 {
		newStep := resource.TestStep{
			Config: fmt.Sprintf(`
resource "crowdstrike_cloud_posture_custom_rule" "rule_%s" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  parent_rule_id   = one(data.crowdstrike_cloud_posture_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_posture_rules" "rule_%[1]s" {
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
			ExpectNonEmptyPlan: true,
		}
		steps = append(steps, newStep)
	}

	return steps
}

// Minimum configuration for rego rules
func generateMinimalRuleLogicTests(config ruleCustomConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	resourceName := "crowdstrike_cloud_posture_custom_rule.rule" + "_" + ruleName

	for i := range 2 {
		resourceStep := resource.TestStep{
			Config: fmt.Sprintf(`
resource "crowdstrike_cloud_posture_custom_rule" "rule_%s" {
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

// Ensure duplicate rules will inherit fields from parent when fields are omitted in-place
func generateRuleCopyDefinedToOmittedTests(config ruleCustomConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	resourceName := "crowdstrike_cloud_posture_custom_rule.rule" + "_" + ruleName + "_definedToOmitted"

	alertInfo := strings.Join([]string{
		`"` + strings.Join(config.ruleBaseConfig.alertInfo[0], `","`) + `"`,
	}, "")
	remediationInfo := strings.Join([]string{
		`"` + strings.Join(config.ruleBaseConfig.remediationInfo[0], `","`) + `"`,
	}, "")

	definedStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_posture_custom_rule" "rule_%s_definedToOmitted" {
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
  parent_rule_id   = one(data.crowdstrike_cloud_posture_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_posture_rules" "rule_%[1]s" {
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
resource "crowdstrike_cloud_posture_custom_rule" "rule_%s_definedToOmitted" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  severity         = "%s"
  parent_rule_id   = one(data.crowdstrike_cloud_posture_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_posture_rules" "rule_%[1]s" {
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
		ExpectNonEmptyPlan: true,
	}

	steps = append(steps, definedStep)
	steps = append(steps, undefinedStep)

	return steps
}

// Ensure alert_info fail when set to empty for duplicate rules
func generateRuleCopyDefinedToEmptyAlertInfoTests(config ruleCustomConfig) []resource.TestStep {
	var steps []resource.TestStep
	resourceName := "definedToEmptyAlertInfoCopyRule"
	fullResourceName := fmt.Sprintf("crowdstrike_cloud_posture_custom_rule.%s", resourceName)

	alertInfo := strings.Join([]string{
		`"` + strings.Join(config.ruleBaseConfig.alertInfo[0], `","`) + `"`,
	}, "")
	remediationInfo := strings.Join([]string{
		`"` + strings.Join(config.ruleBaseConfig.remediationInfo[0], `","`) + `"`,
	}, "")

	definedStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_posture_custom_rule" "%s" {
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
  parent_rule_id = one(data.crowdstrike_cloud_posture_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_posture_rules" "rule_%[1]s" {
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
resource "crowdstrike_cloud_posture_custom_rule" "%s" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  severity         = "%s"
  controls         = [%s]
  remediation_info = [%s]
  alert_info       = []
  parent_rule_id   = one(data.crowdstrike_cloud_posture_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_posture_rules" "rule_%[1]s" {
  rule_name = "%[9]s"
  benchmark = "%[10]s"
}
`, resourceName, config.resourceType, config.ruleBaseConfig.ruleNamePrefix+resourceName, config.ruleBaseConfig.description[0],
			config.cloudProvider, config.severity[0], testGenerateControlBlock(config.ruleBaseConfig.controls[0]),
			remediationInfo, config.parentRule.ruleName, config.parentRule.benchmark),
		ExpectError: regexp.MustCompile(
			"Invalid Configuration",
		),
	}

	steps = append(steps, definedStep)
	steps = append(steps, undefinedStep)

	// Required config to perform deletion after test
	steps = append(steps, definedStep)

	return steps
}

// Ensure remediation_info fail when set to empty for duplicate rules
func generateRuleCopyDefinedToEmptyRemediationInfoTests(config ruleCustomConfig) []resource.TestStep {
	var steps []resource.TestStep
	resourceName := "definedToEmptyRemediationInfoCopyRule"
	fullResourceName := fmt.Sprintf("crowdstrike_cloud_posture_custom_rule.%s", resourceName)

	alertInfo := strings.Join([]string{
		`"` + strings.Join(config.ruleBaseConfig.alertInfo[0], `","`) + `"`,
	}, "")
	remediationInfo := strings.Join([]string{
		`"` + strings.Join(config.ruleBaseConfig.remediationInfo[0], `","`) + `"`,
	}, "")

	definedStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_posture_custom_rule" "%s" {
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
  parent_rule_id = one(data.crowdstrike_cloud_posture_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_posture_rules" "rule_%[1]s" {
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
resource "crowdstrike_cloud_posture_custom_rule" "%s" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  severity         = "%s"
  controls         = [%s]
  remediation_info = []
  alert_info       = [%s]
  parent_rule_id   = one(data.crowdstrike_cloud_posture_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_posture_rules" "rule_%[1]s" {
  rule_name = "%[9]s"
  benchmark = "%[10]s"
}
`, resourceName, config.resourceType, config.ruleBaseConfig.ruleNamePrefix, config.ruleBaseConfig.description[0],
			config.cloudProvider, config.severity[0],
			testGenerateControlBlock(config.ruleBaseConfig.controls[0]), alertInfo,
			config.parentRule.ruleName, config.parentRule.benchmark),
		ExpectError: regexp.MustCompile(
			"Invalid Configuration",
		),
	}

	steps = append(steps, definedStep)
	steps = append(steps, undefinedStep)

	// Required config to perform deletion after test
	steps = append(steps, definedStep)

	return steps
}

// Ensure controls fail on empty alert_info for duplicate rules
func generateRuleCopyDefinedToEmptyControlsTests(config ruleCustomConfig) []resource.TestStep {
	var steps []resource.TestStep
	resourceName := "definedToEmptyControlsCopyRule"
	fullResourceName := fmt.Sprintf("crowdstrike_cloud_posture_custom_rule.%s", resourceName)

	alertInfo := strings.Join([]string{
		`"` + strings.Join(config.ruleBaseConfig.alertInfo[0], `","`) + `"`,
	}, "")
	remediationInfo := strings.Join([]string{
		`"` + strings.Join(config.ruleBaseConfig.remediationInfo[0], `","`) + `"`,
	}, "")

	definedStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_posture_custom_rule" "%s" {
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
  parent_rule_id = one(data.crowdstrike_cloud_posture_rules.rule_%[1]s.rules).id

}

data "crowdstrike_cloud_posture_rules" "rule_%[1]s" {
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
resource "crowdstrike_cloud_posture_custom_rule" "%s" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  severity         = "%s"
  controls         = []
  remediation_info = [%s]
  alert_info       = [%s]
  parent_rule_id   = one(data.crowdstrike_cloud_posture_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_posture_rules" "rule_%[1]s" {
  rule_name = "%[9]s"
  benchmark = "%[10]s"
}
`, resourceName, config.resourceType, config.ruleBaseConfig.ruleNamePrefix+resourceName, config.ruleBaseConfig.description[0],
			config.cloudProvider, config.severity[0],
			remediationInfo, alertInfo,
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
			resource.TestCheckResourceAttr(fullResourceName, "controls.#", "0"),
			resource.TestCheckResourceAttr(fullResourceName, fmt.Sprintf("alert_info.%d", len(config.ruleBaseConfig.alertInfo[0])-1), config.ruleBaseConfig.alertInfo[0][len(config.ruleBaseConfig.alertInfo[0])-1]),
			resource.TestCheckResourceAttr(fullResourceName, fmt.Sprintf("remediation_info.%d", len(config.ruleBaseConfig.remediationInfo[0])-1), config.ruleBaseConfig.remediationInfo[0][len(config.ruleBaseConfig.remediationInfo[0])-1]),
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

// Validating fields set to empty when omitted in-place
func generateRuleRegoDefinedToOmittedTests(config ruleCustomConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	resourceName := "crowdstrike_cloud_posture_custom_rule.rule" + "_" + ruleName + "_definedToOmitted"

	alertInfo := strings.Join([]string{
		`"` + strings.Join(config.ruleBaseConfig.alertInfo[0], `","`) + `"`,
	}, "")
	remediationInfo := strings.Join([]string{
		`"` + strings.Join(config.ruleBaseConfig.remediationInfo[0], `","`) + `"`,
	}, "")

	definedStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_posture_custom_rule" "rule_%s_definedToOmitted" {
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
resource "crowdstrike_cloud_posture_custom_rule" "rule_%s_definedToOmitted" {
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

// Validating fields set to empty when set to empty list/set in-place
func generateRuleRegoDefinedToEmptyTests(config ruleCustomConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	resourceName := "crowdstrike_cloud_posture_custom_rule.rule" + "_" + ruleName + "_definedToEmpty"

	alertInfo := strings.Join([]string{
		`"` + strings.Join(config.ruleBaseConfig.alertInfo[0], `","`) + `"`,
	}, "")
	remediationInfo := strings.Join([]string{
		`"` + strings.Join(config.ruleBaseConfig.remediationInfo[0], `","`) + `"`,
	}, "")

	definedStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_posture_custom_rule" "rule_%s_definedToEmpty" {
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
resource "crowdstrike_cloud_posture_custom_rule" "rule_%s_definedToEmpty" {
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

// Validate attack_types cannot be set for duplicate rules
func generateRuleCopyDefinedAttackTypeTests(config ruleCustomConfig) []resource.TestStep {
	resourceName := "definedToEmptyAttackTypesCopyRule"

	alertInfo := strings.Join([]string{
		`"` + strings.Join(config.ruleBaseConfig.alertInfo[0], `","`) + `"`,
	}, "")
	remediationInfo := strings.Join([]string{
		`"` + strings.Join(config.ruleBaseConfig.remediationInfo[0], `","`) + `"`,
	}, "")

	return []resource.TestStep{
		{
			Config: fmt.Sprintf(`
resource "crowdstrike_cloud_posture_custom_rule" "%s" {
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
  parent_rule_id = one(data.crowdstrike_cloud_posture_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_posture_rules" "rule_%[1]s" {
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
