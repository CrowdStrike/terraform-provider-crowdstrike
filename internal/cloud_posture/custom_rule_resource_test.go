package cloudposture_test

// Check empty fields.
// Check nil
// Check from defined to empty or nil. In-place updates.

import (
	"fmt"
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
}

var azureCopyConfig = ruleCustomConfig{
	ruleBaseConfig: commonConfig,
	parentId:       "1c9516e9-490b-461c-8644-9239ff3cf0d3",
	cloudProvider:  "Azure",
	cloudPlatform:  "Azure",
	resourceType:   "Microsoft.Compute/virtualMachines",
}

var gcpCopyConfig = ruleCustomConfig{
	ruleBaseConfig: commonConfig,
	parentId:       "0260ffa9-eb65-42f4-a02a-7456d280049a",
	cloudProvider:  "GCP",
	cloudPlatform:  "GCP",
	resourceType:   "sqladmin.googleapis.com/Instance",
}

func TestCloudPostureCustomRuleResource(t *testing.T) {
	var steps []resource.TestStep

	steps = append(steps, generateRuleCopyDefinedToEmptyTests(awsCopyConfig, "AWS")...)
	// steps = append(steps, generateRuleCopyTests(awsCopyConfig, "AWS")...)
	// steps = append(steps, generateRuleCopyTests(azureCopyConfig, "Azure")...)
	// steps = append(steps, generateRuleCopyTests(gcpCopyConfig, "GCP")...)
	// steps = append(steps, generateRuleLogicTests(awsCopyConfig, "AWS_Rego")...)
	// steps = append(steps, generateRuleLogicTests(azureCopyConfig, "Azure_Rego")...)
	// steps = append(steps, generateRuleLogicTests(gcpCopyConfig, "GCP_Rego")...)
	// steps = append(steps, generateMinimalRuleCopyTests(awsCopyConfig, "AWS_Min")...)
	// steps = append(steps, generateMinimalRuleCopyTests(azureCopyConfig, "Azure_Min")...)
	// steps = append(steps, generateMinimalRuleCopyTests(gcpCopyConfig, "GCP_Min")...)
	// steps = append(steps, generateMinimalRuleLogicTests(awsCopyConfig, "AWS_Min_Rego")...)
	// steps = append(steps, generateMinimalRuleLogicTests(azureCopyConfig, "Azure_Min_Rego")...)
	// steps = append(steps, generateMinimalRuleLogicTests(gcpCopyConfig, "GCP_Min_Rego")...)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    steps,
	})
}

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
  parent_rule_id   = "%s"
  alert_info = [%s]
}
`, ruleName, config.resourceType, config.ruleBaseConfig.ruleNamePrefix+ruleName, config.ruleBaseConfig.description[i],
				config.cloudProvider, config.severity[i], remediationInfo,
				testGenerateControlBlock(config.ruleBaseConfig.controls[i]), config.parentId, alertInfo),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(resourceName, "subdomain", config.ruleBaseConfig.subdomain),
				resource.TestCheckResourceAttr(resourceName, "domain", config.ruleBaseConfig.domain),
				resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
				resource.TestCheckResourceAttr(resourceName, "name", config.ruleBaseConfig.ruleNamePrefix+ruleName),
				resource.TestCheckResourceAttr(resourceName, "description", config.ruleBaseConfig.description[i]),
				resource.TestCheckResourceAttr(resourceName, "cloud_platform", config.cloudPlatform),
				resource.TestCheckResourceAttr(resourceName, "cloud_provider", config.cloudProvider),
				resource.TestCheckResourceAttr(resourceName, "severity", config.severity[i]),
				resource.TestCheckResourceAttr(resourceName, "parent_rule_id", config.parentId),
				resource.TestCheckResourceAttr(resourceName, "controls.0.authority", config.ruleBaseConfig.controls[i].authority),
				resource.TestCheckResourceAttr(resourceName, "controls.0.code", config.ruleBaseConfig.controls[i].code),
				resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("alert_info.%d", len(config.ruleBaseConfig.alertInfo[i])-1), config.ruleBaseConfig.alertInfo[i][len(config.ruleBaseConfig.alertInfo[i])-1]),
				resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("remediation_info.%d", len(config.ruleBaseConfig.remediationInfo[i])-1), config.ruleBaseConfig.remediationInfo[i][len(config.ruleBaseConfig.remediationInfo[i])-1]),
				resource.TestCheckResourceAttrSet(resourceName, "id"),
			),
		}
		steps = append(steps, newStep)
	}

	return steps
}

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
  parent_rule_id   = "%s"
}
`, ruleName, config.resourceType, config.ruleBaseConfig.ruleNamePrefix+ruleName, config.ruleBaseConfig.description[i],
				config.cloudProvider, config.parentId),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(resourceName, "subdomain", config.ruleBaseConfig.subdomain),
				resource.TestCheckResourceAttr(resourceName, "domain", config.ruleBaseConfig.domain),
				resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
				resource.TestCheckResourceAttr(resourceName, "name", config.ruleBaseConfig.ruleNamePrefix+ruleName),
				resource.TestCheckResourceAttr(resourceName, "description", config.ruleBaseConfig.description[i]),
				resource.TestCheckResourceAttr(resourceName, "cloud_platform", config.cloudPlatform),
				resource.TestCheckResourceAttr(resourceName, "cloud_provider", config.cloudProvider),
				resource.TestCheckResourceAttr(resourceName, "parent_rule_id", config.parentId),
				resource.TestCheckResourceAttrSet(resourceName, "id"),
				resource.TestCheckResourceAttrSet(resourceName, "severity"),
			),
		}
		steps = append(steps, newStep)
	}

	return steps
}

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

func testGenerateControlBlock(c control) string {
	return fmt.Sprintf(`
    {
		authority = "%s"
		code = "%s"
	}
	`, c.authority, c.code)
}

func generateRuleCopyDefinedToEmptyTests(config ruleCustomConfig, ruleName string) []resource.TestStep {
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
  parent_rule_id   = "%s"
  alert_info = [%s]
}
`, ruleName, config.resourceType, config.ruleBaseConfig.ruleNamePrefix+ruleName, config.ruleBaseConfig.description[0],
			config.cloudProvider, config.severity[0], remediationInfo,
			testGenerateControlBlock(config.ruleBaseConfig.controls[0]), config.parentId, alertInfo),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(resourceName, "subdomain", config.ruleBaseConfig.subdomain),
			resource.TestCheckResourceAttr(resourceName, "domain", config.ruleBaseConfig.domain),
			resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(resourceName, "name", config.ruleBaseConfig.ruleNamePrefix+ruleName),
			resource.TestCheckResourceAttr(resourceName, "description", config.ruleBaseConfig.description[0]),
			resource.TestCheckResourceAttr(resourceName, "cloud_platform", config.cloudPlatform),
			resource.TestCheckResourceAttr(resourceName, "cloud_provider", config.cloudProvider),
			resource.TestCheckResourceAttr(resourceName, "severity", config.severity[0]),
			resource.TestCheckResourceAttr(resourceName, "parent_rule_id", config.parentId),
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
  remediation_info = []
  controls = []
  parent_rule_id   = "%s"
  alert_info = []
}
`, ruleName, config.resourceType, config.ruleBaseConfig.ruleNamePrefix+ruleName, config.ruleBaseConfig.description[0],
			config.cloudProvider, config.severity[0], config.parentId),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(resourceName, "subdomain", config.ruleBaseConfig.subdomain),
			resource.TestCheckResourceAttr(resourceName, "domain", config.ruleBaseConfig.domain),
			resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(resourceName, "name", config.ruleBaseConfig.ruleNamePrefix+ruleName),
			resource.TestCheckResourceAttr(resourceName, "description", config.ruleBaseConfig.description[0]),
			resource.TestCheckResourceAttr(resourceName, "cloud_platform", config.cloudPlatform),
			resource.TestCheckResourceAttr(resourceName, "cloud_provider", config.cloudProvider),
			resource.TestCheckResourceAttr(resourceName, "severity", config.severity[0]),
			resource.TestCheckResourceAttr(resourceName, "parent_rule_id", config.parentId),
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
