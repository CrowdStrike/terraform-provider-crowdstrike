package cloudsecurity_test

import (
	"fmt"
	"strings"
	"testing"
	"unicode"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

type ruleIacBaseConfig struct {
	ruleNamePrefix  string
	description     []string
	severity        []string
	remediationInfo [][]string
	logic           []string
	alertInfo       [][]string
	category        []string
	labels          [][]string
}

type ruleIacConfig struct {
	ruleIacBaseConfig
	cloudProvider string
	resourceType  string
}

var commonIacConfig = ruleIacBaseConfig{
	ruleNamePrefix: acctest.ResourcePrefix,
	description: []string{
		"This is a description for IAC rule",
		"This is an updated description for IAC rule",
	},
	severity: []string{"critical", "informational"},
	remediationInfo: [][]string{
		{
			"Apply security best practices to this resource configuration",
			"Ensure proper access controls are in place",
		},
		{
			"Review and update the resource configuration according to security guidelines",
			"Implement recommended security measures",
		},
	},
	logic: []string{
		"package crowdstrike\n\nimport rego.v1\n\n# EC2 Security Group policy\ncx_policy contains result if {\n\tsome i, name\n\tresource := input.document[i].resource.aws_security_group[name]\n\tsome rule in resource.ingress\n\trule.from_port == 22\n\t\"0.0.0.0/0\" in rule.cidr_blocks\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceType\": \"aws_security_group\",\n\t\t\"resourceName\": name,\n\t\t\"searchKey\": sprintf(\"aws_security_group[%s].ingress\", [name]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": \"Security group should not allow SSH from anywhere\",\n\t\t\"keyActualValue\": \"Security group allows SSH from 0.0.0.0/0\",\n\t}\n}",
		"package crowdstrike\n\nimport rego.v1\n\n# EC2 Security Group policy\ncx_policy contains result if {\n\tsome i, name\n\tresource := input.document[i].resource.aws_security_group[name]\n\tsome rule in resource.ingress\n\trule.from_port == 3389\n\t\"0.0.0.0/0\" in rule.cidr_blocks\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceType\": \"aws_security_group\",\n\t\t\"resourceName\": name,\n\t\t\"searchKey\": sprintf(\"aws_security_group[%s].ingress\", [name]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": \"Security group should not allow RDP from anywhere\",\n\t\t\"keyActualValue\": \"Security group allows RDP from 0.0.0.0/0\",\n\t}\n}",
	},
	alertInfo: [][]string{
		{
			"List all resources in the account.",
			"Check if the resource configuration meets the requirement.",
			"Check if multiple availability zones are configured.",
		},
		{
			"Check if the resource configuration meets the requirement.",
			"List all resources in the account.",
			"Check if multiple availability zones are configured.",
			"Alert when any of the above conditions are met.",
		},
	},
	category: []string{
		"Network Security",
		"Data Encryption",
	},
	labels: [][]string{
		{"aws", "network", "critical"},
		{"encryption", "compliance", "pci-dss", "production"},
	},
}

var terraformIacConfig = ruleIacConfig{
	ruleIacBaseConfig: commonIacConfig,
	cloudProvider:     "AWS",
	resourceType:      "EC2",
}

var azureIacConfig = ruleIacConfig{
	ruleIacBaseConfig: commonIacConfig,
	cloudProvider:     "Azure",
	resourceType:      "Virtual Machines",
}

var gcpIacConfig = ruleIacConfig{
	ruleIacBaseConfig: commonIacConfig,
	cloudProvider:     "GCP",
	resourceType:      "Compute Engine",
}

var generalIacConfig = ruleIacConfig{
	ruleIacBaseConfig: commonIacConfig,
	cloudProvider:     "General",
	resourceType:      "Custom",
}

// Terraform Tests.
func TestCloudSecurityIacCustomRuleResource_Terraform_Basic(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIacRuleBasicTests(terraformIacConfig, "Terraform"),
	})
}

func TestCloudSecurityIacCustomRuleResource_Terraform_Minimal(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateMinimalIacRuleRegoTests(terraformIacConfig, "Terraform_Min"),
	})
}

// Cloud Provider Tests.
func TestCloudSecurityIacCustomRuleResource_Azure_Basic(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIacRuleBasicTests(azureIacConfig, "Azure"),
	})
}

func TestCloudSecurityIacCustomRuleResource_GCP_Basic(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIacRuleBasicTests(gcpIacConfig, "GCP"),
	})
}

func TestCloudSecurityIacCustomRuleResource_General_Basic(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIacRuleBasicTests(generalIacConfig, "General"),
	})
}

// Additional tests for field behavior.
func TestCloudSecurityIacCustomRuleResource_RegoDefinedToOmitted(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIacRuleRegoDefinedToOmittedTests(terraformIacConfig, "Terraform_Omit_Rego"),
	})
}

func TestCloudSecurityIacCustomRuleResource_RegoInPlaceUpdate(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIacRuleInPlaceUpdateTests(terraformIacConfig, "Terraform_InPlaceUpdate"),
	})
}

// Basic test with in-place updates of user defined remediation_info and alert_info.
func generateIacRuleBasicTests(config ruleIacConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	randomSuffix := sdkacctest.RandString(8)
	ruleName = fmt.Sprintf("tfacc_%s_%s", ruleName, randomSuffix)
	resourceName := "crowdstrike_cloud_security_iac_custom_rule.rule" + "_" + ruleName

	for i := range 2 {
		alertInfo := `"` + strings.Join(config.alertInfo[i], `","`) + `"`
		remediationInfo := `"` + strings.Join(config.remediationInfo[i], `","`) + `"`

		lastAlertIdx := len(config.alertInfo[i]) - 1
		lastRemediationIdx := len(config.remediationInfo[i]) - 1

		resourceStep := resource.TestStep{
			Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_iac_custom_rule" "rule_%s" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  severity         = "%s"
  remediation_info = [%s]
  alert_info       = [%s]
  logic = <<EOF
%s
EOF
}
`, ruleName, config.resourceType, config.ruleNamePrefix+ruleName, config.description[i],
				config.cloudProvider, config.severity[i], remediationInfo, alertInfo, config.logic[i]),
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("resource_type"), knownvalue.StringExact(config.resourceType)),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(config.ruleNamePrefix+ruleName)),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact(config.description[i])),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cloud_provider"), knownvalue.StringExact(config.cloudProvider)),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("iac_framework"), knownvalue.StringExact("Terraform")),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.StringExact(config.severity[i])),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("alert_info").AtSliceIndex(lastAlertIdx), knownvalue.StringExact(config.alertInfo[i][lastAlertIdx])),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("remediation_info").AtSliceIndex(lastRemediationIdx), knownvalue.StringExact(config.remediationInfo[i][lastRemediationIdx])),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("logic"), knownvalue.StringExact(config.logic[i]+"\n")),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
			},
		}

		importTestStep := resource.TestStep{
			ResourceName:                         resourceName,
			ImportState:                          true,
			ImportStateVerify:                    true,
			ImportStateVerifyIdentifierAttribute: "id",
			ImportStateVerifyIgnore:              []string{"logic"}, // API strips trailing whitespace; semantic equality handles plan-time but not import verify
			ImportStateCheck:                     verifySemanticFields(config.logic[i]+"\n", "", nil),
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

// Minimum configuration for rego rules.
func generateMinimalIacRuleRegoTests(config ruleIacConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	randomSuffix := sdkacctest.RandString(8)
	ruleName = fmt.Sprintf("tfacc_%s_%s", ruleName, randomSuffix)
	resourceName := "crowdstrike_cloud_security_iac_custom_rule.rule" + "_" + ruleName

	for i := range 2 {
		alertInfo := `"` + strings.Join(config.alertInfo[i], `","`) + `"`

		lastAlertIdx := len(config.alertInfo[i]) - 1

		resourceStep := resource.TestStep{
			Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_iac_custom_rule" "rule_%s" {
  name           = "%s"
  description    = "%s"
  cloud_provider = "%s"
  logic = <<EOF
%s
EOF
  alert_info = [%s]
}
`, ruleName, config.ruleNamePrefix+ruleName, config.description[i],
				config.cloudProvider, config.logic[i], alertInfo),
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(config.ruleNamePrefix+ruleName)),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact(config.description[i])),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cloud_provider"), knownvalue.StringExact(config.cloudProvider)),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("iac_framework"), knownvalue.StringExact("Terraform")),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("logic"), knownvalue.StringExact(config.logic[i]+"\n")),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("alert_info").AtSliceIndex(lastAlertIdx), knownvalue.StringExact(config.alertInfo[i][lastAlertIdx])),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.NotNull()),
			},
		}

		importTestStep := resource.TestStep{
			ResourceName:                         resourceName,
			ImportState:                          true,
			ImportStateVerify:                    true,
			ImportStateVerifyIdentifierAttribute: "id",
			ImportStateVerifyIgnore:              []string{"logic"}, // API strips trailing whitespace; semantic equality handles plan-time but not import verify
			ImportStateCheck:                     verifySemanticFields(config.logic[i]+"\n", "", nil),
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

// Validating optional fields (remediation_info, alert_info) can be omitted in-place without replacement.
func generateIacRuleRegoDefinedToOmittedTests(config ruleIacConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	randomSuffix := sdkacctest.RandString(8)
	ruleName = fmt.Sprintf("tfacc_%s_%s", ruleName, randomSuffix)
	resourceName := "crowdstrike_cloud_security_iac_custom_rule.rule" + "_" + ruleName + "_definedToOmitted"

	alertInfo := `"` + strings.Join(config.alertInfo[0], `","`) + `"`
	remediationInfo := `"` + strings.Join(config.remediationInfo[0], `","`) + `"`

	lastAlertIdx := len(config.alertInfo[0]) - 1
	lastRemediationIdx := len(config.remediationInfo[0]) - 1

	definedStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_iac_custom_rule" "rule_%s_definedToOmitted" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  severity         = "%s"
  remediation_info = [%s]
  alert_info = [%s]
  logic = <<EOF
%s
EOF
}
`, ruleName, config.resourceType, config.ruleNamePrefix+ruleName, config.description[0],
			config.cloudProvider, config.severity[0], remediationInfo,
			alertInfo, config.logic[0]),
		ConfigStateChecks: []statecheck.StateCheck{
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("resource_type"), knownvalue.StringExact(config.resourceType)),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(config.ruleNamePrefix+ruleName)),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact(config.description[0])),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cloud_provider"), knownvalue.StringExact(config.cloudProvider)),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("iac_framework"), knownvalue.StringExact("Terraform")),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.StringExact(config.severity[0])),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("logic"), knownvalue.StringExact(config.logic[0]+"\n")),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("alert_info").AtSliceIndex(lastAlertIdx), knownvalue.StringExact(config.alertInfo[0][lastAlertIdx])),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("remediation_info").AtSliceIndex(lastRemediationIdx), knownvalue.StringExact(config.remediationInfo[0][lastRemediationIdx])),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
		},
	}

	undefinedStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_iac_custom_rule" "rule_%s_definedToOmitted" {
  name           = "%s"
  description    = "%s"
  cloud_provider = "%s"
  severity       = "%s"
  logic = <<EOF
%s
EOF
}
`, ruleName, config.ruleNamePrefix+ruleName, config.description[0],
			config.cloudProvider, config.severity[0], config.logic[0]),
		ConfigStateChecks: []statecheck.StateCheck{
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(config.ruleNamePrefix+ruleName)),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact(config.description[0])),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cloud_provider"), knownvalue.StringExact(config.cloudProvider)),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("iac_framework"), knownvalue.StringExact("Terraform")),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.StringExact(config.severity[0])),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("logic"), knownvalue.StringExact(config.logic[0]+"\n")),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("resource_type"), knownvalue.StringExact("Custom")),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("remediation_info"), knownvalue.Null()),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("alert_info"), knownvalue.Null()),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
		},
	}

	steps = append(steps, definedStep)
	steps = append(steps, undefinedStep)

	return steps
}

// Validating optional fields (remediation_info, alert_info) can be updated in place without replacement.
func generateIacRuleInPlaceUpdateTests(config ruleIacConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	randomSuffix := sdkacctest.RandString(8)
	ruleName = fmt.Sprintf("tfacc_%s_%s", ruleName, randomSuffix)
	resourceName := "crowdstrike_cloud_security_iac_custom_rule.rule" + "_" + ruleName + "_inPlaceUpdate"

	alertInfo := `"` + strings.Join(config.alertInfo[0], `","`) + `"`
	remediationInfo := `"` + strings.Join(config.remediationInfo[0], `","`) + `"`

	lastAlertIdx := len(config.alertInfo[0]) - 1
	lastRemediationIdx := len(config.remediationInfo[0]) - 1

	definedStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_iac_custom_rule" "rule_%s_inPlaceUpdate" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  severity         = "%s"
  remediation_info = [%s]
  alert_info   = [%s]
  logic = <<EOF
%s
EOF
}
`, ruleName, config.resourceType, config.ruleNamePrefix+ruleName, config.description[0],
			config.cloudProvider, config.severity[0], remediationInfo,
			alertInfo, config.logic[0]),
		ConfigStateChecks: []statecheck.StateCheck{
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("resource_type"), knownvalue.StringExact(config.resourceType)),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(config.ruleNamePrefix+ruleName)),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact(config.description[0])),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cloud_provider"), knownvalue.StringExact(config.cloudProvider)),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("iac_framework"), knownvalue.StringExact("Terraform")),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.StringExact(config.severity[0])),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("logic"), knownvalue.StringExact(config.logic[0]+"\n")),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("alert_info").AtSliceIndex(lastAlertIdx), knownvalue.StringExact(config.alertInfo[0][lastAlertIdx])),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("remediation_info").AtSliceIndex(lastRemediationIdx), knownvalue.StringExact(config.remediationInfo[0][lastRemediationIdx])),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
		},
	}

	undefinedStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_iac_custom_rule" "rule_%s_inPlaceUpdate" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  severity         = "%s"
  remediation_info = ["Fix this issue"]
  alert_info   = [%s]
  logic = <<EOF
%s
EOF
}
`, ruleName, config.resourceType, config.ruleNamePrefix+ruleName, config.description[0],
			config.cloudProvider, config.severity[0], alertInfo, config.logic[0]),
		ConfigStateChecks: []statecheck.StateCheck{
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("resource_type"), knownvalue.StringExact(config.resourceType)),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(config.ruleNamePrefix+ruleName)),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact(config.description[0])),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cloud_provider"), knownvalue.StringExact(config.cloudProvider)),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("iac_framework"), knownvalue.StringExact("Terraform")),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.StringExact(config.severity[0])),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("logic"), knownvalue.StringExact(config.logic[0]+"\n")),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("alert_info").AtSliceIndex(lastAlertIdx), knownvalue.StringExact(config.alertInfo[0][lastAlertIdx])),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("remediation_info").AtSliceIndex(0), knownvalue.StringExact("Fix this issue")),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
		},
	}

	steps = append(steps, definedStep)
	steps = append(steps, undefinedStep)

	return steps
}

// Test for category and labels fields.
func TestCloudSecurityIacCustomRuleResource_CategoryAndLabels(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIacRuleCategoryAndLabelsTests(terraformIacConfig, "Terraform_CategoryLabels"),
	})
}

func generateIacRuleCategoryAndLabelsTests(config ruleIacConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	randomSuffix := sdkacctest.RandString(8)
	ruleName = fmt.Sprintf("tfacc_%s_%s", ruleName, randomSuffix)
	resourceName := "crowdstrike_cloud_security_iac_custom_rule.rule" + "_" + ruleName

	for i := range 2 {
		alertInfo := `"` + strings.Join(config.alertInfo[i], `","`) + `"`
		labels := `"` + strings.Join(config.labels[i], `","`) + `"`

		lastAlertIdx := len(config.alertInfo[i]) - 1
		lastLabelIdx := len(config.labels[i]) - 1

		resourceStep := resource.TestStep{
			Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_iac_custom_rule" "rule_%s" {
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  severity         = "%s"
  category         = "%s"
  labels           = [%s]
  alert_info       = [%s]
  logic = <<EOF
%s
EOF
}
`, ruleName, config.ruleNamePrefix+ruleName, config.description[i],
				config.cloudProvider, config.severity[i], config.category[i], labels, alertInfo, config.logic[i]),
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(config.ruleNamePrefix+ruleName)),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact(config.description[i])),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cloud_provider"), knownvalue.StringExact(config.cloudProvider)),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("iac_framework"), knownvalue.StringExact("Terraform")),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.StringExact(config.severity[i])),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("category"), knownvalue.StringExact(config.category[i])),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("labels").AtSliceIndex(lastLabelIdx), knownvalue.StringExact(config.labels[i][lastLabelIdx])),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("alert_info").AtSliceIndex(lastAlertIdx), knownvalue.StringExact(config.alertInfo[i][lastAlertIdx])),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("logic"), knownvalue.StringExact(config.logic[i]+"\n")),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
			},
		}

		importTestStep := resource.TestStep{
			ResourceName:                         resourceName,
			ImportState:                          true,
			ImportStateVerify:                    true,
			ImportStateVerifyIdentifierAttribute: "id",
			ImportStateVerifyIgnore:              []string{"category", "labels", "logic"}, // API normalizes casing; semantic equality handles plan-time but not import verify
			ImportStateCheck:                     verifySemanticFields(config.logic[i]+"\n", config.category[i], config.labels[i]),
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

// Test using file() function to load Rego logic from external files.
func TestCloudSecurityIacCustomRuleResource_WithFileFunction(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIacRuleWithFileFunctionTests(terraformIacConfig, "Terraform_FileFunction"),
	})
}

func generateIacRuleWithFileFunctionTests(config ruleIacConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	randomSuffix := sdkacctest.RandString(8)
	ruleName = fmt.Sprintf("tfacc_%s_%s", ruleName, randomSuffix)
	resourceName := "crowdstrike_cloud_security_iac_custom_rule.rule" + "_" + ruleName

	// Test files to use for each iteration
	testFiles := []string{
		"testdata/rego/ssh-rule.rego",
		"testdata/rego/rdp-rule.rego",
	}

	for i := range 2 {
		alertInfo := `"` + strings.Join(config.alertInfo[i], `","`) + `"`
		remediationInfo := `"` + strings.Join(config.remediationInfo[i], `","`) + `"`

		lastAlertIdx := len(config.alertInfo[i]) - 1
		lastRemediationIdx := len(config.remediationInfo[i]) - 1

		resourceStep := resource.TestStep{
			Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_iac_custom_rule" "rule_%s" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  severity         = "%s"
  remediation_info = [%s]
  alert_info       = [%s]
  logic            = file("${path.module}/%s")
}
`, ruleName, config.resourceType, config.ruleNamePrefix+ruleName, config.description[i],
				config.cloudProvider, config.severity[i], remediationInfo, alertInfo, testFiles[i]),
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("resource_type"), knownvalue.StringExact(config.resourceType)),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(config.ruleNamePrefix+ruleName)),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact(config.description[i])),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cloud_provider"), knownvalue.StringExact(config.cloudProvider)),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("iac_framework"), knownvalue.StringExact("Terraform")),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.StringExact(config.severity[i])),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("alert_info").AtSliceIndex(lastAlertIdx), knownvalue.StringExact(config.alertInfo[i][lastAlertIdx])),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("remediation_info").AtSliceIndex(lastRemediationIdx), knownvalue.StringExact(config.remediationInfo[i][lastRemediationIdx])),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("logic"), knownvalue.StringExact(config.logic[i]+"\n")),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
			},
		}

		importTestStep := resource.TestStep{
			ResourceName:                         resourceName,
			ImportState:                          true,
			ImportStateVerify:                    true,
			ImportStateVerifyIdentifierAttribute: "id",
			ImportStateVerifyIgnore:              []string{"logic"}, // API strips trailing whitespace; semantic equality handles plan-time but not import verify
			ImportStateCheck:                     verifySemanticFields(config.logic[i]+"\n", "", nil),
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

// verifySemanticFields creates an ImportStateCheck function that verifies fields with
// semantic equality. Pass empty string for category or nil for labels to skip those checks.
//   - logic: verified with trailing whitespace insensitivity (always checked)
//   - category: verified with case insensitivity (optional - pass "" to skip)
//   - labels: verified with case insensitivity (optional - pass nil to skip)
func verifySemanticFields(expectedLogic, expectedCategory string, expectedLabels []string) resource.ImportStateCheckFunc {
	return func(states []*terraform.InstanceState) error {
		if len(states) == 0 {
			return fmt.Errorf("no instance states found")
		}

		state := states[0]

		// Verify logic with trailing whitespace insensitivity (always checked)
		actualLogic := state.Attributes["logic"]
		expectedLogicTrimmed := strings.TrimRightFunc(expectedLogic, unicode.IsSpace)
		actualLogicTrimmed := strings.TrimRightFunc(actualLogic, unicode.IsSpace)

		if expectedLogicTrimmed != actualLogicTrimmed {
			return fmt.Errorf("logic field mismatch after semantic comparison:\nexpected (trimmed): %q\nactual (trimmed): %q", expectedLogicTrimmed, actualLogicTrimmed)
		}

		// Verify category with case insensitivity (optional)
		if expectedCategory != "" {
			actualCategory := state.Attributes["category"]
			if !strings.EqualFold(expectedCategory, actualCategory) {
				return fmt.Errorf("category field mismatch after case-insensitive comparison:\nexpected: %q\nactual: %q", expectedCategory, actualCategory)
			}
		}

		// Verify labels with case insensitivity (optional)
		if len(expectedLabels) > 0 {
			labelsCount := state.Attributes["labels.#"]
			for i, expectedLabel := range expectedLabels {
				actualLabel := state.Attributes[fmt.Sprintf("labels.%d", i)]
				if !strings.EqualFold(expectedLabel, actualLabel) {
					return fmt.Errorf("labels[%d] field mismatch after case-insensitive comparison:\nexpected: %q\nactual: %q", i, expectedLabel, actualLabel)
				}
			}

			// Verify count matches
			if labelsCount != fmt.Sprintf("%d", len(expectedLabels)) {
				return fmt.Errorf("labels count mismatch:\nexpected: %d\nactual: %s", len(expectedLabels), labelsCount)
			}
		}

		return nil
	}
}

// TestVerifySemanticFields_Unit tests the helper function directly.
func TestVerifySemanticFields_Unit(t *testing.T) {
	tests := []struct {
		name           string
		expectedLogic  string
		expectedCat    string
		expectedLabels []string
		attributes     map[string]string
		shouldPass     bool
	}{
		// logic checks
		{
			name:          "logic exact match",
			expectedLogic: "hello world",
			attributes:    map[string]string{"logic": "hello world"},
			shouldPass:    true,
		},
		{
			name:          "logic trailing newline difference",
			expectedLogic: "hello world\n",
			attributes:    map[string]string{"logic": "hello world"},
			shouldPass:    true,
		},
		{
			name:          "logic multiple trailing newlines",
			expectedLogic: "hello world\n\n\n",
			attributes:    map[string]string{"logic": "hello world"},
			shouldPass:    true,
		},
		{
			name:          "logic content differs",
			expectedLogic: "hello world",
			attributes:    map[string]string{"logic": "goodbye world"},
			shouldPass:    false,
		},
		// category checks
		{
			name:          "category exact match",
			expectedLogic: "logic",
			expectedCat:   "Network Security",
			attributes:    map[string]string{"logic": "logic", "category": "Network Security"},
			shouldPass:    true,
		},
		{
			name:          "category case insensitive match",
			expectedLogic: "logic",
			expectedCat:   "Network Security",
			attributes:    map[string]string{"logic": "logic", "category": "network security"},
			shouldPass:    true,
		},
		{
			name:          "category content differs",
			expectedLogic: "logic",
			expectedCat:   "Network Security",
			attributes:    map[string]string{"logic": "logic", "category": "Data Encryption"},
			shouldPass:    false,
		},
		// labels checks
		{
			name:           "labels exact match",
			expectedLogic:  "logic",
			expectedLabels: []string{"aws", "network"},
			attributes:     map[string]string{"logic": "logic", "labels.#": "2", "labels.0": "aws", "labels.1": "network"},
			shouldPass:     true,
		},
		{
			name:           "labels case insensitive match",
			expectedLogic:  "logic",
			expectedLabels: []string{"AWS", "Network"},
			attributes:     map[string]string{"logic": "logic", "labels.#": "2", "labels.0": "aws", "labels.1": "network"},
			shouldPass:     true,
		},
		{
			name:           "labels content differs",
			expectedLogic:  "logic",
			expectedLabels: []string{"aws", "network"},
			attributes:     map[string]string{"logic": "logic", "labels.#": "2", "labels.0": "aws", "labels.1": "storage"},
			shouldPass:     false,
		},
		{
			name:           "labels count mismatch",
			expectedLogic:  "logic",
			expectedLabels: []string{"aws", "network"},
			attributes:     map[string]string{"logic": "logic", "labels.#": "1", "labels.0": "aws"},
			shouldPass:     false,
		},
		// empty states
		{
			name:          "no instance states",
			expectedLogic: "logic",
			attributes:    nil,
			shouldPass:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var states []*terraform.InstanceState
			if tt.attributes != nil {
				states = []*terraform.InstanceState{
					{Attributes: tt.attributes},
				}
			}

			checkFunc := verifySemanticFields(tt.expectedLogic, tt.expectedCat, tt.expectedLabels)
			err := checkFunc(states)

			if tt.shouldPass && err != nil {
				t.Errorf("expected check to pass, but got error: %v", err)
			}
			if !tt.shouldPass && err == nil {
				t.Errorf("expected check to fail, but it passed")
			}
		})
	}
}
