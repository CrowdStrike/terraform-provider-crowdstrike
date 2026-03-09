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

// AWS Tests.
func TestCloudSecurityIomCustomRuleResource_AWS_Copy(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleCopyTests(awsCopyConfig, "AWS"),
	})
}

func TestCloudSecurityIomCustomRuleResource_AWS_Rego(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleLogicTests(awsCopyConfig, "AWS_Rego"),
	})
}

func TestCloudSecurityIomCustomRuleResource_AWS_Minimal(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateMinimalIomRuleCopyTests(awsCopyConfig, "AWS_Min"),
	})
}

func TestCloudSecurityIomCustomRuleResource_AWS_MinimalRego(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateMinimalIomRuleLogicTests(awsCopyConfig, "AWS_Min_Rego"),
	})
}

func TestCloudSecurityIomCustomRuleResource_AWS_DefinedToOmitted(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleCopyDefinedToOmittedTests(awsCopyConfig, "AWS_Omit"),
	})
}

func TestCloudSecurityIomCustomRuleResource_AWS_RegoDefinedToOmitted(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleRegoDefinedToOmittedTests(awsCopyConfig, "AWS_Omit_Rego"),
	})
}

func TestCloudSecurityIomCustomRuleResource_AWS_RegoDefinedToEmpty(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleRegoDefinedToEmptyTests(awsCopyConfig, "AWS_Empty_Rego"),
	})
}

func TestCloudSecurityIomCustomRuleResource_AWS_CopyDefinedToEmpty(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleCopyDefinedToEmptyTests(awsCopyConfig),
	})
}

func TestCloudSecurityIomCustomRuleResource_AWS_CopyDefinedAttackType(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleCopyDefinedAttackTypeTests(awsCopyConfig),
	})
}

func TestCloudSecurityIomCustomRuleResource_AWS_CopyInheritToEmptyToInherit(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleCopyInheritToEmptyToInheritTests(awsCopyConfig, "AWS_InheritCycle"),
	})
}

func TestCloudSecurityIomCustomRuleResource_AWS_CopyEmptyOnCreate(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleCopyEmptyOnCreateTests(awsCopyConfig, "AWS_EmptyCreate"),
	})
}

// Azure Tests.
func TestCloudSecurityIomCustomRuleResource_Azure_Copy(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleCopyTests(azureCopyConfig, "Azure"),
	})
}

func TestCloudSecurityIomCustomRuleResource_Azure_Rego(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleLogicTests(azureCopyConfig, "Azure_Rego"),
	})
}

func TestCloudSecurityIomCustomRuleResource_Azure_Minimal(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateMinimalIomRuleCopyTests(azureCopyConfig, "Azure_Min"),
	})
}

func TestCloudSecurityIomCustomRuleResource_Azure_MinimalRego(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateMinimalIomRuleLogicTests(azureCopyConfig, "Azure_Min_Rego"),
	})
}

func TestCloudSecurityIomCustomRuleResource_Azure_DefinedToOmitted(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleCopyDefinedToOmittedTests(azureCopyConfig, "Azure_Omit"),
	})
}

func TestCloudSecurityIomCustomRuleResource_Azure_RegoDefinedToOmitted(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleRegoDefinedToOmittedTests(azureCopyConfig, "Azure_Omit_Rego"),
	})
}

func TestCloudSecurityIomCustomRuleResource_Azure_RegoDefinedToEmpty(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleRegoDefinedToEmptyTests(azureCopyConfig, "Azure_Empty_Rego"),
	})
}

func TestCloudSecurityIomCustomRuleResource_Azure_CopyDefinedToEmpty(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleCopyDefinedToEmptyTests(azureCopyConfig),
	})
}

func TestCloudSecurityIomCustomRuleResource_Azure_CopyDefinedAttackType(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleCopyDefinedAttackTypeTests(azureCopyConfig),
	})
}

func TestCloudSecurityIomCustomRuleResource_Azure_CopyInheritToEmptyToInherit(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleCopyInheritToEmptyToInheritTests(azureCopyConfig, "Azure_InheritCycle"),
	})
}

func TestCloudSecurityIomCustomRuleResource_Azure_CopyEmptyOnCreate(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleCopyEmptyOnCreateTests(azureCopyConfig, "Azure_EmptyCreate"),
	})
}

// GCP Tests.
func TestCloudSecurityIomCustomRuleResource_GCP_Copy(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleCopyTests(gcpCopyConfig, "GCP"),
	})
}

func TestCloudSecurityIomCustomRuleResource_GCP_Rego(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleLogicTests(gcpCopyConfig, "GCP_Rego"),
	})
}

func TestCloudSecurityIomCustomRuleResource_GCP_Minimal(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateMinimalIomRuleCopyTests(gcpCopyConfig, "GCP_Min"),
	})
}

func TestCloudSecurityIomCustomRuleResource_GCP_MinimalRego(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateMinimalIomRuleLogicTests(gcpCopyConfig, "GCP_Min_Rego"),
	})
}

func TestCloudSecurityIomCustomRuleResource_GCP_DefinedToOmitted(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleCopyDefinedToOmittedTests(gcpCopyConfig, "GCP_Omit"),
	})
}

func TestCloudSecurityIomCustomRuleResource_GCP_RegoDefinedToOmitted(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleRegoDefinedToOmittedTests(gcpCopyConfig, "GCP_Omit_Rego"),
	})
}

func TestCloudSecurityIomCustomRuleResource_GCP_RegoDefinedToEmpty(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleRegoDefinedToEmptyTests(gcpCopyConfig, "GCP_Empty_Rego"),
	})
}

func TestCloudSecurityIomCustomRuleResource_GCP_CopyDefinedToEmpty(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleCopyDefinedToEmptyTests(gcpCopyConfig),
	})
}

func TestCloudSecurityIomCustomRuleResource_GCP_CopyDefinedAttackType(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleCopyDefinedAttackTypeTests(gcpCopyConfig),
	})
}

func TestCloudSecurityIomCustomRuleResource_GCP_CopyInheritToEmptyToInherit(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleCopyInheritToEmptyToInheritTests(gcpCopyConfig, "GCP_InheritCycle"),
	})
}

func TestCloudSecurityIomCustomRuleResource_GCP_CopyEmptyOnCreate(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleCopyEmptyOnCreateTests(gcpCopyConfig, "GCP_EmptyCreate"),
	})
}

// OCI Tests.
func TestCloudSecurityIomCustomRuleResource_OCI_Copy(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleCopyTests(ociCopyConfig, "OCI"),
	})
}

func TestCloudSecurityIomCustomRuleResource_OCI_Rego(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleLogicTests(ociCopyConfig, "OCI_Rego"),
	})
}

func TestCloudSecurityIomCustomRuleResource_OCI_Minimal(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateMinimalIomRuleCopyTests(ociCopyConfig, "OCI_Min"),
	})
}

func TestCloudSecurityIomCustomRuleResource_OCI_MinimalRego(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateMinimalIomRuleLogicTests(ociCopyConfig, "OCI_Min_Rego"),
	})
}

func TestCloudSecurityIomCustomRuleResource_OCI_DefinedToOmitted(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleCopyDefinedToOmittedTests(ociCopyConfig, "OCI_Omit"),
	})
}

func TestCloudSecurityIomCustomRuleResource_OCI_RegoDefinedToOmitted(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleRegoDefinedToOmittedTests(ociCopyConfig, "OCI_Omit_Rego"),
	})
}

func TestCloudSecurityIomCustomRuleResource_OCI_RegoDefinedToEmpty(t *testing.T) {
	skipIfRegoNotEnabled(t)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleRegoDefinedToEmptyTests(ociCopyConfig, "OCI_Empty_Rego"),
	})
}

func TestCloudSecurityIomCustomRuleResource_OCI_CopyDefinedToEmpty(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleCopyDefinedToEmptyTests(ociCopyConfig),
	})
}

func TestCloudSecurityIomCustomRuleResource_OCI_CopyDefinedAttackType(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleCopyDefinedAttackTypeTests(ociCopyConfig),
	})
}

func TestCloudSecurityIomCustomRuleResource_OCI_CopyInheritToEmptyToInherit(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleCopyInheritToEmptyToInheritTests(ociCopyConfig, "OCI_InheritCycle"),
	})
}

func TestCloudSecurityIomCustomRuleResource_OCI_CopyEmptyOnCreate(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    generateIomRuleCopyEmptyOnCreateTests(ociCopyConfig, "OCI_EmptyCreate"),
	})
}

// In-place updates of user defined remediation_info, alert_info, and controls for duplicate rules.
func generateIomRuleCopyTests(config ruleCustomConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	randomSuffix := sdkacctest.RandString(8)
	ruleName = fmt.Sprintf("tfacc_%s_%s", ruleName, randomSuffix)
	resourceName := "crowdstrike_cloud_security_iom_custom_rule.rule" + "_" + ruleName

	for i := range 2 {
		alertInfo := strings.Join([]string{
			`"` + strings.Join(config.alertInfo[i], `","`) + `"`,
		}, "")
		remediationInfo := strings.Join([]string{
			`"` + strings.Join(config.remediationInfo[i], `","`) + `"`,
		}, "")
		resourceStep := resource.TestStep{
			Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_iom_custom_rule" "rule_%s" {
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
}
`, ruleName, config.resourceType, config.ruleNamePrefix+ruleName, config.description[i],
				config.cloudProvider, config.severity[i], remediationInfo,
				testGenerateControlBlock(config.controls[i]), alertInfo,
				config.parentRule.ruleName, config.parentRule.benchmark),
			Check: resource.ComposeAggregateTestCheckFunc(
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
func generateIomRuleLogicTests(config ruleCustomConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	randomSuffix := sdkacctest.RandString(8)
	ruleName = fmt.Sprintf("tfacc_%s_%s", ruleName, randomSuffix)
	resourceName := "crowdstrike_cloud_security_iom_custom_rule.rule" + "_" + ruleName

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
resource "crowdstrike_cloud_security_iom_custom_rule" "rule_%s" {
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
func generateMinimalIomRuleCopyTests(config ruleCustomConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	randomSuffix := sdkacctest.RandString(8)
	ruleName = fmt.Sprintf("tfacc_%s_%s", ruleName, randomSuffix)
	resourceName := "crowdstrike_cloud_security_iom_custom_rule.rule" + "_" + ruleName

	for i := range 2 {
		newStep := resource.TestStep{
			Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_iom_custom_rule" "rule_%s" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  parent_rule_id   = one(data.crowdstrike_cloud_security_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_security_rules" "rule_%[1]s" {
  rule_name = "%[6]s"
}
`, ruleName, config.resourceType, config.ruleNamePrefix+ruleName, config.description[i],
				config.cloudProvider, config.parentRule.ruleName, config.parentRule.benchmark),
			Check: resource.ComposeAggregateTestCheckFunc(
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
func generateMinimalIomRuleLogicTests(config ruleCustomConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	randomSuffix := sdkacctest.RandString(8)
	ruleName = fmt.Sprintf("tfacc_%s_%s", ruleName, randomSuffix)
	resourceName := "crowdstrike_cloud_security_iom_custom_rule.rule" + "_" + ruleName

	for i := range 2 {
		resourceStep := resource.TestStep{
			Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_iom_custom_rule" "rule_%s" {
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
func generateIomRuleCopyDefinedToOmittedTests(config ruleCustomConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	randomSuffix := sdkacctest.RandString(8)
	ruleName = fmt.Sprintf("tfacc_%s_%s", ruleName, randomSuffix)
	resourceName := "crowdstrike_cloud_security_iom_custom_rule.rule" + "_" + ruleName + "_definedToOmitted"

	alertInfo := strings.Join([]string{
		`"` + strings.Join(config.alertInfo[0], `","`) + `"`,
	}, "")
	remediationInfo := strings.Join([]string{
		`"` + strings.Join(config.remediationInfo[0], `","`) + `"`,
	}, "")

	definedStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_iom_custom_rule" "rule_%s_definedToOmitted" {
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
}
`, ruleName, config.resourceType, config.ruleNamePrefix+ruleName, config.description[0],
			config.cloudProvider, config.severity[0], remediationInfo,
			testGenerateControlBlock(config.controls[0]), alertInfo,
			config.parentRule.ruleName, config.parentRule.benchmark),
		Check: resource.ComposeAggregateTestCheckFunc(
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
resource "crowdstrike_cloud_security_iom_custom_rule" "rule_%s_definedToOmitted" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  severity         = "%s"
  parent_rule_id   = one(data.crowdstrike_cloud_security_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_security_rules" "rule_%[1]s" {
  rule_name = "%[7]s"
}
`, ruleName, config.resourceType, config.ruleNamePrefix+ruleName, config.description[0],
			config.cloudProvider, config.severity[0], config.parentRule.ruleName, config.parentRule.benchmark),
		Check: resource.ComposeAggregateTestCheckFunc(
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
func generateIomRuleCopyDefinedToEmptyTests(config ruleCustomConfig) []resource.TestStep {
	var steps []resource.TestStep
	randomSuffix := sdkacctest.RandString(8)
	resourceName := fmt.Sprintf("tfacc_definedToEmptyCopyRule_%s", randomSuffix)
	fullResourceName := fmt.Sprintf("crowdstrike_cloud_security_iom_custom_rule.%s", resourceName)

	alertInfo := strings.Join([]string{
		`"` + strings.Join(config.alertInfo[0], `","`) + `"`,
	}, "")
	remediationInfo := strings.Join([]string{
		`"` + strings.Join(config.remediationInfo[0], `","`) + `"`,
	}, "")

	definedStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_iom_custom_rule" "%s" {
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
}
`, resourceName, config.resourceType, config.ruleNamePrefix+resourceName, config.description[0],
			config.cloudProvider, config.severity[0], remediationInfo,
			testGenerateControlBlock(config.controls[0]), alertInfo,
			config.parentRule.ruleName, config.parentRule.benchmark),
		Check: resource.ComposeAggregateTestCheckFunc(
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
resource "crowdstrike_cloud_security_iom_custom_rule" "%s" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  severity         = "%s"
  parent_rule_id   = one(data.crowdstrike_cloud_security_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_security_rules" "rule_%[1]s" {
  rule_name = "%[9]s"
}
`, resourceName, config.resourceType, config.ruleNamePrefix+resourceName, config.description[0],
			config.cloudProvider, config.severity[0], testGenerateControlBlock(config.controls[0]),
			remediationInfo, config.parentRule.ruleName, config.parentRule.benchmark),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(fullResourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(fullResourceName, "name", config.ruleNamePrefix+resourceName),
			resource.TestCheckResourceAttr(fullResourceName, "description", config.description[0]),
			resource.TestCheckResourceAttr(fullResourceName, "cloud_platform", config.cloudPlatform),
			resource.TestCheckResourceAttr(fullResourceName, "cloud_provider", config.cloudProvider),
			resource.TestCheckResourceAttr(fullResourceName, "severity", config.severity[0]),
			resource.TestMatchResourceAttr(fullResourceName, "controls.#", regexp.MustCompile(`^[1-9]\d*$`)),
			resource.TestMatchResourceAttr(fullResourceName, "alert_info.#", regexp.MustCompile(`^[1-9]\d*$`)),
			resource.TestMatchResourceAttr(fullResourceName, "remediation_info.#", regexp.MustCompile(`^[1-9]\d*$`)),
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
func generateIomRuleRegoDefinedToOmittedTests(config ruleCustomConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	randomSuffix := sdkacctest.RandString(8)
	ruleName = fmt.Sprintf("tfacc_%s_%s", ruleName, randomSuffix)
	resourceName := "crowdstrike_cloud_security_iom_custom_rule.rule" + "_" + ruleName + "_definedToOmitted"

	alertInfo := strings.Join([]string{
		`"` + strings.Join(config.alertInfo[0], `","`) + `"`,
	}, "")
	remediationInfo := strings.Join([]string{
		`"` + strings.Join(config.remediationInfo[0], `","`) + `"`,
	}, "")

	definedStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_iom_custom_rule" "rule_%s_definedToOmitted" {
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
resource "crowdstrike_cloud_security_iom_custom_rule" "rule_%s_definedToOmitted" {
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
func generateIomRuleRegoDefinedToEmptyTests(config ruleCustomConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	randomSuffix := sdkacctest.RandString(8)
	ruleName = fmt.Sprintf("tfacc_%s_%s", ruleName, randomSuffix)
	resourceName := "crowdstrike_cloud_security_iom_custom_rule.rule" + "_" + ruleName + "_definedToEmpty"

	alertInfo := strings.Join([]string{
		`"` + strings.Join(config.alertInfo[0], `","`) + `"`,
	}, "")
	remediationInfo := strings.Join([]string{
		`"` + strings.Join(config.remediationInfo[0], `","`) + `"`,
	}, "")

	definedStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_iom_custom_rule" "rule_%s_definedToEmpty" {
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
resource "crowdstrike_cloud_security_iom_custom_rule" "rule_%s_definedToEmpty" {
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
func generateIomRuleCopyDefinedAttackTypeTests(config ruleCustomConfig) []resource.TestStep {
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
resource "crowdstrike_cloud_security_iom_custom_rule" "%s" {
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

// Test inheritance cycle: inherit from parent -> set to empty -> inherit from parent again.
func generateIomRuleCopyInheritToEmptyToInheritTests(config ruleCustomConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	randomSuffix := sdkacctest.RandString(8)
	ruleName = fmt.Sprintf("tfacc_%s_%s", ruleName, randomSuffix)
	resourceName := "crowdstrike_cloud_security_iom_custom_rule.rule" + "_" + ruleName

	// Step 1: Create minimal copy rule - should inherit controls, remediation_info, and alert_info from parent
	inheritStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_iom_custom_rule" "rule_%s" {
  resource_type  = "%s"
  name           = "%s"
  description    = "%s - Step 1"
  cloud_provider = "%s"
  severity       = "%s"
  parent_rule_id = one(data.crowdstrike_cloud_security_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_security_rules" "rule_%[1]s" {
  rule_name = "%[7]s"
}
`, ruleName, config.resourceType, config.ruleNamePrefix+ruleName,
			config.description[0], config.cloudProvider, config.severity[0],
			config.parentRule.ruleName, config.parentRule.benchmark),
		Check: resource.ComposeAggregateTestCheckFunc(
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
resource "crowdstrike_cloud_security_iom_custom_rule" "rule_%s" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s - Step 2"
  cloud_provider   = "%s"
  severity         = "%s"
  parent_rule_id   = one(data.crowdstrike_cloud_security_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_security_rules" "rule_%[1]s" {
  rule_name = "%[7]s"
}
`, ruleName, config.resourceType, config.ruleNamePrefix+ruleName,
			config.description[0], config.cloudProvider, config.severity[0],
			config.parentRule.ruleName, config.parentRule.benchmark),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(resourceName, "resource_type", config.resourceType),
			resource.TestCheckResourceAttr(resourceName, "name", config.ruleNamePrefix+ruleName),
			resource.TestCheckResourceAttr(resourceName, "description", config.description[0]+" - Step 2"),
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

	// Step 3: Remove the explicit fields - should inherit from parent again
	inheritAgainStep := resource.TestStep{
		Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_iom_custom_rule" "rule_%s" {
  resource_type  = "%s"
  name           = "%s"
  description    = "%s - Step 3"
  cloud_provider = "%s"
  severity       = "%s"
  parent_rule_id = one(data.crowdstrike_cloud_security_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_security_rules" "rule_%[1]s" {
  rule_name = "%[7]s"
}
`, ruleName, config.resourceType, config.ruleNamePrefix+ruleName,
			config.description[0], config.cloudProvider, config.severity[0],
			config.parentRule.ruleName, config.parentRule.benchmark),
		Check: resource.ComposeAggregateTestCheckFunc(
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
func generateIomRuleCopyEmptyOnCreateTests(config ruleCustomConfig, ruleName string) []resource.TestStep {
	var steps []resource.TestStep
	randomSuffix := sdkacctest.RandString(8)
	ruleName = fmt.Sprintf("tfacc_%s_%s", ruleName, randomSuffix)
	resourceName := "crowdstrike_cloud_security_iom_custom_rule.rule" + "_" + ruleName

	configStr := fmt.Sprintf(`
resource "crowdstrike_cloud_security_iom_custom_rule" "rule_%s" {
  resource_type    = "%s"
  name             = "%s"
  description      = "%s"
  cloud_provider   = "%s"
  severity         = "%s"
  parent_rule_id   = one(data.crowdstrike_cloud_security_rules.rule_%[1]s.rules).id
}

data "crowdstrike_cloud_security_rules" "rule_%[1]s" {
  rule_name = "%[7]s"
}
`, ruleName, config.resourceType, config.ruleNamePrefix+ruleName,
		config.description[0], config.cloudProvider, config.severity[0],
		config.parentRule.ruleName, config.parentRule.benchmark)

	createStep := resource.TestStep{
		Config: configStr,
		Check: resource.ComposeAggregateTestCheckFunc(
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
