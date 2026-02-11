// Package cloudsecurity_test contains acceptance tests for the CrowdStrike Terraform Provider
// cloud security resources.
//
// This file specifically tests the crowdstrike_cloud_security_kac_custom_rule resource,
// which manages KAC (Kubernetes Admission Controller) custom rules.
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

// TestCloudSecurityKacCustomRuleResource_Basic tests basic CRUD operations.
func TestCloudSecurityKacCustomRuleResource_Basic(t *testing.T) {
	skipIfRegoNotEnabled(t)
	randomSuffix := sdkacctest.RandString(8)
	resourceName := fmt.Sprintf("crowdstrike_cloud_security_kac_custom_rule.test_%s", randomSuffix)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testCloudSecurityKacCustomRuleResourceConfig_basic(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("Terraform Test KAC Rule %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "description", "This is a test KAC custom rule"),
					resource.TestCheckResourceAttr(resourceName, "severity", "critical"),
					resource.TestCheckResourceAttr(resourceName, "logic", "package crowdstrike\n\nimport rego.v1\n\ndefault result := \"fail\"\n\nresult := \"pass\" if {\n\tinput.metadata.name == \"test-pod\"\n}\n"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestMatchResourceAttr(resourceName, "id", regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)),
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
			{
				Config: testCloudSecurityKacCustomRuleResourceConfig_updated(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("Terraform Test KAC Rule %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "description", "This is an updated test KAC custom rule"),
					resource.TestCheckResourceAttr(resourceName, "severity", "high"),
					resource.TestCheckResourceAttr(resourceName, "logic", "package crowdstrike\n\nimport rego.v1\n\ndefault result := \"fail\"\n\nresult := \"pass\" if {\n\tinput.metadata.name == \"updated-test-pod\"\n}\n"),
					resource.TestCheckResourceAttr(resourceName, "remediation_info.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "remediation_info.0", "Review and update pod security policies"),
					resource.TestCheckResourceAttr(resourceName, "remediation_info.1", "Implement network segmentation"),
					resource.TestCheckResourceAttr(resourceName, "attack_types.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "attack_types.*", "data-exfiltration"),
					resource.TestCheckResourceAttr(resourceName, "alert_info.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "alert_info.0", "Updated alert - Monitor for pod privilege escalation attempts"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

// TestCloudSecurityKacCustomRuleResource_DataSourceIntegration tests that a newly created KAC rule
// can be found via the rules data source.
func TestCloudSecurityKacCustomRuleResource_DataSourceIntegration(t *testing.T) {
	skipIfRegoNotEnabled(t)
	randomSuffix := sdkacctest.RandString(8)
	resourceName := fmt.Sprintf("crowdstrike_cloud_security_kac_custom_rule.test_%s", randomSuffix)
	dataSourceName := fmt.Sprintf("data.crowdstrike_cloud_security_rules.test_%s", randomSuffix)
	ruleName := fmt.Sprintf("Data Source Test KAC Rule %s", randomSuffix)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testCloudSecurityKacCustomRuleResourceConfig_withDataSource(randomSuffix, ruleName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", ruleName),
					resource.TestCheckResourceAttr(resourceName, "severity", "high"),
					resource.TestCheckResourceAttr(dataSourceName, "rules.#", "1"),
					resource.TestCheckResourceAttrPair(dataSourceName, "rules.0.id", resourceName, "id"),
					resource.TestCheckResourceAttrPair(dataSourceName, "rules.0.name", resourceName, "name"),
					resource.TestCheckResourceAttr(dataSourceName, "rules.0.rule_origin", "Custom"),
					resource.TestCheckResourceAttrSet(dataSourceName, "rules.0.logic"),
					resource.TestCheckResourceAttrSet(dataSourceName, "rules.0.severity"),
					resource.TestCheckResourceAttrSet(dataSourceName, "rules.0.description"),
				),
			},
		},
	})
}

func testCloudSecurityKacCustomRuleResourceConfig_basic(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_kac_custom_rule" "test_%s" {
  name        = "Terraform Test KAC Rule %s"
  description = "This is a test KAC custom rule"
  severity    = "critical"
  logic = <<EOF
package crowdstrike

import rego.v1

default result := "fail"

result := "pass" if {
	input.metadata.name == "test-pod"
}
EOF
}
`, suffix, suffix)
}

func testCloudSecurityKacCustomRuleResourceConfig_updated(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_kac_custom_rule" "test_%s" {
  name        = "Terraform Test KAC Rule %s"
  description = "This is an updated test KAC custom rule"
  severity    = "high"

  remediation_info = [
    "Review and update pod security policies",
    "Implement network segmentation"
  ]

  attack_types = [
    "data-exfiltration"
  ]

  alert_info = [
    "Updated alert - Monitor for pod privilege escalation attempts"
  ]

  logic = <<EOF
package crowdstrike

import rego.v1

default result := "fail"

result := "pass" if {
	input.metadata.name == "updated-test-pod"
}
EOF
}
`, suffix, suffix)
}

func testCloudSecurityKacCustomRuleResourceConfig_withDataSource(suffix, ruleName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_kac_custom_rule" "test_%s" {
  name        = "%s"
  description = "Test KAC rule for data source integration"
  severity    = "high"

  logic = <<EOF
package crowdstrike

import rego.v1

default result := "fail"

result := "pass" if {
	input.metadata.namespace != "default"
}
EOF
}

data "crowdstrike_cloud_security_rules" "test_%s" {
  rule_name = crowdstrike_cloud_security_kac_custom_rule.test_%s.name
  rule_origin = "Custom"
}
`, suffix, ruleName, suffix, suffix)
}
