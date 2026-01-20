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
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
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
			// Create and Read testing
			{
				Config: testCloudSecurityKacCustomRuleResourceConfig_basic(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("Terraform Test KAC Rule %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "description", "This is a test KAC custom rule"),
					resource.TestCheckResourceAttr(resourceName, "severity", "critical"),
					resource.TestCheckResourceAttr(resourceName, "logic", "import rego.v1\n\ndefault result := \"fail\"\n\nresult := \"pass\" if {\n\tinput.metadata.name == \"test-pod\"\n}\n"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestMatchResourceAttr(resourceName, "id", regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)),
				),
			},
			// ImportState testing
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
			// Update and Read testing
			{
				Config: testCloudSecurityKacCustomRuleResourceConfig_updated(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("Terraform Test KAC Rule %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "description", "This is an updated test KAC custom rule"),
					resource.TestCheckResourceAttr(resourceName, "severity", "high"),
					resource.TestCheckResourceAttr(resourceName, "logic", "import rego.v1\n\ndefault result := \"fail\"\n\nresult := \"pass\" if {\n\tinput.metadata.name == \"updated-test-pod\"\n}\n"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

// TestCloudSecurityKacCustomRuleResource_MinimalConfig tests minimal required configuration.
func TestCloudSecurityKacCustomRuleResource_MinimalConfig(t *testing.T) {
	skipIfRegoNotEnabled(t)
	randomSuffix := sdkacctest.RandString(8)
	resourceName := fmt.Sprintf("crowdstrike_cloud_security_kac_custom_rule.test_%s", randomSuffix)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testCloudSecurityKacCustomRuleResourceConfig_minimal(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("Minimal KAC Rule %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "description", "Minimal configuration"),
					resource.TestCheckResourceAttr(resourceName, "severity", "critical"), // Should default to critical
					resource.TestCheckResourceAttr(resourceName, "logic", "import rego.v1\n\ndefault result := \"pass\"\n"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

// TestCloudSecurityKacCustomRuleResource_SeverityValidation tests severity field validation.
func TestCloudSecurityKacCustomRuleResource_SeverityValidation(t *testing.T) {
	skipIfRegoNotEnabled(t)
	randomSuffix := sdkacctest.RandString(8)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testCloudSecurityKacCustomRuleResourceConfig_invalidSeverity(randomSuffix),
				ExpectError: regexp.MustCompile("Attribute severity value must be one of"),
				PlanOnly:    true,
			},
		},
	})
}

// TestCloudSecurityKacCustomRuleResource_MissingLogic tests that logic is required.
func TestCloudSecurityKacCustomRuleResource_MissingLogic(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testCloudSecurityKacCustomRuleResourceConfig_missingLogic(randomSuffix),
				ExpectError: regexp.MustCompile("Missing required argument"),
				PlanOnly:    true,
			},
		},
	})
}

// TestCloudSecurityKacCustomRuleResource_AllSeverities tests all valid severity values.
func TestCloudSecurityKacCustomRuleResource_AllSeverities(t *testing.T) {
	skipIfRegoNotEnabled(t)
	randomSuffix := sdkacctest.RandString(8)
	severities := []string{"critical", "high", "medium", "informational"}

	for _, severity := range severities {
		t.Run(fmt.Sprintf("severity_%s", severity), func(t *testing.T) {
			resourceName := fmt.Sprintf("crowdstrike_cloud_security_kac_custom_rule.test_%s_%s", severity, randomSuffix)

			resource.ParallelTest(t, resource.TestCase{
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				PreCheck:                 func() { acctest.PreCheck(t) },
				Steps: []resource.TestStep{
					{
						Config: testCloudSecurityKacCustomRuleResourceConfig_withSeverity(randomSuffix, severity),
						Check: resource.ComposeAggregateTestCheckFunc(
							resource.TestCheckResourceAttr(resourceName, "severity", severity),
							resource.TestCheckResourceAttrSet(resourceName, "id"),
						),
					},
				},
			})
		})
	}
}

// TestCloudSecurityKacCustomRuleResource_NameRequiresReplace tests that name changes require replacement.
func TestCloudSecurityKacCustomRuleResource_NameRequiresReplace(t *testing.T) {
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
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				Config: testCloudSecurityKacCustomRuleResourceConfig_newName(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("New Terraform Test KAC Rule %s", randomSuffix)),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
			},
		},
	})
}

// Test configuration functions

func testCloudSecurityKacCustomRuleResourceConfig_basic(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_kac_custom_rule" "test_%s" {
  name        = "Terraform Test KAC Rule %s"
  description = "This is a test KAC custom rule"
  severity    = "critical"
  logic = <<EOF
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
  logic = <<EOF
import rego.v1

default result := "fail"

result := "pass" if {
	input.metadata.name == "updated-test-pod"
}
EOF
}
`, suffix, suffix)
}

func testCloudSecurityKacCustomRuleResourceConfig_minimal(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_kac_custom_rule" "test_%s" {
  name        = "Minimal KAC Rule %s"
  description = "Minimal configuration"
  logic = <<EOF
import rego.v1

default result := "pass"
EOF
}
`, suffix, suffix)
}

func testCloudSecurityKacCustomRuleResourceConfig_invalidSeverity(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_kac_custom_rule" "test_%s" {
  name        = "Invalid Severity KAC Rule %s"
  description = "Rule with invalid severity"
  severity    = "invalid"
  logic = <<EOF
import rego.v1

default result := "pass"
EOF
}
`, suffix, suffix)
}

func testCloudSecurityKacCustomRuleResourceConfig_missingLogic(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_kac_custom_rule" "test_%s" {
  name        = "Missing Logic KAC Rule %s"
  description = "Rule missing required logic"
  severity    = "high"
}
`, suffix, suffix)
}

func testCloudSecurityKacCustomRuleResourceConfig_withSeverity(suffix, severity string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_kac_custom_rule" "test_%s_%s" {
  name        = "KAC Rule %s Severity %s"
  description = "Rule with %s severity"
  severity    = "%s"
  logic = <<EOF
import rego.v1

default result := "pass"
EOF
}
`, severity, suffix, severity, suffix, severity, severity)
}

func testCloudSecurityKacCustomRuleResourceConfig_newName(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_kac_custom_rule" "test_%s" {
  name        = "New Terraform Test KAC Rule %s"
  description = "This is a test KAC custom rule"
  severity    = "critical"
  logic = <<EOF
import rego.v1

default result := "fail"

result := "pass" if {
	input.metadata.name == "test-pod"
}
EOF
}
`, suffix, suffix)
}
