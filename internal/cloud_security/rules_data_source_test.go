package cloudsecurity_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestCloudSecurityRulesDatasourceConfigConflicts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    testDatasourceConfigConflicts(),
	})
}

func TestCloudSecurityRulesDatasourceEmptyResultSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    testEmptyResultSet(),
	})
}

func TestCloudSecurityRulesDatasourceAWS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    testCloudRules(awsConfig),
	})
}

func TestCloudSecurityRulesDatasourceAzure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    testCloudRules(azureConfig),
	})
}

func TestCloudSecurityRulesDatasourceGCP(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    testCloudRules(gcpConfig),
	})
}

func TestCloudSecurityRulesDatasourceWildcardPatterns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    testWildcardPatterns(awsConfig),
	})
}

func testCloudRules(config dataRuleConfig) (steps []resource.TestStep) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := fmt.Sprintf("data.crowdstrike_cloud_security_rules.%s", config.cloudProvider)
	steps = []resource.TestStep{
		{
			Config: fmt.Sprintf(`
		data "crowdstrike_cloud_security_rules" "%[1]s" {
		  cloud_provider = "%[1]s"
		  resource_type  = "%[2]s"
		}
		`, config.cloudProvider, config.resourceType),
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.NotNull()),
			},
		},
		{
			Config: fmt.Sprintf(`
				data "crowdstrike_cloud_security_rules" "%[1]s" {
				  cloud_provider = "%[1]s"
				  rule_name = "%[2]s"
				}
				`, config.cloudProvider, config.ruleName),
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(1)),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("id"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("remediation_info"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("alert_info"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("severity"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("domain"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("name"), knownvalue.StringExact(config.ruleName)),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("controls"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("cloud_provider"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("attack_types"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("resource_type"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("subdomain"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("rule_origin"), knownvalue.NotNull()),
			},
		},
		{
			Config: fmt.Sprintf(`
		data "crowdstrike_cloud_security_rules" "%[1]s" {
		  cloud_provider = "%[1]s"
		  rule_name = "%[2]s"
		  benchmark = "%[3]s"
		  framework = "%[4]s"
		  service = "%[5]s"
		}
		`, config.cloudProvider, config.ruleName, config.benchmark, config.framework, config.service),
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(1)),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("id"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("remediation_info"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("alert_info"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("severity"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("domain"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("name"), knownvalue.StringExact(config.ruleName)),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("controls"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("cloud_provider"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("attack_types"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("resource_type"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("subdomain"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("rule_origin"), knownvalue.NotNull()),
			},
		},
		{
			Config: fmt.Sprintf(`
		data "crowdstrike_cloud_security_rules" "%s" {
		  fql = "rule_name:'%s'"
		}
		`, config.cloudProvider, config.ruleName),
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(1)),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("id"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("remediation_info"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("alert_info"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("severity"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("domain"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("name"), knownvalue.StringExact(config.ruleName)),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("controls"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("cloud_provider"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("attack_types"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("resource_type"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("subdomain"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("rule_origin"), knownvalue.NotNull()),
			},
		},
		{
			Config: fmt.Sprintf(`
		resource "crowdstrike_cloud_security_custom_rule" "rule_%[1]s" {
		  resource_type    = "%[5]s"
		  name             = "%[6]s"
		  description      = "Test Custom Rule Name"
		  cloud_provider   = "%[2]s"
		  parent_rule_id   = one(data.crowdstrike_cloud_security_rules.rule_%[1]s.rules).id
		}

		data "crowdstrike_cloud_security_rules" "rule_%[1]s" {
		 rule_name = "%[3]s"
		 benchmark = "%[4]s"
		}
		data "crowdstrike_cloud_security_rules" "%[1]s" {
		  rule_origin = "Custom"
		}
		`, config.cloudProvider, config.cloudProvider, config.ruleName, config.benchmark, config.resourceType, rName),
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.NotNull()),
			},
			Check: resource.ComposeAggregateTestCheckFunc(
				func(s *terraform.State) error {
					rs, ok := s.RootModule().Resources[resourceName]
					if !ok {
						return fmt.Errorf("Not found: %s", resourceName)
					}
					// Verify that all returned rules have rule_origin "Custom"
					for i := 0; ; i++ {
						typeKey := fmt.Sprintf("rules.%d.rule_origin", i)
						if typeVal, ok := rs.Primary.Attributes[typeKey]; !ok {
							break
						} else if typeVal != "Custom" {
							return fmt.Errorf("Expected rule %d to have rule_origin 'Custom', got '%s'", i, typeVal)
						}
					}
					return nil
				},
			),
		},
	}

	return steps
}

func TestCloudSecurityRulesDatasourceWithSuppressionRule(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}
	randomSuffix := sdkacctest.RandString(8)
	customRuleName := fmt.Sprintf("%s Custom Rule With Suppression %s", acctest.ResourcePrefix, randomSuffix)
	suppressionRuleName := fmt.Sprintf("TF Test Suppression for Custom Rule %s", randomSuffix)
	customRuleResourceName := "crowdstrike_cloud_security_custom_rule.test_with_suppression"
	suppressionResourceName := "crowdstrike_cloud_security_suppression_rule.test_suppression"
	dataSourceName := "data.crowdstrike_cloud_security_rules.test_with_suppression"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testCloudRulesWithSuppressionConfig(customRuleName, suppressionRuleName),
				ConfigStateChecks: []statecheck.StateCheck{
					// Initial custom rule
					statecheck.ExpectKnownValue(customRuleResourceName, tfjsonpath.New("name"), knownvalue.StringExact(customRuleName)),
					statecheck.ExpectKnownValue(customRuleResourceName, tfjsonpath.New("id"), knownvalue.NotNull()),

					// Initial Suppression rule
					statecheck.ExpectKnownValue(suppressionResourceName, tfjsonpath.New("name"), knownvalue.StringExact(suppressionRuleName)),
					statecheck.ExpectKnownValue(suppressionResourceName, tfjsonpath.New("id"), knownvalue.NotNull()),

					// Check initial suppression rule id
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("name"), knownvalue.StringExact(customRuleName)),

					// Validate the suppression is now attached to the rule
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("suppression_rule_ids"), knownvalue.ListSizeExact(1)),
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					func(s *terraform.State) error {
						suppressionRS, ok := s.RootModule().Resources[suppressionResourceName]
						if !ok {
							return fmt.Errorf("Not found: %s", suppressionResourceName)
						}
						suppressionID := suppressionRS.Primary.ID

						dataSourceRS, ok := s.RootModule().Resources[dataSourceName]
						if !ok {
							return fmt.Errorf("Not found: %s", dataSourceName)
						}

						suppressionRuleIDKey := "rules.0.suppression_rule_ids.0"
						if dataSourceSuppressionID, ok := dataSourceRS.Primary.Attributes[suppressionRuleIDKey]; ok {
							if dataSourceSuppressionID != suppressionID {
								return fmt.Errorf("Expected suppression_rule_id to be '%s', got '%s'", suppressionID, dataSourceSuppressionID)
							}
						} else {
							return fmt.Errorf("suppression_rule_ids not found in data source output")
						}

						return nil
					},
				),
			},
		},
	})
}

func testCloudRulesWithSuppressionConfig(customRuleName, suppressionRuleName string) string {
	return fmt.Sprintf(`
# First, find a parent rule to base our custom rule on
data "crowdstrike_cloud_security_rules" "parent_rule" {
  rule_name = "IAM root user has an active access key"
  cloud_provider = "AWS"
}

# Create a custom rule
resource "crowdstrike_cloud_security_custom_rule" "test_with_suppression" {
  resource_type    = "AWS::IAM::CredentialReport"
  name             = "%[1]s"
  description      = "Test custom rule for suppression data source test"
  cloud_provider   = "AWS"
  parent_rule_id   = one(data.crowdstrike_cloud_security_rules.parent_rule.rules).id
}

# Create a suppression rule that applies to the custom rule
resource "crowdstrike_cloud_security_suppression_rule" "test_suppression" {
  name              = "%[2]s"
  type              = "IOM"
  description       = "Test suppression rule for data source verification"
  reason            = "false-positive"

  rule_selection_filter = {
    ids = [crowdstrike_cloud_security_custom_rule.test_with_suppression.id]
  }

  asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
  }
}

# Query for the custom rule using the data source
data "crowdstrike_cloud_security_rules" "test_with_suppression" {
  rule_name = "%[1]s"

  # Ensure the suppression rule is created before we query
  depends_on = [crowdstrike_cloud_security_suppression_rule.test_suppression]
}
`, customRuleName, suppressionRuleName)
}

func testDatasourceConfigConflicts() []resource.TestStep {
	return []resource.TestStep{
		{
			Config: `
data "crowdstrike_cloud_security_rules" "test" {
	fql = "test"
	cloud_provider = "test"
}
			`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		{
			Config: `
data "crowdstrike_cloud_security_rules" "test" {
	fql       = "test"
	rule_name = "test"
}
			`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		{
			Config: `
data "crowdstrike_cloud_security_rules" "test" {
	fql         = "test"
	resource_type = "test"
}
			`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		{
			Config: `
data "crowdstrike_cloud_security_rules" "test" {
	fql     = "test"
	benchmark = "test"
}
			`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		{
			Config: `
data "crowdstrike_cloud_security_rules" "test" {
	fql     = "test"
	framework = "test"
}
			`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		{
			Config: `
data "crowdstrike_cloud_security_rules" "test" {
	fql     = "test"
	service = "test"
}
			`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		{
			Config: `
data "crowdstrike_cloud_security_rules" "test" {
	fql  = "test"
	rule_origin = "Default"
}
			`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		{
			Config: `
data "crowdstrike_cloud_security_rules" "test" {
	rule_origin = "Invalid"
}
			`,
			ExpectError: regexp.MustCompile("Invalid Attribute Value"),
		},
	}
}

func testEmptyResultSet() []resource.TestStep {
	return []resource.TestStep{
		{
			Config: `
data "crowdstrike_cloud_security_rules" "empty" {
  cloud_provider = "AWS"
  rule_name = "NonExistentRuleThatShouldNeverExist12345"
}
			`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("data.crowdstrike_cloud_security_rules.empty", tfjsonpath.New("rules"), knownvalue.Null()),
			},
		},
	}
}

func testWildcardPatterns(config dataRuleConfig) []resource.TestStep {
	resourceName := "data.crowdstrike_cloud_security_rules.wildcard"
	return []resource.TestStep{
		{
			Config: fmt.Sprintf(`
data "crowdstrike_cloud_security_rules" "wildcard" {
  cloud_provider = "%[1]s"
  rule_name = "%[2]s"
}
`, config.cloudProvider, "NLB/ALB*"),
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.NotNull()),
			},
		},
	}
}
