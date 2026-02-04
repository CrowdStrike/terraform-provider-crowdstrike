package cloudsecurity_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
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
	resourceName := fmt.Sprintf("data.crowdstrike_cloud_security_rules.%s", config.cloudProvider)
	steps = []resource.TestStep{
		{
			Config: fmt.Sprintf(`
		data "crowdstrike_cloud_security_rules" "%[1]s" {
		  cloud_provider = "%[1]s"
		  resource_type  = "%[2]s"
		}
		`, config.cloudProvider, config.resourceType),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet(resourceName, "rules.#"),
				resource.TestMatchResourceAttr(resourceName, "rules.#", regexp.MustCompile(`^[2-9]|\d{2,}$`)),
				func(s *terraform.State) error {
					rs, ok := s.RootModule().Resources[resourceName]
					if !ok {
						return fmt.Errorf("Not found: %s", resourceName)
					}
					for i := 0; ; i++ {
						key := fmt.Sprintf("rules.%d.id", i)
						if _, ok := rs.Primary.Attributes[key]; !ok {
							break
						}
					}
					return nil
				},
			),
		},
		{
			Config: fmt.Sprintf(`
				data "crowdstrike_cloud_security_rules" "%[1]s" {
				  cloud_provider = "%[1]s"
				  rule_name = "%[2]s"
				}
				`, config.cloudProvider, config.ruleName),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(resourceName, "rules.#", "1"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.id"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.remediation_info.#"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.alert_info.#"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.severity"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.domain"),
				resource.TestCheckResourceAttr(resourceName, "rules.0.name", config.ruleName),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.controls.#"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.cloud_provider"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.attack_types.#"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.resource_type"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.subdomain"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.type"),
			),
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
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(resourceName, "rules.#", "1"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.id"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.remediation_info.#"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.alert_info.#"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.severity"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.domain"),
				resource.TestCheckResourceAttr(resourceName, "rules.0.name", config.ruleName),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.controls.#"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.cloud_provider"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.attack_types.#"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.resource_type"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.subdomain"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.type"),
			),
		},
		{
			Config: fmt.Sprintf(`
		data "crowdstrike_cloud_security_rules" "%s" {
		  fql = "rule_name:'%s'"
		}
		`, config.cloudProvider, config.ruleName),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(resourceName, "rules.#", "1"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.id"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.remediation_info.#"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.alert_info.#"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.severity"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.domain"),
				resource.TestCheckResourceAttr(resourceName, "rules.0.name", config.ruleName),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.controls.#"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.cloud_provider"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.attack_types.#"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.resource_type"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.subdomain"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.type"),
			),
		},
		{
			Config: fmt.Sprintf(`
		resource "crowdstrike_cloud_security_custom_rule" "rule_%[1]s" {
		  resource_type    = "%[5]s"
		  name             = "Test Custom Rule Name"
		  description      = "Test Custom Rule Name"
		  cloud_provider   = "%[2]s"
		  parent_rule_id   = one(data.crowdstrike_cloud_security_rules.rule_%[1]s.rules).id
		}

		data "crowdstrike_cloud_security_rules" "rule_%[1]s" {
		 rule_name = "%[3]s"
		 benchmark = "%[4]s"
		}
		data "crowdstrike_cloud_security_rules" "%[1]s" {
		  type = "Custom"
		}
		`, config.cloudProvider, config.cloudProvider, config.ruleName, config.benchmark, config.resourceType),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet(resourceName, "rules.#"),
				func(s *terraform.State) error {
					rs, ok := s.RootModule().Resources[resourceName]
					if !ok {
						return fmt.Errorf("Not found: %s", resourceName)
					}
					// Verify that all returned rules have type "Custom"
					for i := 0; ; i++ {
						typeKey := fmt.Sprintf("rules.%d.type", i)
						if typeVal, ok := rs.Primary.Attributes[typeKey]; !ok {
							break
						} else if typeVal != "Custom" {
							return fmt.Errorf("Expected rule %d to have type 'Custom', got '%s'", i, typeVal)
						}
					}
					return nil
				},
			),
		},
	}

	return steps
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
	type = "Default"
}
			`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		{
			Config: `
data "crowdstrike_cloud_security_rules" "test" {
	type = "Invalid"
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
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("data.crowdstrike_cloud_security_rules.empty", "rules.#", "0"),
			),
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
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet(resourceName, "rules.#"),
				resource.TestMatchResourceAttr(resourceName, "rules.#", regexp.MustCompile(`^[1-9]\d*$`)),
			),
		},
	}
}
