package cloudsecurity_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestCloudSecurityRulesDataSource(t *testing.T) {
	var steps []resource.TestStep

	steps = append(steps, testDatasourceConfigConflicts()...)
	steps = append(steps, testEmptyResultSet()...)
	steps = append(steps, testCloudRules(awsConfig)...)
	steps = append(steps, testCloudRules(azureConfig)...)
	steps = append(steps, testCloudRules(gcpConfig)...)
	steps = append(steps, testWildcardPatterns(awsConfig)...)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    steps,
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
