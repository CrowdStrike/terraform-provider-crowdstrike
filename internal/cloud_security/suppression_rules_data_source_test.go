package cloudsecurity_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func compareSuppressionRuleToDataSource(resourceName, dataSourceName string) []statecheck.StateCheck {
	dataSourceRulePath := tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey

	return []statecheck.StateCheck{
		statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("rules"), knownvalue.NotNull()),
		statecheck.CompareValuePairs(
			resourceName,
			tfjsonpath.New("id"),
			dataSourceName,
			dataSourceRulePath("id"),
			compare.ValuesSame(),
		),
		statecheck.CompareValuePairs(
			resourceName,
			tfjsonpath.New("name"),
			dataSourceName,
			dataSourceRulePath("name"),
			compare.ValuesSame(),
		),
		statecheck.CompareValuePairs(
			resourceName,
			tfjsonpath.New("type"),
			dataSourceName,
			dataSourceRulePath("type"),
			compare.ValuesSame(),
		),
		statecheck.CompareValuePairs(
			resourceName,
			tfjsonpath.New("reason"),
			dataSourceName,
			dataSourceRulePath("reason"),
			compare.ValuesSame(),
		),
		statecheck.CompareValuePairs(
			resourceName,
			tfjsonpath.New("description"),
			dataSourceName,
			dataSourceRulePath("description"),
			compare.ValuesSame(),
		),
		statecheck.CompareValuePairs(
			resourceName,
			tfjsonpath.New("comment"),
			dataSourceName,
			dataSourceRulePath("comment"),
			compare.ValuesSame(),
		),
		statecheck.CompareValuePairs(
			resourceName,
			tfjsonpath.New("expiration_date"),
			dataSourceName,
			dataSourceRulePath("expiration_date"),
			compare.ValuesSame(),
		),
		statecheck.CompareValuePairs(
			resourceName,
			tfjsonpath.New("rule_selection_filter"),
			dataSourceName,
			dataSourceRulePath("rule_selection_filter"),
			compare.ValuesSame(),
		),
		statecheck.CompareValuePairs(
			resourceName,
			tfjsonpath.New("asset_filter"),
			dataSourceName,
			dataSourceRulePath("asset_filter"),
			compare.ValuesSame(),
		),
	}
}

func TestCloudSecuritySuppressionRulesDataSource_Name(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}

	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_cloud_security_suppression_rule.test"
	dataSourceName := "data.crowdstrike_cloud_security_suppression_rules.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:            testAccSuppressionRulesDataSourceConfig_Name(rName),
				ConfigStateChecks: compareSuppressionRuleToDataSource(resourceName, dataSourceName),
			},
		},
	})
}

func TestCloudSecuritySuppressionRulesDataSource_Description(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}

	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_cloud_security_suppression_rule.test"
	dataSourceName := "data.crowdstrike_cloud_security_suppression_rules.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:            testAccSuppressionRulesDataSourceConfig_description(rName),
				ConfigStateChecks: compareSuppressionRuleToDataSource(resourceName, dataSourceName),
			},
		},
	})
}

func TestCloudSecuritySuppressionRulesDataSource_FQL(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}

	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_cloud_security_suppression_rule.test"
	dataSourceName := "data.crowdstrike_cloud_security_suppression_rules.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:            testAccSuppressionRulesDataSourceConfig_fql(rName),
				ConfigStateChecks: compareSuppressionRuleToDataSource(resourceName, dataSourceName),
			},
		},
	})
}

func TestCloudSecuritySuppressionRulesDataSource_Wildcard(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}

	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_cloud_security_suppression_rule.test"
	dataSourceName := "data.crowdstrike_cloud_security_suppression_rules.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:            testAccSuppressionRulesDataSourceConfig_wildcard(rName),
				ConfigStateChecks: compareSuppressionRuleToDataSource(resourceName, dataSourceName),
			},
		},
	})
}

func TestCloudSecuritySuppressionRulesDataSource_Conflicts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccSuppressionRulesDataSourceConfig_conflicts(),
				ExpectError: regexp.MustCompile(`(?s).*Attribute "fql" cannot be specified when "type" is specified.*Attribute "fql" cannot be specified when "name" is specified.*Attribute "fql" cannot be specified when "description" is specified.*Attribute "fql" cannot be specified when "reason" is specified.*`),
			},
		},
	})
}

func testAccSuppressionRulesDataSourceConfig_Name(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "test" {
  name   = %[1]q
  type   = "IOM"
  reason = "false-positive"

  rule_selection_filter = {
    names = ["ELB configured publicly with TLS/SSL disabled"]
  }

  asset_filter = {
    cloud_providers = ["aws"]
    regions         = ["us-east-1"]
  }
}

data "crowdstrike_cloud_security_suppression_rules" "test" {
  name = crowdstrike_cloud_security_suppression_rule.test.name
  depends_on = [crowdstrike_cloud_security_suppression_rule.test]
}
`, rName)
}

func testAccSuppressionRulesDataSourceConfig_description(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "test" {
  name        = %[1]q
  type        = "IOM"
  reason      = "false-positive"
  description = %[2]q

  rule_selection_filter = {
    names = ["ELB configured publicly with TLS/SSL disabled"]
  }

  asset_filter = {
    cloud_providers = ["aws"]
    regions         = ["us-east-1"]
  }
}

data "crowdstrike_cloud_security_suppression_rules" "test" {
  description = %[2]q
  depends_on  = [crowdstrike_cloud_security_suppression_rule.test]
}
`, rName, fmt.Sprintf("Test description filter pattern %s", rName))
}

func testAccSuppressionRulesDataSourceConfig_fql(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "test" {
  name        = %[1]q
  type        = "IOM"
  reason      = "false-positive"
  description = "Test suppression rule for complex FQL filtering"

  rule_selection_filter = {
    names = ["ELB configured publicly with TLS/SSL disabled"]
  }

  asset_filter = {
    cloud_providers = ["aws"]
    regions         = ["us-east-1"]
  }
}

data "crowdstrike_cloud_security_suppression_rules" "test" {
  fql        = "name:*'*TF Test FQL Complex*'+subdomain:'IOM'+suppression_reason:'false-positive'"
  depends_on = [crowdstrike_cloud_security_suppression_rule.test]
}
`, fmt.Sprintf("TF Test FQL Complex %s", rName))
}

func testAccSuppressionRulesDataSourceConfig_wildcard(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "test" {
  name        = "TF Test Wildcard %[1]s"
  type        = "IOM"
  reason      = "false-positive"
  description = "Test wildcard description pattern %[1]s"

  rule_selection_filter = {
    names = ["ELB configured publicly with TLS/SSL disabled"]
  }

  asset_filter = {
    cloud_providers = ["aws"]
    regions         = ["us-east-1"]
  }
}

data "crowdstrike_cloud_security_suppression_rules" "test" {
  description = "*wildcard description pattern*"
  depends_on  = [crowdstrike_cloud_security_suppression_rule.test]
}
`, rName)
}

func testAccSuppressionRulesDataSourceConfig_conflicts() string {
	return `
data "crowdstrike_cloud_security_suppression_rules" "test" {
  fql         = "subdomain:'IOM'"
  type        = "IOM"
  name        = "test"
  description = "test"
  reason      = "false-positive"
}
`
}
