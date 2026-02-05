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

func TestCloudSecuritySuppressionRulesDataSource_ConfigConflicts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    testSuppressionRulesDataSourceConfigConflicts(),
	})
}

func TestCloudSecuritySuppressionRulesDataSource_EmptyResultSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    testSuppressionRulesEmptyResultSet(),
	})
}

func TestCloudSecuritySuppressionRulesDataSource_Basic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}
	randomSuffix := sdkacctest.RandString(8)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    testSuppressionRulesBasic(randomSuffix),
	})
}

func TestCloudSecuritySuppressionRulesDataSource_FilterByType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}
	randomSuffix := sdkacctest.RandString(8)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    testSuppressionRulesFilterByType(randomSuffix),
	})
}

func TestCloudSecuritySuppressionRulesDataSource_FilterByReason(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}
	randomSuffix := sdkacctest.RandString(8)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    testSuppressionRulesFilterByReason(randomSuffix),
	})
}

func TestCloudSecuritySuppressionRulesDataSource_FQLFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}
	randomSuffix := sdkacctest.RandString(8)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    testSuppressionRulesFQLFilter(randomSuffix),
	})
}

func TestCloudSecuritySuppressionRulesDataSource_WildcardPatterns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}
	randomSuffix := sdkacctest.RandString(8)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    testSuppressionRulesWildcardPatterns(randomSuffix),
	})
}

func testSuppressionRulesBasic(randomSuffix string) []resource.TestStep {
	resourceName := "data.crowdstrike_cloud_security_suppression_rules.basic"
	return []resource.TestStep{
		{
			Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "test" {
  name   = "TF Test Data Source Basic %s"
  type   = "IOM"
  reason = "false-positive"
  comment = "Test suppression rule for data source testing"

  rule_selection_filter = {
    names = ["ELB configured publicly with TLS/SSL disabled"]
  }

  asset_filter = {
    cloud_providers = ["aws"]
    regions = ["us-east-1"]
  }
}

data "crowdstrike_cloud_security_suppression_rules" "basic" {
  depends_on = [crowdstrike_cloud_security_suppression_rule.test]
}
`, randomSuffix),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet(resourceName, "rules.#"),
				resource.TestMatchResourceAttr(resourceName, "rules.#", regexp.MustCompile(`^[1-9]\d*$`)),
				func(s *terraform.State) error {
					rs, ok := s.RootModule().Resources[resourceName]
					if !ok {
						return fmt.Errorf("Not found: %s", resourceName)
					}
					// Verify that at least one rule has all required attributes
					for i := 0; ; i++ {
						idKey := fmt.Sprintf("rules.%d.id", i)
						if _, ok := rs.Primary.Attributes[idKey]; !ok {
							break
						}
						nameKey := fmt.Sprintf("rules.%d.name", i)
						typeKey := fmt.Sprintf("rules.%d.type", i)
						reasonKey := fmt.Sprintf("rules.%d.reason", i)

						if _, ok := rs.Primary.Attributes[nameKey]; !ok {
							return fmt.Errorf("Missing name for rule %d", i)
						}
						if _, ok := rs.Primary.Attributes[typeKey]; !ok {
							return fmt.Errorf("Missing type for rule %d", i)
						}
						if _, ok := rs.Primary.Attributes[reasonKey]; !ok {
							return fmt.Errorf("Missing reason for rule %d", i)
						}
					}
					return nil
				},
			),
		},
	}
}

func testSuppressionRulesFilterByType(randomSuffix string) []resource.TestStep {
	resourceName := "data.crowdstrike_cloud_security_suppression_rules.by_type"
	return []resource.TestStep{
		{
			Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "test_type" {
  name   = "TF Test Data Source Type Filter %s"
  type   = "IOM"
  reason = "compensating-control"
  description = "Test suppression rule for type filtering"

  rule_selection_filter = {
    names = ["ELB configured publicly with TLS/SSL disabled"]
  }

  asset_filter = {
    cloud_providers = ["aws"]
    regions = ["us-east-1"]
  }
}

data "crowdstrike_cloud_security_suppression_rules" "by_type" {
  type = "IOM"
  depends_on = [crowdstrike_cloud_security_suppression_rule.test_type]
}
`, randomSuffix),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet(resourceName, "rules.#"),
				resource.TestMatchResourceAttr(resourceName, "rules.#", regexp.MustCompile(`^[1-9]\d*$`)),
				func(s *terraform.State) error {
					rs, ok := s.RootModule().Resources[resourceName]
					if !ok {
						return fmt.Errorf("Not found: %s", resourceName)
					}
					// Verify that all returned rules have type "IOM"
					for i := 0; ; i++ {
						typeKey := fmt.Sprintf("rules.%d.type", i)
						if typeVal, ok := rs.Primary.Attributes[typeKey]; !ok {
							break
						} else if typeVal != "IOM" {
							return fmt.Errorf("Expected rule %d to have type 'IOM', got '%s'", i, typeVal)
						}
					}
					return nil
				},
			),
		},
	}
}

func testSuppressionRulesFilterByReason(randomSuffix string) []resource.TestStep {
	resourceName := "data.crowdstrike_cloud_security_suppression_rules.by_reason"
	return []resource.TestStep{
		{
			Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "test_reason" {
  name   = "TF Test Data Source Reason Filter %s"
  type   = "IOM"
  reason = "accept-risk"
  description = "Test suppression rule for reason filtering"

  rule_selection_filter = {
    names = ["ELB configured publicly with TLS/SSL disabled"]
  }

  asset_filter = {
    cloud_providers = ["aws"]
    regions = ["us-east-1"]
  }
}

data "crowdstrike_cloud_security_suppression_rules" "by_reason" {
  reason = "accept-risk"
  depends_on = [crowdstrike_cloud_security_suppression_rule.test_reason]
}
`, randomSuffix),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet(resourceName, "rules.#"),
				resource.TestMatchResourceAttr(resourceName, "rules.#", regexp.MustCompile(`^[1-9]\d*$`)),
				func(s *terraform.State) error {
					rs, ok := s.RootModule().Resources[resourceName]
					if !ok {
						return fmt.Errorf("Not found: %s", resourceName)
					}
					// Verify that all returned rules have reason "accept-risk"
					for i := 0; ; i++ {
						reasonKey := fmt.Sprintf("rules.%d.reason", i)
						if reasonVal, ok := rs.Primary.Attributes[reasonKey]; !ok {
							break
						} else if reasonVal != "accept-risk" {
							return fmt.Errorf("Expected rule %d to have reason 'accept-risk', got '%s'", i, reasonVal)
						}
					}
					return nil
				},
			),
		},
	}
}

func testSuppressionRulesFQLFilter(randomSuffix string) []resource.TestStep {
	resourceName := "data.crowdstrike_cloud_security_suppression_rules.fql"
	return []resource.TestStep{
		{
			Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "test_fql" {
  name   = "TF Test Data Source FQL %s"
  type   = "IOM"
  reason = "false-positive"
  description = "Test suppression rule for FQL filtering"

  rule_selection_filter = {
    names = ["ELB configured publicly with TLS/SSL disabled"]
  }
}

data "crowdstrike_cloud_security_suppression_rules" "fql" {
  fql = "name:*'*TF Test Data Source FQL*'"
  depends_on = [crowdstrike_cloud_security_suppression_rule.test_fql]
}
`, randomSuffix),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet(resourceName, "rules.#"),
				resource.TestMatchResourceAttr(resourceName, "rules.#", regexp.MustCompile(`^[1-9]\d*$`)),
				func(s *terraform.State) error {
					rs, ok := s.RootModule().Resources[resourceName]
					if !ok {
						return fmt.Errorf("Not found: %s", resourceName)
					}
					// Verify that all returned rules contain "TF Test Data Source FQL" in their name
					for i := 0; ; i++ {
						nameKey := fmt.Sprintf("rules.%d.name", i)
						if nameVal, ok := rs.Primary.Attributes[nameKey]; !ok {
							break
						} else if !regexp.MustCompile(`TF Test Data Source FQL`).MatchString(nameVal) {
							return fmt.Errorf("Expected rule %d name to contain 'TF Test Data Source FQL', got '%s'", i, nameVal)
						}
					}
					return nil
				},
			),
		},
	}
}

func testSuppressionRulesWildcardPatterns(randomSuffix string) []resource.TestStep {
	resourceName := "data.crowdstrike_cloud_security_suppression_rules.wildcard"
	return []resource.TestStep{
		{
			Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "test_wildcard" {
  name   = "TF Test Data Source Wildcard %s"
  type   = "IOM"
  reason = "false-positive"
  description = "Test suppression rule for wildcard pattern testing"

  rule_selection_filter = {
    names = ["ELB configured publicly with TLS/SSL disabled"]
  }

  asset_filter = {
    cloud_providers = ["aws"]
    regions = ["us-east-1"]
  }
}

data "crowdstrike_cloud_security_suppression_rules" "wildcard" {
  name = "TF Test Data Source*"
  depends_on = [crowdstrike_cloud_security_suppression_rule.test_wildcard]
}
`, randomSuffix),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet(resourceName, "rules.#"),
				resource.TestMatchResourceAttr(resourceName, "rules.#", regexp.MustCompile(`^[1-9]\d*$`)),
			),
		},
	}
}

func testSuppressionRulesDataSourceConfigConflicts() []resource.TestStep {
	return []resource.TestStep{
		{
			Config: `
data "crowdstrike_cloud_security_suppression_rules" "conflict_fql_type" {
  fql  = "subdomain:'IOM'"
  type = "IOM"
}
			`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		{
			Config: `
data "crowdstrike_cloud_security_suppression_rules" "conflict_fql_name" {
  fql  = "name:'test'"
  name = "test"
}
			`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		{
			Config: `
data "crowdstrike_cloud_security_suppression_rules" "conflict_fql_description" {
  fql         = "description:'test'"
  description = "test"
}
			`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		{
			Config: `
data "crowdstrike_cloud_security_suppression_rules" "conflict_fql_reason" {
  fql    = "suppression_reason:'false-positive'"
  reason = "false-positive"
}
			`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		{
			Config: `
data "crowdstrike_cloud_security_suppression_rules" "conflict_fql_comment" {
  fql     = "suppression_comment:'test'"
  comment = "test"
}
			`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		{
			Config: `
data "crowdstrike_cloud_security_suppression_rules" "invalid_type" {
  type = "InvalidType"
}
			`,
			ExpectError: regexp.MustCompile("Invalid Attribute Value"),
		},
		{
			Config: `
data "crowdstrike_cloud_security_suppression_rules" "invalid_reason" {
  reason = "invalid-reason"
}
			`,
			ExpectError: regexp.MustCompile("Invalid Attribute Value"),
		},
	}
}

func testSuppressionRulesEmptyResultSet() []resource.TestStep {
	return []resource.TestStep{
		{
			Config: `
data "crowdstrike_cloud_security_suppression_rules" "empty" {
  name = "NonExistentSuppressionRuleThatShouldNeverExist12345"
}
			`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("data.crowdstrike_cloud_security_suppression_rules.empty", "rules.#", "0"),
			),
		},
	}
}
