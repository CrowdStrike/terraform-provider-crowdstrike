package cloudsecurity_test

import (
	"fmt"
	"regexp"
	"strconv"
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

func TestCloudSecuritySuppressionRulesDataSource_DisabledFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}
	randomSuffix := sdkacctest.RandString(8)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    testSuppressionRulesDisabledFilter(randomSuffix),
	})
}

func TestCloudSecuritySuppressionRulesDataSource_Pagination(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}

	t.Setenv("TF_CROWDSTRIKE_PAGE_LIMIT", "2")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    testSuppressionRulesPagination(),
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
		// Test wildcard on name field
		{
			Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "test_wildcard_name" {
  name   = "TF Test Wildcard Name %s"
  type   = "IOM"
  reason = "false-positive"
  description = "Test suppression rule for name wildcard testing"

  rule_selection_filter = {
    names = ["ELB configured publicly with TLS/SSL disabled"]
  }

  asset_filter = {
    cloud_providers = ["aws"]
    regions = ["us-east-1"]
  }
}

data "crowdstrike_cloud_security_suppression_rules" "wildcard" {
  name = "TF Test Wildcard*"
  depends_on = [crowdstrike_cloud_security_suppression_rule.test_wildcard_name]
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

					wildcardPattern := regexp.MustCompile(`^TF Test Wildcard`)
					for i := 0; ; i++ {
						nameKey := fmt.Sprintf("rules.%d.name", i)
						if nameVal, ok := rs.Primary.Attributes[nameKey]; !ok {
							break
						} else if !wildcardPattern.MatchString(nameVal) {
							return fmt.Errorf("Expected rule %d name to match pattern 'TF Test Wildcard*', got '%s'", i, nameVal)
						}
					}

					return nil
				},
			),
		},
		// Test wildcard on description field
		{
			Config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "test_wildcard_desc" {
  name   = "TF Test Wildcard Description %s"
  type   = "IOM"
  reason = "compensating-control"
  description = "Test wildcard description pattern %s"

  rule_selection_filter = {
    names = ["S3 bucket configured with open READ permissions"]
  }

  asset_filter = {
    cloud_providers = ["aws"]
    regions = ["us-west-2"]
  }
}

data "crowdstrike_cloud_security_suppression_rules" "wildcard" {
  description = "*wildcard description pattern*"
  depends_on = [crowdstrike_cloud_security_suppression_rule.test_wildcard_desc]
}
`, randomSuffix, randomSuffix),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet(resourceName, "rules.#"),
				resource.TestMatchResourceAttr(resourceName, "rules.#", regexp.MustCompile(`^[1-9]\d*$`)),
				func(s *terraform.State) error {
					rs, ok := s.RootModule().Resources[resourceName]
					if !ok {
						return fmt.Errorf("Not found: %s", resourceName)
					}

					wildcardPattern := regexp.MustCompile(`.*wildcard description pattern.*`)
					for i := 0; ; i++ {
						nameKey := fmt.Sprintf("rules.%d.description", i)
						if nameVal, ok := rs.Primary.Attributes[nameKey]; !ok {
							break
						} else if !wildcardPattern.MatchString(nameVal) {
							return fmt.Errorf("Expected rule %d description to match pattern '*wildcard description pattern*', got '%s'", i, nameVal)
						}
					}

					return nil
				},
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

func testSuppressionRulesPagination() []resource.TestStep {
	resourceName := "data.crowdstrike_cloud_security_suppression_rules.pagination"
	return []resource.TestStep{
		{
			Config: `
# Create 5 IOM suppression rules to help test pagination
resource "crowdstrike_cloud_security_suppression_rule" "pagination_test_1" {
  name   = "TF Test Pagination Rule 1"
  type   = "IOM"
  reason = "false-positive"

  rule_selection_filter = {
    names = ["ELB configured publicly with TLS/SSL disabled"]
  }

  asset_filter = {
    cloud_providers = ["aws"]
    regions = ["us-east-1"]
  }
}

resource "crowdstrike_cloud_security_suppression_rule" "pagination_test_2" {
  name   = "TF Test Pagination Rule 2"
  type   = "IOM"
  reason = "compensating-control"

  rule_selection_filter = {
    names = ["S3 bucket configured with open READ permissions"]
  }

  asset_filter = {
    cloud_providers = ["aws"]
    regions = ["us-west-2"]
  }
}

resource "crowdstrike_cloud_security_suppression_rule" "pagination_test_3" {
  name   = "TF Test Pagination Rule 3"
  type   = "IOM"
  reason = "accept-risk"

  rule_selection_filter = {
    names = ["EC2 instance configured with open SSH access"]
  }

  asset_filter = {
    cloud_providers = ["aws"]
    regions = ["eu-west-1"]
  }
}

resource "crowdstrike_cloud_security_suppression_rule" "pagination_test_4" {
  name   = "TF Test Pagination Rule 4"
  type   = "IOM"
  reason = "false-positive"

  rule_selection_filter = {
    names = ["RDS database instance configured with open access"]
  }

  asset_filter = {
    cloud_providers = ["aws"]
    regions = ["ap-southeast-1"]
  }
}

resource "crowdstrike_cloud_security_suppression_rule" "pagination_test_5" {
  name   = "TF Test Pagination Rule 5"
  type   = "IOM"
  reason = "compensating-control"

  rule_selection_filter = {
    names = ["Lambda function configured with open resource policy"]
  }

  asset_filter = {
    cloud_providers = ["aws"]
    regions = ["us-central-1"]
  }
}

data "crowdstrike_cloud_security_suppression_rules" "pagination" {
  # Use broad filter to get many results and test pagination
  type = "IOM"
  depends_on = [
    crowdstrike_cloud_security_suppression_rule.pagination_test_1,
    crowdstrike_cloud_security_suppression_rule.pagination_test_2,
    crowdstrike_cloud_security_suppression_rule.pagination_test_3,
    crowdstrike_cloud_security_suppression_rule.pagination_test_4,
    crowdstrike_cloud_security_suppression_rule.pagination_test_5
  ]
}`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet(resourceName, "rules.#"),
				resource.TestCheckResourceAttrWith(resourceName, "rules.#", func(value string) error {
					count, err := strconv.Atoi(value)
					if err != nil {
						return fmt.Errorf("failed to parse rules count: %v", err)
					}
					if count >= 5 {
						return nil
					} else {
						return fmt.Errorf("expected at least 5 rules (our test rules), but got %d - pagination may not have worked correctly", count)
					}
				}),
				func(s *terraform.State) error {
					rs, ok := s.RootModule().Resources[resourceName]
					if !ok {
						return fmt.Errorf("Not found: %s", resourceName)
					}

					testRuleNames := map[string]bool{
						"TF Test Pagination Rule 1": false,
						"TF Test Pagination Rule 2": false,
						"TF Test Pagination Rule 3": false,
						"TF Test Pagination Rule 4": false,
						"TF Test Pagination Rule 5": false,
					}

					for i := 0; ; i++ {
						nameKey := fmt.Sprintf("rules.%d.name", i)
						if nameVal, ok := rs.Primary.Attributes[nameKey]; !ok {
							break
						} else {
							if _, exists := testRuleNames[nameVal]; exists {
								testRuleNames[nameVal] = true
							}
						}
					}

					for ruleName, found := range testRuleNames {
						if !found {
							return fmt.Errorf("test rule '%s' not found in pagination results", ruleName)
						}
					}

					return nil
				},
			),
		},
	}
}

func testSuppressionRulesDisabledFilter(randomSuffix string) []resource.TestStep {
	resourceNameActiveOnly := "data.crowdstrike_cloud_security_suppression_rules.active_only"
	resourceNameAll := "data.crowdstrike_cloud_security_suppression_rules.all_rules"

	return []resource.TestStep{
		// Single step: Test disabled field boolean logic
		{
			Config: fmt.Sprintf(`
# Create a rule without expiration date (should be active)
resource "crowdstrike_cloud_security_suppression_rule" "test_active" {
  name   = "TF Test Active Rule %s"
  type   = "IOM"
  reason = "false-positive"
  description = "Test active suppression rule for disabled filtering"

  rule_selection_filter = {
    names = ["ELB configured publicly with TLS/SSL disabled"]
  }

  asset_filter = {
    cloud_providers = ["aws"]
    regions = ["us-east-1"]
  }
}

# Test disabled = false (should find active rules)
data "crowdstrike_cloud_security_suppression_rules" "active_only" {
  name = "TF Test Active Rule %s"
  disabled = false
  depends_on = [crowdstrike_cloud_security_suppression_rule.test_active]
}

# Test disabled = true (should find all rules including expired ones)
data "crowdstrike_cloud_security_suppression_rules" "all_rules" {
  name = "TF Test Active Rule %s"
  disabled = true
  depends_on = [crowdstrike_cloud_security_suppression_rule.test_active]
}
`, randomSuffix, randomSuffix, randomSuffix),
			Check: resource.ComposeAggregateTestCheckFunc(
				// Both queries should find the active rule
				resource.TestCheckResourceAttrSet(resourceNameActiveOnly, "rules.#"),
				resource.TestMatchResourceAttr(resourceNameActiveOnly, "rules.#", regexp.MustCompile(`^[1-9]\d*$`)),
				resource.TestCheckResourceAttrSet(resourceNameAll, "rules.#"),
				resource.TestMatchResourceAttr(resourceNameAll, "rules.#", regexp.MustCompile(`^0$`)),
			),
		},
	}
}
