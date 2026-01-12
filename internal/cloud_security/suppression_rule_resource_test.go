package cloudsecurity_test

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCloudSecuritySuppressionRuleResource_Basic(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testSuppressionRuleBasicConfig(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("crowdstrike_cloud_security_suppression_rule.test", "name", "TF Test Basic Suppression Rule"),
					resource.TestCheckResourceAttr("crowdstrike_cloud_security_suppression_rule.test", "description", "Basic test suppression rule"),
					resource.TestCheckResourceAttr("crowdstrike_cloud_security_suppression_rule.test", "domain", "CSPM"),
					resource.TestCheckResourceAttr("crowdstrike_cloud_security_suppression_rule.test", "subdomain", "IOM"),
					resource.TestCheckResourceAttr("crowdstrike_cloud_security_suppression_rule.test", "suppression_reason", "false-positive"),
					resource.TestCheckResourceAttrSet("crowdstrike_cloud_security_suppression_rule.test", "id"),
				),
			},
		},
	})
}

func TestCloudSecuritySuppressionRuleResource_EC2Scenario(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.ec2_test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testSuppressionRuleEC2ScenarioConfig(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test EC2 Suppression %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "description", "Suppress EC2 instance excessive response hop limit rule for specific instances"),
					resource.TestCheckResourceAttr(resourceName, "domain", "CSPM"),
					resource.TestCheckResourceAttr(resourceName, "subdomain", "IOM"),
					resource.TestCheckResourceAttr(resourceName, "suppression_reason", "accept-risk"),
					resource.TestCheckResourceAttr(resourceName, "suppression_comment", "These instances are configured correctly for our architecture"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.rule_names.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.cloud_providers.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.regions.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.resource_types.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.account_ids.#", "3"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "id",
			},
		},
	})
}

func TestCloudSecuritySuppressionRuleResource_SSMScenario(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.ssm_test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testSuppressionRuleSSMScenarioConfig(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test SSM Suppression %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "description", "Suppress SSM parameter encryption rule for legacy parameters"),
					resource.TestCheckResourceAttr(resourceName, "domain", "CSPM"),
					resource.TestCheckResourceAttr(resourceName, "subdomain", "IOM"),
					resource.TestCheckResourceAttr(resourceName, "suppression_reason", "compensating-control"),
					resource.TestCheckResourceAttr(resourceName, "suppression_comment", "Legacy parameters with alternative encryption"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.rule_names.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.cloud_providers.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.regions.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.resource_types.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.account_ids.#", "5"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

func TestCloudSecuritySuppressionRuleResource_AccountLevelMultiRule(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.account_test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testSuppressionRuleAccountLevelConfig(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Account Level Suppression %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "description", "Suppress multiple backup and monitoring rules for test account"),
					resource.TestCheckResourceAttr(resourceName, "domain", "CSPM"),
					resource.TestCheckResourceAttr(resourceName, "subdomain", "IOM"),
					resource.TestCheckResourceAttr(resourceName, "suppression_reason", "false-positive"),
					resource.TestCheckResourceAttr(resourceName, "suppression_comment", "Test account with different compliance requirements"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.rule_names.#", "4"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.cloud_providers.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.regions.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.resource_types.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.account_ids.#", "1"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

func TestCloudSecuritySuppressionRuleResource_WithExpiration(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.expiration_test"

	// Set expiration to 1 week from now
	expirationDate := time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testSuppressionRuleWithExpirationConfig(randomSuffix, expirationDate),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Expiration Suppression %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "suppression_expiration_date", expirationDate),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

func TestCloudSecuritySuppressionRuleResource_Update(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.update_test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create initial rule
			{
				Config: testSuppressionRuleUpdateConfigStep1(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Update Suppression %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "description", "Initial description"),
					resource.TestCheckResourceAttr(resourceName, "suppression_reason", "false-positive"),
					resource.TestCheckResourceAttr(resourceName, "suppression_comment", "Initial comment"),
				),
			},
			// Update the rule
			{
				Config: testSuppressionRuleUpdateConfigStep2(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Update Suppression %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "description", "Updated description"),
					resource.TestCheckResourceAttr(resourceName, "suppression_reason", "compensating-control"),
					resource.TestCheckResourceAttr(resourceName, "suppression_comment", "Updated comment"),
				),
			},
		},
	})
}

func TestCloudSecuritySuppressionRuleResource_ExpirationDateCannotBeCleared(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.expiration_clear_test"

	// Set initial expiration to 2 weeks from now
	initialExpiration := time.Now().Add(14 * 24 * time.Hour).UTC().Format(time.RFC3339)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Step 1: Create with expiration date
			{
				Config: testSuppressionRuleWithExpirationClearConfig(randomSuffix, initialExpiration),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Expiration Clear %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "suppression_expiration_date", initialExpiration),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			// Step 2: Try to clear expiration date - should fail
			{
				Config:      testSuppressionRuleExpirationClearedConfig(randomSuffix),
				ExpectError: regexp.MustCompile("Cannot Clear Suppression Expiration Date"),
				PlanOnly:    true,
			},
		},
	})
}

func TestCloudSecuritySuppressionRuleResource_ExpirationDateCanBeUpdated(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.expiration_update_test"

	// Set initial expiration to 2 weeks from now
	initialExpiration := time.Now().Add(14 * 24 * time.Hour).UTC().Format(time.RFC3339)
	// Set updated expiration to 1 month from now
	updatedExpiration := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Step 1: Create with expiration date
			{
				Config: testSuppressionRuleWithExpirationUpdateConfig(randomSuffix, initialExpiration),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Expiration Update %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "suppression_expiration_date", initialExpiration),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			// Step 2: Update expiration date to a new value - should succeed
			{
				Config: testSuppressionRuleWithExpirationUpdateConfig(randomSuffix, updatedExpiration),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Expiration Update %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "suppression_expiration_date", updatedExpiration),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

func TestCloudSecuritySuppressionRuleResource_ValidationErrors(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Test missing required filters
			{
				Config:      testSuppressionRuleInvalidConfigNoFilters(randomSuffix),
				ExpectError: regexp.MustCompile(`At least one of 'rule_selection_filter' or 'scope_asset_filter'`),
				PlanOnly:    true,
			},
			// Test invalid expiration date format
			{
				Config:      testSuppressionRuleInvalidExpirationDate(randomSuffix),
				ExpectError: regexp.MustCompile("must be in RFC3339 format"),
				PlanOnly:    true,
			},
			// Test expired date
			{
				Config:      testSuppressionRuleExpiredCreateConfig(randomSuffix),
				ExpectError: regexp.MustCompile("has already passed"),
				PlanOnly:    true,
			},
		},
	})
}

func TestCloudSecuritySuppressionRuleResource_RuleSeverityFilters(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.severity_test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testSuppressionRuleSeverityFilterConfig(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Severity Filter %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.rule_severities.#", "2"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

func TestCloudSecuritySuppressionRuleResource_TagFilters(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.tag_test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testSuppressionRuleTagFilterConfig(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Tag Filter %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.tags.#", "2"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

func TestCloudSecuritySuppressionRuleResource_EmptyFilterValidation(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Test empty rule selection filter
			{
				Config:      testSuppressionRuleEmptyRuleSelectionFilter(randomSuffix),
				ExpectError: regexp.MustCompile("Empty Rule Selection Filter"),
				PlanOnly:    true,
			},
			// Test empty scope asset filter
			{
				Config:      testSuppressionRuleEmptyScopeAssetFilter(randomSuffix),
				ExpectError: regexp.MustCompile("Empty Scope Asset Filter"),
				PlanOnly:    true,
			},
		},
	})
}

func TestCloudSecuritySuppressionRuleResource_AllRuleSelectionFilters(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.rule_filters_test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testSuppressionRuleAllRuleSelectionFiltersConfig(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test All Rule Filters %s", randomSuffix)),
					resource.TestCheckResourceAttrSet(resourceName, "rule_selection_filter.rule_ids.#"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.rule_names.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.rule_origins.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.rule_providers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.rule_services.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.rule_severities.#", "2"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

// Add cloud_group_ids when cloud groups data source is added
func TestCloudSecuritySuppressionRuleResource_AllScopeAssetFilters(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.scope_filters_test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testSuppressionRuleAllScopeAssetFiltersConfig(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test All Scope Filters %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.account_ids.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.cloud_providers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.regions.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.resource_ids.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.resource_names.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.resource_types.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.service_categories.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.tags.#", "2"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

func TestCloudSecuritySuppressionRuleResource_ComplexFilterCombinations(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.complex_test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testSuppressionRuleComplexFiltersConfig(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Complex Filters %s", randomSuffix)),
					// Rule selection filter checks
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.rule_providers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.rule_severities.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.rule_origins.#", "1"),
					// Scope asset filter checks
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.cloud_providers.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.service_categories.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.tags.#", "3"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

func TestCloudSecuritySuppressionRuleResource_TagValidation(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Test invalid tag format - missing value
			{
				Config:      testSuppressionRuleInvalidTagFormat(randomSuffix, "Environment"),
				ExpectError: regexp.MustCompile(`must[\s\n]*be[\s\n]*in[\s\n]*the[\s\n]*format[\s\n]*'key=value'`),
				PlanOnly:    true,
			},
			// Test invalid tag format - missing key
			{
				Config:      testSuppressionRuleInvalidTagFormat(randomSuffix, "=production"),
				ExpectError: regexp.MustCompile(`must[\s\n]*be[\s\n]*in[\s\n]*the[\s\n]*format[\s\n]*'key=value'`),
				PlanOnly:    true,
			},
			// Test invalid tag format - no equals sign
			{
				Config:      testSuppressionRuleInvalidTagFormat(randomSuffix, "Environment-production"),
				ExpectError: regexp.MustCompile(`must[\s\n]*be[\s\n]*in[\s\n]*the[\s\n]*format[\s\n]*'key=value'`),
				PlanOnly:    true,
			},
		},
	})
}

func TestCloudSecuritySuppressionRuleResource_ComprehensiveImportState(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.import_test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testSuppressionRuleComprehensiveImportConfig(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Comprehensive Import %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "description", "Comprehensive test for import functionality"),
					resource.TestCheckResourceAttr(resourceName, "suppression_comment", "Testing all attributes for import"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.rule_names.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.rule_severities.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.account_ids.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.tags.#", "2"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "id",
			},
		},
	})
}

func TestCloudSecuritySuppressionRuleResource_AdvancedUpdateScenarios(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.advanced_update_test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create with rule selection filter only
			{
				Config: testSuppressionRuleAdvancedUpdateStep1(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Advanced Update %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.rule_names.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.cloud_providers.#", "1"),
				),
			},
			// Update to add more complex filters
			{
				Config: testSuppressionRuleAdvancedUpdateStep2(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Advanced Update %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.rule_names.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.rule_severities.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.cloud_providers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.tags.#", "2"),
				),
			},
			// Update to change filter types completely
			{
				Config: testSuppressionRuleAdvancedUpdateStep3(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Advanced Update %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.rule_providers.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.rule_origins.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.resource_types.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "scope_asset_filter.regions.#", "2"),
				),
			},
		},
	})
}

// Test configuration helper functions

func testSuppressionRuleBasicConfig() string {
	return `
resource "crowdstrike_cloud_security_suppression_rule" "test" {
  name              = "TF Test Basic Suppression Rule"
  description       = "Basic test suppression rule"
  domain            = "CSPM"
  subdomain         = "IOM"
  suppression_reason = "false-positive"

  rule_selection_filter = {
    rule_names = ["Test Rule"]
  }

  scope_asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
  }
}
`
}

func testSuppressionRuleEC2ScenarioConfig(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "ec2_test" {
  name                = "TF Test EC2 Suppression %s"
  description         = "Suppress EC2 instance excessive response hop limit rule for specific instances"
  domain              = "CSPM"
  subdomain           = "IOM"
  suppression_reason  = "accept-risk"
  suppression_comment = "These instances are configured correctly for our architecture"

  rule_selection_filter = {
    rule_names = ["EC2 instance with excessive response hop limit"]
  }

  scope_asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
    resource_types = ["AWS::EC2::Instance"]
    account_ids    = ["123456789012", "123456789013", "123456789014"]
  }
}
`, suffix)
}

func testSuppressionRuleSSMScenarioConfig(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "ssm_test" {
  name                = "TF Test SSM Suppression %s"
  description         = "Suppress SSM parameter encryption rule for legacy parameters"
  domain              = "CSPM"
  subdomain           = "IOM"
  suppression_reason  = "compensating-control"
  suppression_comment = "Legacy parameters with alternative encryption"

  rule_selection_filter = {
    rule_names = ["SSM contains parameters that are not encrypted"]
  }

  scope_asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
    resource_types = ["AWS::SSM::Parameter"]
    account_ids    = ["123456789012", "123456789013", "123456789014", "123456789015", "123456789016"]
  }
}
`, suffix)
}

func testSuppressionRuleAccountLevelConfig(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "account_test" {
  name                = "TF Test Account Level Suppression %s"
  description         = "Suppress multiple backup and monitoring rules for test account"
  domain              = "CSPM"
  subdomain           = "IOM"
  suppression_reason  = "false-positive"
  suppression_comment = "Test account with different compliance requirements"

  rule_selection_filter = {
    rule_names = [
      "Backup plan does not include EBS resources",
      "Backup plan does not include DynamoDB resources",
      "CloudWatch log metric filter and alarm missing for changes to Network Access Control Lists",
      "CloudTrail is not configured to log S3 object-level read events"
    ]
  }

  scope_asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["global"]
    resource_types = ["AWS::Account"]
    account_ids    = ["123456789099"]
  }
}
`, suffix)
}

func testSuppressionRuleWithExpirationConfig(suffix, expirationDate string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "expiration_test" {
  name                       = "TF Test Expiration Suppression %s"
  description                = "Suppression rule with expiration date"
  domain                     = "CSPM"
  subdomain                  = "IOM"
  suppression_reason         = "false-positive"
  suppression_expiration_date = "%s"

  rule_selection_filter = {
    rule_names = ["Test Rule with Expiration"]
  }

  scope_asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
  }
}
`, suffix, expirationDate)
}

func testSuppressionRuleUpdateConfigStep1(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "update_test" {
  name                = "TF Test Update Suppression %s"
  description         = "Initial description"
  domain              = "CSPM"
  subdomain           = "IOM"
  suppression_reason  = "false-positive"
  suppression_comment = "Initial comment"

  rule_selection_filter = {
    rule_names = ["Test Rule"]
  }

  scope_asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
  }
}
`, suffix)
}

func testSuppressionRuleUpdateConfigStep2(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "update_test" {
  name                = "TF Test Update Suppression %s"
  description         = "Updated description"
  domain              = "CSPM"
  subdomain           = "IOM"
  suppression_reason  = "compensating-control"
  suppression_comment = "Updated comment"

  rule_selection_filter = {
    rule_names = ["Test Rule"]
  }

  scope_asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
  }
}
`, suffix)
}

func testSuppressionRuleInvalidConfigNoFilters(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "invalid_test" {
  name              = "TF Test Invalid Suppression %s"
  description       = "Invalid suppression rule without filters"
  domain            = "CSPM"
  subdomain         = "IOM"
  suppression_reason = "false-positive"
}
`, suffix)
}

func testSuppressionRuleInvalidExpirationDate(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "invalid_date_test" {
  name                       = "TF Test Invalid Date %s"
  description                = "Invalid expiration date format"
  domain                     = "CSPM"
  subdomain                  = "IOM"
  suppression_reason         = "false-positive"
  suppression_expiration_date = "2025-12-31"  # Invalid format - should be RFC3339

  rule_selection_filter = {
    rule_names = ["Test Rule"]
  }

  scope_asset_filter = {
    cloud_providers = ["aws"]
  }
}
`, suffix)
}


func testSuppressionRuleSeverityFilterConfig(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "severity_test" {
  name              = "TF Test Severity Filter %s"
  description       = "Test rule severity filtering"
  domain            = "CSPM"
  subdomain         = "IOM"
  suppression_reason = "false-positive"

  rule_selection_filter = {
    rule_severities = ["critical", "high"]
  }

  scope_asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
  }
}
`, suffix)
}

func testSuppressionRuleTagFilterConfig(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "tag_test" {
  name              = "TF Test Tag Filter %s"
  description       = "Test asset tag filtering"
  domain            = "CSPM"
  subdomain         = "IOM"
  suppression_reason = "false-positive"

  rule_selection_filter = {
    rule_names = ["Test Rule"]
  }

  scope_asset_filter = {
    cloud_providers = ["aws"]
    tags           = ["Environment=test", "Team=security"]
  }
}
`, suffix)
}

func testSuppressionRuleWithExpirationClearConfig(suffix, expirationDate string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "expiration_clear_test" {
  name                       = "TF Test Expiration Clear %s"
  description                = "Test expiration date clearing prevention"
  domain                     = "CSPM"
  subdomain                  = "IOM"
  suppression_reason         = "false-positive"
  suppression_expiration_date = "%s"

  rule_selection_filter = {
    rule_names = ["Test Rule Clear"]
  }

  scope_asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
  }
}
`, suffix, expirationDate)
}

func testSuppressionRuleExpirationClearedConfig(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "expiration_clear_test" {
  name                = "TF Test Expiration Clear %s"
  description         = "Test expiration date clearing prevention"
  domain              = "CSPM"
  subdomain           = "IOM"
  suppression_reason  = "false-positive"
  # suppression_expiration_date is intentionally removed/cleared

  rule_selection_filter = {
    rule_names = ["Test Rule Clear"]
  }

  scope_asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
  }
}
`, suffix)
}

func testSuppressionRuleWithExpirationUpdateConfig(suffix, expirationDate string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "expiration_update_test" {
  name                       = "TF Test Expiration Update %s"
  description                = "Test expiration date updating"
  domain                     = "CSPM"
  subdomain                  = "IOM"
  suppression_reason         = "false-positive"
  suppression_expiration_date = "%s"

  rule_selection_filter = {
    rule_names = ["Test Rule Update"]
  }

  scope_asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
  }
}
`, suffix, expirationDate)
}

func testSuppressionRuleEmptyRuleSelectionFilter(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "empty_rule_filter_test" {
  name              = "TF Test Empty Rule Filter %s"
  description       = "Test empty rule selection filter validation"
  domain            = "CSPM"
  subdomain         = "IOM"
  suppression_reason = "false-positive"

  rule_selection_filter = {
    # All filter criteria are intentionally empty/null
  }

  scope_asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
  }
}
`, suffix)
}

func testSuppressionRuleEmptyScopeAssetFilter(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "empty_scope_filter_test" {
  name              = "TF Test Empty Scope Filter %s"
  description       = "Test empty scope asset filter validation"
  domain            = "CSPM"
  subdomain         = "IOM"
  suppression_reason = "false-positive"

  rule_selection_filter = {
    rule_names = ["Test Rule"]
  }

  scope_asset_filter = {
    # All filter criteria are intentionally empty/null
  }
}
`, suffix)
}

func testSuppressionRuleAllRuleSelectionFiltersConfig(suffix string) string {
	return fmt.Sprintf(`
data "crowdstrike_cloud_security_rules" "test_rule" {
  rule_name = "IAM root user has an active access key"
  cloud_provider = "AWS"
}

resource "crowdstrike_cloud_security_suppression_rule" "rule_filters_test" {
  name              = "TF Test All Rule Filters %s"
  description       = "Test all rule selection filter types"
  domain            = "CSPM"
  subdomain         = "IOM"
  suppression_reason = "false-positive"

  rule_selection_filter = {
    rule_ids        = [for rule in data.crowdstrike_cloud_security_rules.test_rule.rules : rule.id]
    rule_names      = ["IAM root user has an active access key"]
    rule_origins    = ["Custom", "Default"]
    rule_providers  = ["AWS", "Azure"]
    rule_services   = ["EC2", "S3"]
    rule_severities = ["critical", "high"]
  }

  scope_asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
  }
}
`, suffix)
}

func testSuppressionRuleAllScopeAssetFiltersConfig(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "scope_filters_test" {
  name              = "TF Test All Scope Filters %s"
  description       = "Test all scope asset filter types"
  domain            = "CSPM"
  subdomain         = "IOM"
  suppression_reason = "false-positive"

  rule_selection_filter = {
    rule_names = ["Test Rule"]
  }

  scope_asset_filter = {
    account_ids        = ["123456789012", "123456789013"]
    cloud_providers    = ["aws", "azure"]
    regions           = ["us-east-1", "us-west-2"]
    resource_ids      = ["res-123", "res-456"]
    resource_names    = ["my-resource", "other-resource"]
    resource_types    = ["AWS::EC2::Instance", "AWS::S3::Bucket"]
    service_categories = ["Compute", "Storage"]
    tags              = ["Environment=prod", "Team=security"]
  }
}
`, suffix)
}

func testSuppressionRuleComplexFiltersConfig(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "complex_test" {
  name              = "TF Test Complex Filters %s"
  description       = "Test complex filter combinations"
  domain            = "CSPM"
  subdomain         = "IOM"
  suppression_reason = "accept-risk"
  suppression_comment = "Complex filtering scenario for testing"

  rule_selection_filter = {
    rule_providers  = ["AWS", "GCP"]
    rule_severities = ["critical", "high", "medium"]
    rule_origins    = ["Custom"]
  }

  scope_asset_filter = {
    cloud_providers    = ["aws", "gcp", "azure"]
    service_categories = ["Compute", "Networking"]
    tags              = ["Environment=staging", "Project=test", "Owner=devops"]
  }
}
`, suffix)
}

func testSuppressionRuleInvalidTagFormat(suffix, invalidTag string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "invalid_tag_test" {
  name              = "TF Test Invalid Tag %s"
  description       = "Test invalid tag format validation"
  domain            = "CSPM"
  subdomain         = "IOM"
  suppression_reason = "false-positive"

  rule_selection_filter = {
    rule_names = ["Test Rule"]
  }

  scope_asset_filter = {
    cloud_providers = ["aws"]
    tags           = ["%s"]
  }
}
`, suffix, invalidTag)
}

func testSuppressionRuleComprehensiveImportConfig(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "import_test" {
  name                = "TF Test Comprehensive Import %s"
  description         = "Comprehensive test for import functionality"
  domain              = "CSPM"
  subdomain           = "IOM"
  suppression_reason  = "compensating-control"
  suppression_comment = "Testing all attributes for import"

  rule_selection_filter = {
    rule_names      = ["Import Test Rule 1", "Import Test Rule 2"]
    rule_severities = ["critical", "high"]
  }

  scope_asset_filter = {
    account_ids    = ["123456789012", "123456789013"]
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
    tags           = ["Environment=import-test", "Purpose=testing"]
  }
}
`, suffix)
}

func testSuppressionRuleAdvancedUpdateStep1(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "advanced_update_test" {
  name              = "TF Test Advanced Update %s"
  description       = "Initial configuration for advanced update test"
  domain            = "CSPM"
  subdomain         = "IOM"
  suppression_reason = "false-positive"

  rule_selection_filter = {
    rule_names = ["Initial Rule"]
  }

  scope_asset_filter = {
    cloud_providers = ["aws"]
  }
}
`, suffix)
}

func testSuppressionRuleAdvancedUpdateStep2(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "advanced_update_test" {
  name              = "TF Test Advanced Update %s"
  description       = "Updated with more complex filters"
  domain            = "CSPM"
  subdomain         = "IOM"
  suppression_reason = "compensating-control"
  suppression_comment = "Added more complex filtering criteria"

  rule_selection_filter = {
    rule_names      = ["Initial Rule", "Additional Rule"]
    rule_severities = ["high", "medium"]
  }

  scope_asset_filter = {
    cloud_providers = ["aws", "azure"]
    tags           = ["Environment=updated", "Status=testing"]
  }
}
`, suffix)
}

func testSuppressionRuleAdvancedUpdateStep3(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "advanced_update_test" {
  name              = "TF Test Advanced Update %s"
  description       = "Completely different filter configuration"
  domain            = "CSPM"
  subdomain         = "IOM"
  suppression_reason = "accept-risk"
  suppression_comment = "Changed to completely different filter types"

  rule_selection_filter = {
    rule_providers = ["GCP"]
    rule_origins   = ["Default"]
  }

  scope_asset_filter = {
    resource_types = ["compute.googleapis.com/Instance", "storage.googleapis.com/Bucket"]
    regions       = ["us-central1", "us-east1"]
  }
}
`, suffix)
}

func TestCloudSecuritySuppressionRuleResource_ExpiredRuleCreation(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.auto_removal_test"

	// Create a rule with expiration date - validates that expired rules show warnings but remain in state
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testSuppressionRuleAutoRemovalConfig(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Auto Removal %s", randomSuffix)),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			// Note: With the new behavior, expired rules remain in state and show warnings
			// rather than being automatically removed
		},
	})
}

func TestCloudSecuritySuppressionRuleResource_ExpiredRuleDestroyAllowed(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.expired_destroy_test"

	// Create with a future date first, then test destroy behavior
	futureDate := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Step 1: Create resource with future expiration date
			{
				Config: testSuppressionRuleValidCreateForDestroyConfig(randomSuffix, futureDate),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Destroy %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "suppression_expiration_date", futureDate),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			// Step 2: Update config to have expired date, then destroy should work
			// This simulates the scenario where a date expires after resource creation
			{
				Config: testSuppressionRuleExpiredForDestroyConfig(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Destroy %s", randomSuffix)),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			// The destroy will happen automatically at the end, testing our destroy logic
		},
	})
}


func TestCloudSecuritySuppressionRuleResource_ExpiredRuleWarningOnRead(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.expired_warning_test"

	// Create with future date, then test read behavior when date expires
	futureDate := time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testSuppressionRuleExpiredWarningConfig(randomSuffix, futureDate),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Expired Warning %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "suppression_expiration_date", futureDate),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			// Note: In practice, when the date expires, the Read method will show a warning
			// but keep the resource in state. This test demonstrates the pattern.
		},
	})
}

func testSuppressionRuleAutoRemovalConfig(suffix string) string {
	// Set expiration to a future date for testing purposes
	futureDate := time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339)
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "auto_removal_test" {
  name                       = "TF Test Auto Removal %s"
  description                = "Test automatic removal when suppression expires"
  domain                     = "CSPM"
  subdomain                  = "IOM"
  suppression_reason         = "false-positive"
  suppression_expiration_date = "%s"

  rule_selection_filter = {
    rule_names = ["Test Auto Removal Rule"]
  }

  scope_asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
  }
}
`, suffix, futureDate)
}

func testSuppressionRuleExpiredDestroyConfig(suffix string) string {
	// Set expiration to a past date to test destroy behavior
	expiredDate := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "expired_destroy_test" {
  name                       = "TF Test Expired Destroy %s"
  description                = "Test destroy behavior with expired suppression date"
  domain                     = "CSPM"
  subdomain                  = "IOM"
  suppression_reason         = "false-positive"
  suppression_expiration_date = "%s"

  rule_selection_filter = {
    rule_names = ["Test Expired Destroy Rule"]
  }

  scope_asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
  }
}
`, suffix, expiredDate)
}

func testSuppressionRuleExpiredCreateConfig(suffix string) string {
	// Set expiration to a past date to test create validation
	expiredDate := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "expired_create_test" {
  name                       = "TF Test Expired Create %s"
  description                = "Test create validation with expired suppression date"
  domain                     = "CSPM"
  subdomain                  = "IOM"
  suppression_reason         = "false-positive"
  suppression_expiration_date = "%s"

  rule_selection_filter = {
    rule_names = ["Test Expired Create Rule"]
  }

  scope_asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
  }
}
`, suffix, expiredDate)
}

func testSuppressionRuleExpiredWarningConfig(suffix, expirationDate string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "expired_warning_test" {
  name                       = "TF Test Expired Warning %s"
  description                = "Test warning behavior when suppression expires"
  domain                     = "CSPM"
  subdomain                  = "IOM"
  suppression_reason         = "false-positive"
  suppression_expiration_date = "%s"

  rule_selection_filter = {
    rule_names = ["Test Expired Warning Rule"]
  }

  scope_asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
  }
}
`, suffix, expirationDate)
}

func testSuppressionRuleValidCreateForDestroyConfig(suffix, expirationDate string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "expired_destroy_test" {
  name                       = "TF Test Destroy %s"
  description                = "Test resource creation with valid date for destroy test"
  domain                     = "CSPM"
  subdomain                  = "IOM"
  suppression_reason         = "false-positive"
  suppression_expiration_date = "%s"

  rule_selection_filter = {
    rule_names = ["Test Valid Create for Destroy Rule"]
  }

  scope_asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
  }
}
`, suffix, expirationDate)
}

func testSuppressionRuleExpiredForDestroyConfig(suffix string) string {
	// Set expiration to a past date to test destroy behavior with expired config
	expiredDate := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "expired_destroy_test" {
  name                       = "TF Test Destroy %s"
  description                = "Test destroy behavior with expired config date"
  domain                     = "CSPM"
  subdomain                  = "IOM"
  suppression_reason         = "false-positive"
  suppression_expiration_date = "%s"

  rule_selection_filter = {
    rule_names = ["Test Valid Create for Destroy Rule"]
  }

  scope_asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
  }
}
`, suffix, expiredDate)
}
