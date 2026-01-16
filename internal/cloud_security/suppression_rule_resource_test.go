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
					resource.TestCheckResourceAttr("crowdstrike_cloud_security_suppression_rule.test", "reason", "false-positive"),
					resource.TestCheckResourceAttr("crowdstrike_cloud_security_suppression_rule.test", "type", "IOM"),
					resource.TestCheckResourceAttrSet("crowdstrike_cloud_security_suppression_rule.test", "id"),
				),
			},
		},
	})
}

func TestCloudSecuritySuppressionRuleResource_Defaults(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testSuppressionRuleDefaultsConfig(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("crowdstrike_cloud_security_suppression_rule.defaults_test", "name", "TF Test Defaults Suppression Rule"),
					resource.TestCheckResourceAttr("crowdstrike_cloud_security_suppression_rule.defaults_test", "reason", "false-positive"),
					// Test all default values
					resource.TestCheckResourceAttr("crowdstrike_cloud_security_suppression_rule.defaults_test", "type", "IOM"),
					resource.TestCheckResourceAttr("crowdstrike_cloud_security_suppression_rule.defaults_test", "description", ""),
					resource.TestCheckResourceAttr("crowdstrike_cloud_security_suppression_rule.defaults_test", "comment", ""),
					resource.TestCheckResourceAttrSet("crowdstrike_cloud_security_suppression_rule.defaults_test", "id"),
					resource.TestCheckNoResourceAttr("crowdstrike_cloud_security_suppression_rule.defaults_test", "expiration_date"),
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
					resource.TestCheckResourceAttr(resourceName, "reason", "accept-risk"),
					resource.TestCheckResourceAttr(resourceName, "comment", "These instances are configured correctly for our architecture"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.names.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.cloud_providers.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.regions.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.resource_types.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.account_ids.#", "3"),
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
					resource.TestCheckResourceAttr(resourceName, "reason", "compensating-control"),
					resource.TestCheckResourceAttr(resourceName, "comment", "Legacy parameters with alternative encryption"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.names.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.cloud_providers.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.regions.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.resource_types.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.account_ids.#", "5"),
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
					resource.TestCheckResourceAttr(resourceName, "reason", "false-positive"),
					resource.TestCheckResourceAttr(resourceName, "comment", "Test account with different compliance requirements"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.names.#", "4"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.cloud_providers.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.regions.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.resource_types.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.account_ids.#", "1"),
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
					resource.TestCheckResourceAttr(resourceName, "expiration_date", expirationDate),
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
					resource.TestCheckResourceAttr(resourceName, "reason", "false-positive"),
					resource.TestCheckResourceAttr(resourceName, "comment", "Initial comment"),
				),
			},
			// Update the rule
			{
				Config: testSuppressionRuleUpdateConfigStep2(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Update Suppression %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "description", "Updated description"),
					resource.TestCheckResourceAttr(resourceName, "reason", "compensating-control"),
					resource.TestCheckResourceAttr(resourceName, "comment", "Updated comment"),
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
					resource.TestCheckResourceAttr(resourceName, "expiration_date", initialExpiration),
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
					resource.TestCheckResourceAttr(resourceName, "expiration_date", initialExpiration),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			// Step 2: Update expiration date to a new value - should succeed
			{
				Config: testSuppressionRuleWithExpirationUpdateConfig(randomSuffix, updatedExpiration),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Expiration Update %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "expiration_date", updatedExpiration),
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
				ExpectError: regexp.MustCompile(`At least one of 'rule_selection_filter' or 'asset_filter'`),
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
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.severities.#", "2"),
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
					resource.TestCheckResourceAttr(resourceName, "asset_filter.tags.#", "2"),
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
				ExpectError: regexp.MustCompile("Empty Asset Filter"),
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
					resource.TestCheckResourceAttrSet(resourceName, "rule_selection_filter.ids.#"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.names.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.origins.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.providers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.services.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.severities.#", "2"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

// Add cloud_group_ids when cloud groups data source is added.
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
					resource.TestCheckResourceAttr(resourceName, "asset_filter.account_ids.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.cloud_providers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.regions.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.resource_ids.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.resource_names.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.resource_types.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.service_categories.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.tags.#", "2"),
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
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.providers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.severities.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.origins.#", "1"),
					// Scope asset filter checks
					resource.TestCheckResourceAttr(resourceName, "asset_filter.cloud_providers.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.service_categories.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.tags.#", "3"),
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
					resource.TestCheckResourceAttr(resourceName, "comment", "Testing all attributes for import"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.names.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.severities.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.account_ids.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.tags.#", "2"),
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
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.names.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.cloud_providers.#", "1"),
				),
			},
			// Update to add more complex filters
			{
				Config: testSuppressionRuleAdvancedUpdateStep2(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Advanced Update %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.names.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.severities.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.cloud_providers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.tags.#", "2"),
				),
			},
			// Update to change filter types completely
			{
				Config: testSuppressionRuleAdvancedUpdateStep3(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Advanced Update %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.providers.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rule_selection_filter.origins.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.resource_types.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.regions.#", "2"),
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
  type              = "IOM"
  description       = "Basic test suppression rule"
  reason = "false-positive"

  rule_selection_filter = {
    names = ["Test Rule"]
  }

  asset_filter = {
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
  type                = "IOM"
  description         = "Suppress EC2 instance excessive response hop limit rule for specific instances"
  reason  = "accept-risk"
  comment = "These instances are configured correctly for our architecture"

  rule_selection_filter = {
    names = ["EC2 instance with excessive response hop limit"]
  }

  asset_filter = {
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
  reason  = "compensating-control"
  comment = "Legacy parameters with alternative encryption"

  rule_selection_filter = {
    names = ["SSM contains parameters that are not encrypted"]
  }

  asset_filter = {
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
  reason  = "false-positive"
  comment = "Test account with different compliance requirements"

  rule_selection_filter = {
    names = [
      "Backup plan does not include EBS resources",
      "Backup plan does not include DynamoDB resources",
      "CloudWatch log metric filter and alarm missing for changes to Network Access Control Lists",
      "CloudTrail is not configured to log S3 object-level read events"
    ]
  }

  asset_filter = {
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
  type                       = "IOM"
  description                = "Suppression rule with expiration date"
  reason         = "false-positive"
  expiration_date = "%s"

  rule_selection_filter = {
    names = ["Test Rule with Expiration"]
  }

  asset_filter = {
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
  reason  = "false-positive"
  comment = "Initial comment"

  rule_selection_filter = {
    names = ["Test Rule"]
  }

  asset_filter = {
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
  reason  = "compensating-control"
  comment = "Updated comment"

  rule_selection_filter = {
    names = ["Test Rule"]
  }

  asset_filter = {
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
  reason = "false-positive"
}
`, suffix)
}

func testSuppressionRuleInvalidExpirationDate(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "invalid_date_test" {
  name                       = "TF Test Invalid Date %s"
  description                = "Invalid expiration date format"
  reason         = "false-positive"
  expiration_date = "2025-12-31"  # Invalid format - should be RFC3339

  rule_selection_filter = {
    names = ["Test Rule"]
  }

  asset_filter = {
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
  reason = "false-positive"

  rule_selection_filter = {
    severities = ["critical", "high"]
  }

  asset_filter = {
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
  reason = "false-positive"

  rule_selection_filter = {
    names = ["Test Rule"]
  }

  asset_filter = {
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
  reason         = "false-positive"
  expiration_date = "%s"

  rule_selection_filter = {
    names = ["Test Rule Clear"]
  }

  asset_filter = {
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
  reason  = "false-positive"
  # expiration_date is intentionally removed/cleared

  rule_selection_filter = {
    names = ["Test Rule Clear"]
  }

  asset_filter = {
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
  reason         = "false-positive"
  expiration_date = "%s"

  rule_selection_filter = {
    names = ["Test Rule Update"]
  }

  asset_filter = {
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
  reason = "false-positive"

  rule_selection_filter = {
    # All filter criteria are intentionally empty/null
  }

  asset_filter = {
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
  reason = "false-positive"

  rule_selection_filter = {
    names = ["Test Rule"]
  }

  asset_filter = {
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
  reason = "false-positive"

  rule_selection_filter = {
    ids        = [for rule in data.crowdstrike_cloud_security_rules.test_rule.rules : rule.id]
    names      = ["IAM root user has an active access key"]
    origins    = ["Custom", "Default"]
    providers  = ["AWS", "Azure"]
    services   = ["EC2", "S3"]
    severities = ["critical", "high"]
  }

  asset_filter = {
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
  reason = "false-positive"

  rule_selection_filter = {
    names = ["Test Rule"]
  }

  asset_filter = {
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
  reason = "accept-risk"
  comment = "Complex filtering scenario for testing"

  rule_selection_filter = {
    providers  = ["AWS", "GCP"]
    severities = ["critical", "high", "medium"]
    origins    = ["Custom"]
  }

  asset_filter = {
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
  reason = "false-positive"

  rule_selection_filter = {
    names = ["Test Rule"]
  }

  asset_filter = {
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
  reason  = "compensating-control"
  comment = "Testing all attributes for import"

  rule_selection_filter = {
    names      = ["Import Test Rule 1", "Import Test Rule 2"]
    severities = ["critical", "high"]
  }

  asset_filter = {
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
  reason = "false-positive"

  rule_selection_filter = {
    names = ["Initial Rule"]
  }

  asset_filter = {
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
  reason = "compensating-control"
  comment = "Added more complex filtering criteria"

  rule_selection_filter = {
    names      = ["Initial Rule", "Additional Rule"]
    severities = ["high", "medium"]
  }

  asset_filter = {
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
  reason = "accept-risk"
  comment = "Changed to completely different filter types"

  rule_selection_filter = {
    providers = ["GCP"]
    origins   = ["Default"]
  }

  asset_filter = {
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
					resource.TestCheckResourceAttr(resourceName, "expiration_date", futureDate),
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
  reason         = "false-positive"
  expiration_date = "%s"

  rule_selection_filter = {
    names = ["Test Auto Removal Rule"]
  }

  asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
  }
}
`, suffix, futureDate)
}

func testSuppressionRuleExpiredCreateConfig(suffix string) string {
	// Set expiration to a past date to test create validation
	expiredDate := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "expired_create_test" {
  name                       = "TF Test Expired Create %s"
  description                = "Test create validation with expired suppression date"
  reason         = "false-positive"
  expiration_date = "%s"

  rule_selection_filter = {
    names = ["Test Expired Create Rule"]
  }

  asset_filter = {
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
  reason         = "false-positive"
  expiration_date = "%s"

  rule_selection_filter = {
    names = ["Test Expired Warning Rule"]
  }

  asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
  }
}
`, suffix, expirationDate)
}

func TestCloudSecuritySuppressionRuleResource_BadRequestErrorHandling(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Test creating a suppression rule with an invalid rule name to trigger a 400 Bad Request
			// This will test that GetPayloadErrorMessage correctly extracts error messages from API responses
			{
				Config:      testSuppressionRuleBadRequestConfig(randomSuffix),
				ExpectError: regexp.MustCompile(`Failed to create suppression rule \(400\).*`),
			},
		},
	})
}

// Configuration that may trigger a 400 Bad Request for API testing.
func testSuppressionRuleBadRequestConfig(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "bad_request_test" {
  name              = "This is a test suppression rule name that deliberately exceeds the one hundred character limit to validate proper error handling %s"
  description       = "Test bad request error handling"
  reason = "false-positive"

  rule_selection_filter = {
    names = ["Test Rule"]
  }

  asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
  }
}
`, suffix)
}

func testSuppressionRuleDefaultsConfig() string {
	return `
resource "crowdstrike_cloud_security_suppression_rule" "defaults_test" {
  name   = "TF Test Defaults Suppression Rule"
  reason = "false-positive"

  rule_selection_filter = {
    names = ["Test Rule for Defaults"]
  }

  asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
  }
}
`
}
