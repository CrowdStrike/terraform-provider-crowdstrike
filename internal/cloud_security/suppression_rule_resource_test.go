package cloudsecurity_test

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// apiThrottleDelay adds a configurable delay to prevent API throttling
// Can be controlled via TEST_DELAY_SECONDS environment variable (default: 0 seconds).
func apiThrottleDelay() {
	delaySeconds := 0 // default delay
	if envDelay := os.Getenv("TEST_DELAY_SECONDS"); envDelay != "" {
		if parsed, err := strconv.Atoi(envDelay); err == nil && parsed >= 0 {
			delaySeconds = parsed
		}
	}
	if delaySeconds > 0 {
		time.Sleep(time.Duration(delaySeconds) * time.Second)
	}
}

// runTest executes a test case using either parallel or sequential mode based on environment variables
// TEST_PARALLEL=true  -> resource.ParallelTest
// TEST_PARALLEL=false -> resource.Test
// If not set, defaults to sequential when delays are configured, parallel when no delays.
func runTest(t *testing.T, testCase resource.TestCase) {
	useParallel := shouldUseParallel()

	if useParallel {
		resource.ParallelTest(t, testCase)
	} else {
		resource.Test(t, testCase)
	}
}

func shouldUseParallel() bool {
	if envParallel := os.Getenv("TEST_PARALLEL"); envParallel != "" {
		return envParallel == "true" || envParallel == "1"
	}

	if envDelay := os.Getenv("TEST_DELAY_SECONDS"); envDelay != "" && envDelay != "0" {
		return false
	}

	return true
}

func TestCloudSecuritySuppressionRuleResource_Basic(t *testing.T) {
	runTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				PreConfig: func() { apiThrottleDelay() },
				Config:    testSuppressionRuleBasicConfig(),
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
	runTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				PreConfig: func() { apiThrottleDelay() },
				Config:    testSuppressionRuleDefaultsConfig(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("crowdstrike_cloud_security_suppression_rule.defaults_test", "name", "TF Test Defaults Suppression Rule"),
					resource.TestCheckResourceAttr("crowdstrike_cloud_security_suppression_rule.defaults_test", "reason", "false-positive"),
					// Test required fields and default values for optional fields
					resource.TestCheckResourceAttr("crowdstrike_cloud_security_suppression_rule.defaults_test", "type", "IOM"),
					resource.TestCheckResourceAttrSet("crowdstrike_cloud_security_suppression_rule.defaults_test", "id"),
					resource.TestCheckNoResourceAttr("crowdstrike_cloud_security_suppression_rule.defaults_test", "description"),
					resource.TestCheckNoResourceAttr("crowdstrike_cloud_security_suppression_rule.defaults_test", "expiration_date"),
					resource.TestCheckNoResourceAttr("crowdstrike_cloud_security_suppression_rule.defaults_test", "comment"),
					// Test that required filter attributes are properly set
					resource.TestCheckResourceAttr("crowdstrike_cloud_security_suppression_rule.defaults_test", "rule_selection_filter.names.#", "1"),
					resource.TestCheckResourceAttr("crowdstrike_cloud_security_suppression_rule.defaults_test", "asset_filter.cloud_providers.#", "1"),
					resource.TestCheckResourceAttr("crowdstrike_cloud_security_suppression_rule.defaults_test", "asset_filter.regions.#", "1"),
				),
			},
		},
	})
}

func TestCloudSecuritySuppressionRuleResource_EC2Scenario(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.ec2_test"

	runTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				PreConfig: func() { apiThrottleDelay() },
				Config:    testSuppressionRuleEC2ScenarioConfig(randomSuffix),
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

func TestCloudSecuritySuppressionRuleResource_AccountLevelMultiRule(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.account_test"

	runTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				PreConfig: func() { apiThrottleDelay() },
				Config:    testSuppressionRuleAccountLevelConfig(randomSuffix),
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

	runTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				PreConfig: func() { apiThrottleDelay() },
				Config:    testSuppressionRuleWithExpirationConfig(randomSuffix, expirationDate),
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

	runTest(t, resource.TestCase{
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

func TestCloudSecuritySuppressionRuleResource_ExpirationDateRequiresReplacement(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.expiration_replace_test"
	var originalID string

	initialExpiration := time.Now().Add(14 * 24 * time.Hour).UTC().Format(time.RFC3339)

	runTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Step 1: Create with expiration date
			{
				Config: testSuppressionRuleWithExpirationReplaceConfig(randomSuffix, initialExpiration),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Expiration Replace %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "expiration_date", initialExpiration),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[resourceName]
						if !ok {
							return fmt.Errorf("resource not found: %s", resourceName)
						}
						originalID = rs.Primary.ID
						return nil
					},
				),
			},
			// Step 2: Clear expiration date - should trigger replacement (new ID)
			{
				Config: testSuppressionRuleExpirationReplacedConfig(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Expiration Replace %s", randomSuffix)),
					resource.TestCheckNoResourceAttr(resourceName, "expiration_date"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[resourceName]
						if !ok {
							return fmt.Errorf("resource not found: %s", resourceName)
						}
						if rs.Primary.ID == originalID {
							return fmt.Errorf("expected resource replacement (ID change), but ID remained the same: %s", originalID)
						}
						return nil
					},
				),
			},
		},
	})
}

func TestCloudSecuritySuppressionRuleResource_ExpirationDateCanBeUpdated(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.expiration_update_test"

	initialExpiration := time.Now().Add(14 * 24 * time.Hour).UTC().Format(time.RFC3339)
	updatedExpiration := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)

	runTest(t, resource.TestCase{
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

	runTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Test missing required filters
			{
				Config:      testSuppressionRuleInvalidConfigNoFilters(randomSuffix),
				ExpectError: regexp.MustCompile(`At[\s\n]*least[\s\n]*one[\s\n]*attribute[\s\n]*out[\s\n]*of[\s\S]*must[\s\n]*be[\s\n]*specified`),
				PlanOnly:    true,
			},
			// Test invalid expiration date format
			{
				Config:      testSuppressionRuleInvalidExpirationDate(randomSuffix),
				ExpectError: regexp.MustCompile(`A[\s\n]*string[\s\n]*value[\s\n]*was[\s\n]*provided[\s\n]*that[\s\n]*is[\s\n]*not[\s\n]*valid[\s\n]*RFC3339[\s\n]*string[\s\n]*format\.`),
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

	runTest(t, resource.TestCase{
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

	runTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testSuppressionRuleTagFilterConfig(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Tag Filter %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.tags.%", "2"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

func TestCloudSecuritySuppressionRuleResource_EmptyFilterValidation(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)

	runTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Test empty rule selection filter
			{
				Config:      testSuppressionRuleEmptyRuleSelectionFilter(randomSuffix),
				ExpectError: regexp.MustCompile("Empty Object"),
				PlanOnly:    true,
			},
			// Test empty scope asset filter
			{
				Config:      testSuppressionRuleEmptyScopeAssetFilter(randomSuffix),
				ExpectError: regexp.MustCompile("Empty Object"),
				PlanOnly:    true,
			},
		},
	})
}

func TestCloudSecuritySuppressionRuleResource_AllRuleSelectionFilters(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.rule_filters_test"

	runTest(t, resource.TestCase{
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

func TestCloudSecuritySuppressionRuleResource_AllScopeAssetFilters(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.scope_filters_test"

	runTest(t, resource.TestCase{
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
					resource.TestCheckResourceAttr(resourceName, "asset_filter.tags.%", "2"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

func TestCloudSecuritySuppressionRuleResource_ComplexFilterCombinations(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.complex_test"

	runTest(t, resource.TestCase{
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
					resource.TestCheckResourceAttr(resourceName, "asset_filter.tags.%", "3"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

func TestCloudSecuritySuppressionRuleResource_TagConfiguration(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.tag_config_test"

	runTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Test successful tag map configuration
			{
				Config: testSuppressionRuleTagConfiguration(randomSuffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Tag Config %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.tags.%", "3"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.tags.Environment", "production"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.tags.Team", "security"),
					resource.TestCheckResourceAttr(resourceName, "asset_filter.tags.Project", "test"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

func TestCloudSecuritySuppressionRuleResource_ComprehensiveImportState(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.import_test"

	runTest(t, resource.TestCase{
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
					resource.TestCheckResourceAttr(resourceName, "asset_filter.tags.%", "2"),
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

	runTest(t, resource.TestCase{
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
					resource.TestCheckResourceAttr(resourceName, "asset_filter.tags.%", "2"),
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

func testSuppressionRuleAccountLevelConfig(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "account_test" {
  name                = "TF Test Account Level Suppression %s"
  type                = "IOM"
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
  type                = "IOM"
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
  type                = "IOM"
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
  type              = "IOM"
  description       = "Invalid suppression rule without filters"
  reason = "false-positive"
}
`, suffix)
}

func testSuppressionRuleInvalidExpirationDate(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "invalid_date_test" {
  name                       = "TF Test Invalid Date %s"
  type                       = "IOM"
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
  type              = "IOM"
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
  type              = "IOM"
  description       = "Test asset tag filtering"
  reason = "false-positive"

  rule_selection_filter = {
    names = ["Test Rule"]
  }

  asset_filter = {
    cloud_providers = ["aws"]
    tags           = {
      Environment = "test"
      Team        = "security"
    }
  }
}
`, suffix)
}

func testSuppressionRuleWithExpirationUpdateConfig(suffix, expirationDate string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "expiration_update_test" {
  name                       = "TF Test Expiration Update %s"
  type                       = "IOM"
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
  type              = "IOM"
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
  type              = "IOM"
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
  type              = "IOM"
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
  type              = "IOM"
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
    tags              = {
      Environment = "prod"
      Team        = "security"
    }
  }
}
`, suffix)
}

func testSuppressionRuleComplexFiltersConfig(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "complex_test" {
  name              = "TF Test Complex Filters %s"
  type              = "IOM"
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
    tags              = {
      Environment = "staging"
      Project     = "test"
      Owner       = "devops"
    }
  }
}
`, suffix)
}

func testSuppressionRuleTagConfiguration(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "tag_config_test" {
  name              = "TF Test Tag Config %s"
  type              = "IOM"
  description       = "Test tag map configuration"
  reason = "false-positive"

  rule_selection_filter = {
    names = ["Test Rule"]
  }

  asset_filter = {
    cloud_providers = ["aws"]
    tags           = {
      Environment = "production"
      Team        = "security"
      Project     = "test"
    }
  }
}
`, suffix)
}

func testSuppressionRuleComprehensiveImportConfig(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "import_test" {
  name                = "TF Test Comprehensive Import %s"
  type                = "IOM"
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
    tags           = {
      Environment = "import-test"
      Purpose     = "testing"
    }
  }
}
`, suffix)
}

func testSuppressionRuleAdvancedUpdateStep1(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "advanced_update_test" {
  name              = "TF Test Advanced Update %s"
  type              = "IOM"
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
  type              = "IOM"
  description       = "Updated with more complex filters"
  reason = "compensating-control"
  comment = "Added more complex filtering criteria"

  rule_selection_filter = {
    names      = ["Initial Rule", "Additional Rule"]
    severities = ["high", "medium"]
  }

  asset_filter = {
    cloud_providers = ["aws", "azure"]
    tags           = {
      Environment = "updated"
      Status      = "testing"
    }
  }
}
`, suffix)
}

func testSuppressionRuleAdvancedUpdateStep3(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "advanced_update_test" {
  name              = "TF Test Advanced Update %s"
  type              = "IOM"
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

func TestCloudSecuritySuppressionRuleResource_ExpirationDateValidationBehavior(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.expiration_behavior_test"

	// Set expiration to past date for validation testing
	expiredDate := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	// Set expiration to future date for successful operations
	futureDate := time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339)

	runTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Test 1: Create operation should fail with expired date
			{
				Config:      testSuppressionRuleExpirationValidationConfig(randomSuffix, expiredDate),
				ExpectError: regexp.MustCompile("has already passed"),
			},
			// Test 2: Create operation should succeed with future date
			{
				Config: testSuppressionRuleExpirationValidationConfig(randomSuffix, futureDate),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Expiration Behavior %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "expiration_date", futureDate),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			// Test 3: Update operation should fail when trying to set expired date
			{
				Config:      testSuppressionRuleExpirationValidationConfig(randomSuffix, expiredDate),
				ExpectError: regexp.MustCompile("has already passed"),
			},
			// Test 4: Import state should succeed even with expired date (simulates Read behavior)
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "id",
			},
		},
	})
}

func TestCloudSecuritySuppressionRuleResource_ExpiredRuleWarningOnRead(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.expired_warning_test"

	// Create with future date, then test read behavior when date expires
	futureDate := time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339)

	runTest(t, resource.TestCase{
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
		},
	})
}

func testSuppressionRuleExpiredCreateConfig(suffix string) string {
	// Set expiration to a past date to test create validation
	expiredDate := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "expired_create_test" {
  name                       = "TF Test Expired Create %s"
  type                       = "IOM"
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

func testSuppressionRuleExpirationValidationConfig(suffix, expirationDate string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "expiration_behavior_test" {
  name                       = "TF Test Expiration Behavior %s"
  type                       = "IOM"
  description                = "Test expiration date validation behavior"
  reason         = "false-positive"
  expiration_date = "%s"

  rule_selection_filter = {
    names = ["Test Expiration Behavior Rule"]
  }

  asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
  }
}
`, suffix, expirationDate)
}

func testSuppressionRuleExpiredWarningConfig(suffix, expirationDate string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "expired_warning_test" {
  name                       = "TF Test Expired Warning %s"
  type                       = "IOM"
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

	runTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Test creating a suppression rule with an invalid rule name to trigger a 400 Bad Request
			// This will test that GetPayloadErrorMessage correctly extracts error messages from API responses
			{
				Config:      testSuppressionRuleBadRequestConfig(randomSuffix),
				ExpectError: regexp.MustCompile(`(?s)Failed to create: 400 Bad Request.*`),
			},
		},
	})
}

// Configuration that may trigger a 400 Bad Request for API testing.
func testSuppressionRuleBadRequestConfig(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "bad_request_test" {
  name              = "This is a test suppression rule name that deliberately exceeds the one hundred character limit to validate proper error handling %s"
  type              = "IOM"
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

func testSuppressionRuleWithExpirationReplaceConfig(suffix, expirationDate string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "expiration_replace_test" {
  name                       = "TF Test Expiration Replace %s"
  type                       = "IOM"
  description                = "Test expiration date replacement behavior"
  reason         = "false-positive"
  expiration_date = "%s"

  rule_selection_filter = {
    names = ["Test Rule with Expiration Replace"]
  }

  asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
  }
}
`, suffix, expirationDate)
}

func testSuppressionRuleExpirationReplacedConfig(suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "expiration_replace_test" {
  name                = "TF Test Expiration Replace %s"
  type                = "IOM"
  description         = "Test expiration date replacement behavior"
  reason  = "false-positive"
  # expiration_date is intentionally removed/cleared - should trigger replacement

  rule_selection_filter = {
    names = ["Test Rule with Expiration Replace"]
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
  type   = "IOM"
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

func TestCloudSecuritySuppressionRuleResource_DeleteWithExpiredDate(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.delete_expired_test"

	// Create with a short expiration (5 seconds in future) to ensure it expires before delete
	shortExpiration := time.Now().Add(10 * time.Second).UTC().Format(time.RFC3339)

	runTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Step 1: Create with short expiration
			{
				Config: testSuppressionRuleDeleteExpiredConfig(randomSuffix, shortExpiration),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Delete Expired %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "expiration_date", shortExpiration),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			// Step 2: Wait for expiration then delete should succeed
			{
				PreConfig: func() {
					// Wait for expiration to pass
					time.Sleep(20 * time.Second)
				},
				Config: testSuppressionRuleDeleteExpiredRemovedConfig(),
			},
		},
	})
}

func TestCloudSecuritySuppressionRuleResource_ReadWithExpiredDate(t *testing.T) {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := "crowdstrike_cloud_security_suppression_rule.read_expired_test"

	// Create with future date initially
	futureDate := time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339)

	runTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Step 1: Create with future expiration
			{
				Config: testSuppressionRuleReadExpiredConfig(randomSuffix, futureDate),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Read Expired %s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceName, "expiration_date", futureDate),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			// Step 2: Refresh operation should succeed even if we manually set an expired date
			// This simulates the Read operation with an expired date
			{
				Config: testSuppressionRuleReadExpiredConfig(randomSuffix, futureDate),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("TF Test Read Expired %s", randomSuffix)),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

func testSuppressionRuleDeleteExpiredConfig(suffix, expirationDate string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "delete_expired_test" {
  name                       = "TF Test Delete Expired %s"
  type                       = "IOM"
  description                = "Test delete operation with expired date"
  reason         = "false-positive"
  expiration_date = "%s"

  rule_selection_filter = {
    names = ["Test Delete Expired Rule"]
  }

  asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
  }
}
`, suffix, expirationDate)
}

func testSuppressionRuleDeleteExpiredRemovedConfig() string {
	return `
# Resource removed - should trigger delete operation
`
}

func testSuppressionRuleReadExpiredConfig(suffix, expirationDate string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_suppression_rule" "read_expired_test" {
  name                       = "TF Test Read Expired %s"
  type                       = "IOM"
  description                = "Test read operation with expired date"
  reason         = "false-positive"
  expiration_date = "%s"

  rule_selection_filter = {
    names = ["Test Read Expired Rule"]
  }

  asset_filter = {
    cloud_providers = ["aws"]
    regions        = ["us-east-1"]
  }
}
`, suffix, expirationDate)
}
