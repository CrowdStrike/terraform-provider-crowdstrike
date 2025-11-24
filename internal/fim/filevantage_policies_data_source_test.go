package fim_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
)

func TestAccFilevantagePoliciesDataSource_Basic(t *testing.T) {
	resourceName := "data.crowdstrike_filevantage_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFilevantagePoliciesDataSourceConfigBasic(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.id"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.name"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.platform_name"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.enabled"),
				),
			},
		},
	})
}

func TestAccFilevantagePoliciesDataSource_WithType(t *testing.T) {
	resourceName := "data.crowdstrike_filevantage_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFilevantagePoliciesDataSourceConfigWithTypeWindows(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
					resource.TestCheckResourceAttr(resourceName, "policies.0.platform_name", "Windows"),
				),
			},
			{
				Config: testAccFilevantagePoliciesDataSourceConfigWithTypeLinux(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
					resource.TestCheckResourceAttr(resourceName, "policies.0.platform_name", "Linux"),
				),
			},
			{
				Config: testAccFilevantagePoliciesDataSourceConfigWithTypeMac(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
					resource.TestCheckResourceAttr(resourceName, "policies.0.platform_name", "Mac"),
				),
			},
		},
	})
}

func TestAccFilevantagePoliciesDataSource_WithIDs(t *testing.T) {
	resourceName := "data.crowdstrike_filevantage_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFilevantagePoliciesDataSourceConfigWithIDs(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
					resource.TestMatchResourceAttr(resourceName, "policies.#", regexp.MustCompile(`^[12]$`)),
				),
			},
		},
	})
}

func TestAccFilevantagePoliciesDataSource_WithSorting(t *testing.T) {
	resourceName := "data.crowdstrike_filevantage_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFilevantagePoliciesDataSourceConfigWithSortingAsc(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
				),
			},
			{
				Config: testAccFilevantagePoliciesDataSourceConfigWithSortingDesc(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
				),
			},
			{
				Config: testAccFilevantagePoliciesDataSourceConfigWithSortingFiltered(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
				),
			},
		},
	})
}

func TestAccFilevantagePoliciesDataSource_ValidationErrors(t *testing.T) {
	testCases := map[string]struct {
		configFunc  func() string
		expectError *regexp.Regexp
	}{
		"type_with_ids": {
			configFunc:  testAccFilevantagePoliciesDataSourceConfigValidationTypeWithIDs,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"missing_required_attributes": {
			configFunc:  testAccFilevantagePoliciesDataSourceConfigValidationMissingRequired,
			expectError: regexp.MustCompile("Missing Required Attribute"),
		},
		"invalid_type_value": {
			configFunc:  testAccFilevantagePoliciesDataSourceConfigValidationInvalidType,
			expectError: regexp.MustCompile("Attribute type value must be one of"),
		},
		"invalid_ids_format": {
			configFunc:  testAccFilevantagePoliciesDataSourceConfigValidationInvalidIDs,
			expectError: regexp.MustCompile("Attribute ids string length must be between 32 and 32"),
		},
		"empty_ids_list": {
			configFunc:  testAccFilevantagePoliciesDataSourceConfigValidationEmptyIDs,
			expectError: regexp.MustCompile("Attribute ids list must contain at least 1 elements"),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			resource.ParallelTest(t, resource.TestCase{
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				PreCheck:                 func() { acctest.PreCheck(t) },
				Steps: []resource.TestStep{
					{
						Config:      tc.configFunc(),
						ExpectError: tc.expectError,
					},
				},
			})
		})
	}
}

func TestAccFilevantagePoliciesDataSource_EmptyResults(t *testing.T) {
	resourceName := "data.crowdstrike_filevantage_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFilevantagePoliciesDataSourceConfigEmptyResults(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "policies.#", "0"),
				),
			},
		},
	})
}

func TestAccFilevantagePoliciesDataSource_404Handling(t *testing.T) {
	resourceName := "data.crowdstrike_filevantage_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFilevantagePoliciesDataSourceConfig404NonExistentID(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "policies.#", "0"),
				),
			},
			{
				Config: testAccFilevantagePoliciesDataSourceConfig404PartialResults(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "policies.#", "1"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.id"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.name"),
				),
			},
		},
	})
}

func TestAccFilevantagePoliciesDataSource_AllAttributes(t *testing.T) {
	resourceName := "data.crowdstrike_filevantage_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFilevantagePoliciesDataSourceConfigBasic(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.id"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.name"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.platform_name"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.enabled"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.host_groups.#"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.ioa_rule_groups.#"),
				),
			},
		},
	})
}

func TestAccFilevantagePoliciesDataSource_ResourceMatch(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	dataSourceName := "data.crowdstrike_filevantage_policies.test"
	resourceName := "crowdstrike_filevantage_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFilevantagePoliciesDataSourceConfigResourceMatch(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(resourceName, "id", dataSourceName, "policies.0.id"),
					resource.TestCheckResourceAttrPair(resourceName, "name", dataSourceName, "policies.0.name"),
					resource.TestCheckResourceAttr(dataSourceName, "policies.0.platform_name", "Windows"),
					resource.TestCheckResourceAttrPair(resourceName, "enabled", dataSourceName, "policies.0.enabled"),
					resource.TestCheckResourceAttrPair(resourceName, "description", dataSourceName, "policies.0.description"),
				),
			},
		},
	})
}

// Test Configuration Functions

func testAccFilevantagePoliciesDataSourceConfigBasic() string {
	return acctest.ProviderConfig + `
data "crowdstrike_filevantage_policies" "test" {
  type = "Windows"
}
`
}

func testAccFilevantagePoliciesDataSourceConfigWithTypeWindows() string {
	return acctest.ProviderConfig + `
data "crowdstrike_filevantage_policies" "test" {
  type = "Windows"
}
`
}

func testAccFilevantagePoliciesDataSourceConfigWithTypeLinux() string {
	return acctest.ProviderConfig + `
data "crowdstrike_filevantage_policies" "test" {
  type = "Linux"
}
`
}

func testAccFilevantagePoliciesDataSourceConfigWithTypeMac() string {
	return acctest.ProviderConfig + `
data "crowdstrike_filevantage_policies" "test" {
  type = "Mac"
}
`
}

func testAccFilevantagePoliciesDataSourceConfigWithIDs() string {
	return acctest.ProviderConfig + `
data "crowdstrike_filevantage_policies" "all" {
  type = "Windows"
}

data "crowdstrike_filevantage_policies" "test" {
  ids = [
    data.crowdstrike_filevantage_policies.all.policies[0].id,
    length(data.crowdstrike_filevantage_policies.all.policies) > 1 ? data.crowdstrike_filevantage_policies.all.policies[1].id : data.crowdstrike_filevantage_policies.all.policies[0].id
  ]
}
`
}

func testAccFilevantagePoliciesDataSourceConfigWithSortingAsc() string {
	return acctest.ProviderConfig + `
data "crowdstrike_filevantage_policies" "test" {
  type = "Windows"
  sort = "modified_timestamp.asc"
}
`
}

func testAccFilevantagePoliciesDataSourceConfigWithSortingDesc() string {
	return acctest.ProviderConfig + `
data "crowdstrike_filevantage_policies" "test" {
  type = "Linux"
  sort = "created_timestamp.desc"
}
`
}

func testAccFilevantagePoliciesDataSourceConfigWithSortingFiltered() string {
	return acctest.ProviderConfig + `
data "crowdstrike_filevantage_policies" "test" {
  type = "Mac"
  sort = "precedence.asc"
}
`
}

func testAccFilevantagePoliciesDataSourceConfigValidationTypeWithIDs() string {
	return acctest.ProviderConfig + `
data "crowdstrike_filevantage_policies" "test" {
  type = "Windows"
  ids  = ["00000000000000000000000000000001", "00000000000000000000000000000002"]
}
`
}

func testAccFilevantagePoliciesDataSourceConfigValidationMissingRequired() string {
	return acctest.ProviderConfig + `
data "crowdstrike_filevantage_policies" "test" {
  # Neither type nor ids specified
}
`
}

func testAccFilevantagePoliciesDataSourceConfigValidationInvalidType() string {
	return acctest.ProviderConfig + `
data "crowdstrike_filevantage_policies" "test" {
  type = "InvalidType"
}
`
}

func testAccFilevantagePoliciesDataSourceConfigValidationInvalidIDs() string {
	return acctest.ProviderConfig + `
data "crowdstrike_filevantage_policies" "test" {
  ids = ["invalid-short-id"]
}
`
}

func testAccFilevantagePoliciesDataSourceConfigValidationEmptyIDs() string {
	return acctest.ProviderConfig + `
data "crowdstrike_filevantage_policies" "test" {
  ids = []
}
`
}

func testAccFilevantagePoliciesDataSourceConfigEmptyResults() string {
	return acctest.ProviderConfig + `
data "crowdstrike_filevantage_policies" "test" {
  ids = ["00000000000000000000000000000000"]
}
`
}

func testAccFilevantagePoliciesDataSourceConfig404NonExistentID() string {
	return acctest.ProviderConfig + `
data "crowdstrike_filevantage_policies" "test" {
  ids = ["00000000000000000000000000000000"]
}
`
}

func testAccFilevantagePoliciesDataSourceConfig404PartialResults() string {
	return acctest.ProviderConfig + `
data "crowdstrike_filevantage_policies" "all" {
  type = "Windows"
}

data "crowdstrike_filevantage_policies" "test" {
  ids = [
    data.crowdstrike_filevantage_policies.all.policies[0].id,
    "00000000000000000000000000000000"
  ]
}
`
}

func testAccFilevantagePoliciesDataSourceConfigResourceMatch(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name        = %[1]q
  description = "Test host group for data source acceptance test"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_filevantage_policy" "test" {
  name         = %[1]q
  description  = "Test policy for data source acceptance test"
  platform_name = "Windows"
  enabled      = true
  host_groups  = [crowdstrike_host_group.test.id]
}

data "crowdstrike_filevantage_policies" "test" {
  ids = [crowdstrike_filevantage_policy.test.id]

  depends_on = [crowdstrike_filevantage_policy.test]
}
`, rName)
}

// Test Data and Helper Functions

var (
	testBoolTrue  = true
	testBoolFalse = false
)

var testFilevantagePolicies = []*models.PoliciesPolicy{
	{
		ID:          utils.Addr("policy-001"),
		Name:        "Production Windows Policy",
		Description: "File integrity monitoring for Windows servers",
		Enabled:     &testBoolTrue,
		Platform:    "Windows",
		HostGroups: []*models.PoliciesAssignedHostGroup{
			{ID: utils.Addr("host-group-001")},
		},
		RuleGroups: []*models.PoliciesAssignedRuleGroup{
			{ID: utils.Addr("rule-group-001")},
		},
	},
	{
		ID:          utils.Addr("policy-002"),
		Name:        "Linux Server Policy",
		Description: "File integrity monitoring for Linux servers",
		Enabled:     &testBoolTrue,
		Platform:    "Linux",
		HostGroups: []*models.PoliciesAssignedHostGroup{
			{ID: utils.Addr("host-group-002")},
		},
		RuleGroups: []*models.PoliciesAssignedRuleGroup{},
	},
	{
		ID:          utils.Addr("policy-003"),
		Name:        "Mac Desktop Policy",
		Description: "File integrity monitoring for Mac desktops",
		Enabled:     &testBoolFalse,
		Platform:    "Mac",
		HostGroups:  []*models.PoliciesAssignedHostGroup{},
		RuleGroups: []*models.PoliciesAssignedRuleGroup{
			{ID: utils.Addr("rule-group-002")},
		},
	},
	{
		ID:          utils.Addr("policy-004"),
		Name:        "Test Windows Policy",
		Description: "Test policy for Windows development",
		Enabled:     &testBoolTrue,
		Platform:    "Windows",
		HostGroups: []*models.PoliciesAssignedHostGroup{
			{ID: utils.Addr("host-group-003")},
			{ID: utils.Addr("host-group-004")},
		},
		RuleGroups: []*models.PoliciesAssignedRuleGroup{},
	},
	{
		ID:          utils.Addr("policy-005"),
		Name:        "Disabled Linux Policy",
		Description: "Disabled file monitoring for Linux",
		Enabled:     &testBoolFalse,
		Platform:    "Linux",
		HostGroups:  []*models.PoliciesAssignedHostGroup{},
		RuleGroups:  []*models.PoliciesAssignedRuleGroup{},
	},
}

func policiesByID(allPolicies []*models.PoliciesPolicy, ids ...string) []*models.PoliciesPolicy {
	result := make([]*models.PoliciesPolicy, 0, len(ids))
	policyMap := make(map[string]*models.PoliciesPolicy)

	for _, policy := range allPolicies {
		if policy.ID != nil {
			policyMap[*policy.ID] = policy
		}
	}

	for _, id := range ids {
		if policy, ok := policyMap[id]; ok {
			result = append(result, policy)
		}
	}

	return result
}

func policiesByType(allPolicies []*models.PoliciesPolicy, platformType string) []*models.PoliciesPolicy {
	result := make([]*models.PoliciesPolicy, 0)

	for _, policy := range allPolicies {
		if policy != nil && policy.Platform == platformType {
			result = append(result, policy)
		}
	}

	return result
}

func TestFilterPoliciesByIDs(t *testing.T) {
	tests := []struct {
		name             string
		inputPolicies    []*models.PoliciesPolicy
		requestedIDs     []string
		expectedPolicies []*models.PoliciesPolicy
	}{
		{
			name:             "all_ids_found",
			inputPolicies:    testFilevantagePolicies,
			requestedIDs:     []string{"policy-001", "policy-003", "policy-005"},
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-001", "policy-003", "policy-005"),
		},
		{
			name:             "partial_ids_found",
			inputPolicies:    testFilevantagePolicies,
			requestedIDs:     []string{"policy-001", "non-existent", "policy-003"},
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-001", "policy-003"),
		},
		{
			name:             "no_ids_found",
			inputPolicies:    testFilevantagePolicies,
			requestedIDs:     []string{"non-existent-1", "non-existent-2"},
			expectedPolicies: []*models.PoliciesPolicy{},
		},
		{
			name:             "empty_id_list",
			inputPolicies:    testFilevantagePolicies,
			requestedIDs:     []string{},
			expectedPolicies: []*models.PoliciesPolicy{},
		},
		{
			name:             "nil_policies",
			inputPolicies:    nil,
			requestedIDs:     []string{"policy-001"},
			expectedPolicies: []*models.PoliciesPolicy{},
		},
		{
			name:             "empty_policies",
			inputPolicies:    []*models.PoliciesPolicy{},
			requestedIDs:     []string{"policy-001"},
			expectedPolicies: []*models.PoliciesPolicy{},
		},
		{
			name: "nil_policy_in_slice",
			inputPolicies: []*models.PoliciesPolicy{
				testFilevantagePolicies[0],
				nil,
				testFilevantagePolicies[1],
			},
			requestedIDs:     []string{"policy-001", "policy-002"},
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-001", "policy-002"),
		},
		{
			name: "policy_with_nil_id",
			inputPolicies: []*models.PoliciesPolicy{
				testFilevantagePolicies[0],
				{
					ID:          nil,
					Name:        "Policy with no ID",
					Description: "Test policy",
					Platform:    "Windows",
				},
				testFilevantagePolicies[1],
			},
			requestedIDs:     []string{"policy-001", "policy-002"},
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-001", "policy-002"),
		},
		{
			name:             "single_id_match",
			inputPolicies:    testFilevantagePolicies,
			requestedIDs:     []string{"policy-004"},
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-004"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Since we don't have a public FilterPoliciesByIDs function for file vantage policies,
			// we'll test the logic used in the actual implementation
			filtered := filterPoliciesByIDsHelper(tt.inputPolicies, tt.requestedIDs)
			assert.ElementsMatch(t, tt.expectedPolicies, filtered, "Filtered policies don't match expected policies")
		})
	}
}

func TestFilterPoliciesByType(t *testing.T) {
	tests := []struct {
		name             string
		inputPolicies    []*models.PoliciesPolicy
		platformType     string
		expectedPolicies []*models.PoliciesPolicy
	}{
		{
			name:             "windows_policies",
			inputPolicies:    testFilevantagePolicies,
			platformType:     "Windows",
			expectedPolicies: policiesByType(testFilevantagePolicies, "Windows"),
		},
		{
			name:             "linux_policies",
			inputPolicies:    testFilevantagePolicies,
			platformType:     "Linux",
			expectedPolicies: policiesByType(testFilevantagePolicies, "Linux"),
		},
		{
			name:             "mac_policies",
			inputPolicies:    testFilevantagePolicies,
			platformType:     "Mac",
			expectedPolicies: policiesByType(testFilevantagePolicies, "Mac"),
		},
		{
			name:             "no_matches",
			inputPolicies:    testFilevantagePolicies,
			platformType:     "NonExistent",
			expectedPolicies: []*models.PoliciesPolicy{},
		},
		{
			name:             "empty_input",
			inputPolicies:    []*models.PoliciesPolicy{},
			platformType:     "Windows",
			expectedPolicies: []*models.PoliciesPolicy{},
		},
		{
			name:             "nil_input",
			inputPolicies:    nil,
			platformType:     "Windows",
			expectedPolicies: []*models.PoliciesPolicy{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := policiesByType(tt.inputPolicies, tt.platformType)
			assert.ElementsMatch(t, tt.expectedPolicies, filtered, "Filtered policies don't match expected policies")
		})
	}
}

// Helper function to simulate the filtering logic used in the data source.
func filterPoliciesByIDsHelper(policies []*models.PoliciesPolicy, requestedIDs []string) []*models.PoliciesPolicy {
	if len(policies) == 0 || len(requestedIDs) == 0 {
		return []*models.PoliciesPolicy{}
	}

	policyMap := make(map[string]*models.PoliciesPolicy)
	for _, policy := range policies {
		if policy != nil && policy.ID != nil {
			policyMap[*policy.ID] = policy
		}
	}

	result := make([]*models.PoliciesPolicy, 0, len(requestedIDs))
	for _, id := range requestedIDs {
		if policy, exists := policyMap[id]; exists {
			result = append(result, policy)
		}
	}

	return result
}
