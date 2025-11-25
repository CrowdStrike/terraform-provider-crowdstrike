package contentupdatepolicy_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	contentupdatepolicy "github.com/crowdstrike/terraform-provider-crowdstrike/internal/content_update_policy"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/types"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
)

func TestAccContentUpdatePoliciesDataSource_Basic(t *testing.T) {
	resourceName := "data.crowdstrike_content_update_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccContentUpdatePoliciesDataSourceConfigBasic(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.id"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.name"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.description"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.enabled"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.created_by"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.created_timestamp"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.modified_by"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.modified_timestamp"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.host_groups.#"),
				),
			},
		},
	})
}

func TestAccContentUpdatePoliciesDataSource_WithFilter(t *testing.T) {
	resourceName := "data.crowdstrike_content_update_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccContentUpdatePoliciesDataSourceConfigWithFilterEnabled(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
					resource.TestCheckResourceAttr(resourceName, "policies.0.enabled", "true"),
				),
			},
			{
				Config: testAccContentUpdatePoliciesDataSourceConfigWithFilterComplex(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
				),
			},
		},
	})
}

func TestAccContentUpdatePoliciesDataSource_WithIDs(t *testing.T) {
	resourceName := "data.crowdstrike_content_update_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccContentUpdatePoliciesDataSourceConfigWithIDs(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
					resource.TestMatchResourceAttr(resourceName, "policies.#", regexp.MustCompile(`^[12]$`)),
				),
			},
		},
	})
}

func TestAccContentUpdatePoliciesDataSource_IndividualFilters(t *testing.T) {
	resourceName := "data.crowdstrike_content_update_policies.test"

	testCases := map[string]struct {
		configFunc func() string
		checkFunc  resource.TestCheckFunc
	}{
		"enabled": {
			configFunc: testAccContentUpdatePoliciesDataSourceConfigWithEnabledFilter,
			checkFunc: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
				resource.TestCheckResourceAttr(resourceName, "policies.0.enabled", "true"),
			),
		},
		"name":        {configFunc: testAccContentUpdatePoliciesDataSourceConfigWithNameFilter},
		"description": {configFunc: testAccContentUpdatePoliciesDataSourceConfigWithDescriptionFilter},
		"created_by":  {configFunc: testAccContentUpdatePoliciesDataSourceConfigWithCreatedByFilter},
		"modified_by": {configFunc: testAccContentUpdatePoliciesDataSourceConfigWithModifiedByFilter},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			checkFunc := tc.checkFunc
			if checkFunc == nil {
				checkFunc = resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
				)
			}

			resource.ParallelTest(t, resource.TestCase{
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				PreCheck:                 func() { acctest.PreCheck(t) },
				Steps: []resource.TestStep{
					{
						Config: tc.configFunc(),
						Check:  checkFunc,
					},
				},
			})
		})
	}
}

func TestAccContentUpdatePoliciesDataSource_ValidationErrors(t *testing.T) {
	testCases := map[string]struct {
		configFunc  func() string
		expectError *regexp.Regexp
	}{
		"filter_with_ids": {
			configFunc:  testAccContentUpdatePoliciesDataSourceConfigValidationFilterIDs,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"filter_with_individual": {
			configFunc:  testAccContentUpdatePoliciesDataSourceConfigValidationFilterIndividual,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"ids_with_individual": {
			configFunc:  testAccContentUpdatePoliciesDataSourceConfigValidationIDsIndividual,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"all_three": {
			configFunc:  testAccContentUpdatePoliciesDataSourceConfigValidationAllThree,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"multiple_filter_methods": {
			configFunc:  testAccContentUpdatePoliciesDataSourceConfigValidationMultipleFilter,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"filter_with_created_by": {
			configFunc:  testAccContentUpdatePoliciesDataSourceConfigValidationFilterCreatedBy,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"ids_with_modified_by": {
			configFunc:  testAccContentUpdatePoliciesDataSourceConfigValidationIDsModifiedBy,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"filter_with_description": {
			configFunc:  testAccContentUpdatePoliciesDataSourceConfigValidationFilterDescription,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
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

func TestAccContentUpdatePoliciesDataSource_404Handling(t *testing.T) {
	resourceName := "data.crowdstrike_content_update_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccContentUpdatePoliciesDataSourceConfig404NonExistentID(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "policies.#", "0"),
				),
			},
			{
				Config: testAccContentUpdatePoliciesDataSourceConfig404PartialResults(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "policies.#", "1"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.id"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.name"),
				),
			},
		},
	})
}

func TestAccContentUpdatePoliciesDataSource_AllAttributes(t *testing.T) {
	resourceName := "data.crowdstrike_content_update_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccContentUpdatePoliciesDataSourceConfigBasic(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.id"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.name"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.enabled"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.created_by"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.created_timestamp"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.modified_by"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.modified_timestamp"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.host_groups.#"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.sensor_operations.ring_assignment"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.system_critical.ring_assignment"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.vulnerability_management.ring_assignment"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.rapid_response.ring_assignment"),
				),
			},
		},
	})
}

func TestAccContentUpdatePoliciesDataSource_ResourceMatch(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	dataSourceName := "data.crowdstrike_content_update_policies.test"
	resourceName := "crowdstrike_content_update_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccContentUpdatePoliciesDataSourceConfigResourceMatch(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(resourceName, "id", dataSourceName, "policies.0.id"),
					resource.TestCheckResourceAttrPair(resourceName, "name", dataSourceName, "policies.0.name"),
					resource.TestCheckResourceAttrPair(resourceName, "enabled", dataSourceName, "policies.0.enabled"),
					resource.TestCheckResourceAttrPair(resourceName, "description", dataSourceName, "policies.0.description"),
					resource.TestCheckResourceAttrPair(resourceName, "host_groups.0", dataSourceName, "policies.0.host_groups.0"),
					resource.TestCheckResourceAttrPair(resourceName, "sensor_operations.ring_assignment", dataSourceName, "policies.0.sensor_operations.ring_assignment"),
					resource.TestCheckResourceAttrPair(resourceName, "sensor_operations.delay_hours", dataSourceName, "policies.0.sensor_operations.delay_hours"),
					resource.TestCheckResourceAttrPair(resourceName, "sensor_operations.pinned_content_version", dataSourceName, "policies.0.sensor_operations.pinned_content_version"),
					resource.TestCheckResourceAttrPair(resourceName, "system_critical.ring_assignment", dataSourceName, "policies.0.system_critical.ring_assignment"),
					resource.TestCheckResourceAttrPair(resourceName, "system_critical.delay_hours", dataSourceName, "policies.0.system_critical.delay_hours"),
					resource.TestCheckResourceAttrPair(resourceName, "vulnerability_management.ring_assignment", dataSourceName, "policies.0.vulnerability_management.ring_assignment"),
					resource.TestCheckResourceAttrPair(resourceName, "vulnerability_management.pinned_content_version", dataSourceName, "policies.0.vulnerability_management.pinned_content_version"),
					resource.TestCheckResourceAttrPair(resourceName, "rapid_response.ring_assignment", dataSourceName, "policies.0.rapid_response.ring_assignment"),
					resource.TestCheckResourceAttrPair(resourceName, "rapid_response.pinned_content_version", dataSourceName, "policies.0.rapid_response.pinned_content_version"),
				),
			},
		},
	})
}

func testAccContentUpdatePoliciesDataSourceConfigBasic() string {
	return acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "test" {}
`
}

func testAccContentUpdatePoliciesDataSourceConfigWithFilterEnabled() string {
	return acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "test" {
  filter = "enabled:true"
}
`
}

func testAccContentUpdatePoliciesDataSourceConfigWithFilterComplex() string {
	return acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "test" {
  filter = "name:'test'+enabled:true"
}
`
}

func testAccContentUpdatePoliciesDataSourceConfigWithIDs() string {
	return acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "all" {}

data "crowdstrike_content_update_policies" "test" {
  ids = [
    data.crowdstrike_content_update_policies.all.policies[0].id,
    length(data.crowdstrike_content_update_policies.all.policies) > 1 ? data.crowdstrike_content_update_policies.all.policies[1].id : data.crowdstrike_content_update_policies.all.policies[0].id
  ]
}
`
}

func testAccContentUpdatePoliciesDataSourceConfigWithEnabledFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "test" {
  enabled = true
}
`
}

func testAccContentUpdatePoliciesDataSourceConfigWithNameFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "test" {
  name = "*policy*"
}
`
}

func testAccContentUpdatePoliciesDataSourceConfigWithDescriptionFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "test" {
  description = "*protection*"
}
`
}

func testAccContentUpdatePoliciesDataSourceConfigValidationFilterIDs() string {
	return acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "test" {
  ids    = ["00000000000000000000000000000001", "00000000000000000000000000000002"]
  description = "*protection*"
}
`
}

func testAccContentUpdatePoliciesDataSourceConfigValidationFilterIndividual() string {
	return acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "test" {
  filter = "description:'test'"
  name   = "test"
}
`
}

func testAccContentUpdatePoliciesDataSourceConfigValidationIDsIndividual() string {
	return acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "test" {
  ids     = ["00000000000000000000000000000001"]
  enabled = true
}
`
}

func testAccContentUpdatePoliciesDataSourceConfigValidationAllThree() string {
	return acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "test" {
  ids    = ["00000000000000000000000000000001"]
  name   = "test"
}
`
}

func testAccContentUpdatePoliciesDataSourceConfigValidationMultipleFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "test" {
  filter  = "name:'test'"
  enabled = true
  name    = "MyPolicy"
}
`
}

func testAccContentUpdatePoliciesDataSourceConfig404NonExistentID() string {
	return acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "test" {
  ids = ["00000000000000000000000000000000"]
}
`
}

func testAccContentUpdatePoliciesDataSourceConfig404PartialResults() string {
	return acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "all" {}

data "crowdstrike_content_update_policies" "test" {
  ids = [
    data.crowdstrike_content_update_policies.all.policies[0].id,
    "00000000000000000000000000000000"
  ]
}
`
}

func testAccContentUpdatePoliciesDataSourceConfigResourceMatch(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
# Fetch available content category versions
data "crowdstrike_content_category_versions" "available" {}

resource "crowdstrike_host_group" "test" {
  name        = %[1]q
  description = "Test host group for data source acceptance test"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_content_update_policy" "test" {
  name            = %[1]q
  description     = "Test policy for data source acceptance test with ring settings"
  enabled         = true
  host_groups     = [crowdstrike_host_group.test.id]

  sensor_operations = {
    ring_assignment        = "ga"
    delay_hours            = 24
    pinned_content_version = length(data.crowdstrike_content_category_versions.available.sensor_operations) > 0 ? data.crowdstrike_content_category_versions.available.sensor_operations[0] : null
  }

  system_critical = {
    ring_assignment = "ga"
    delay_hours     = 48
  }

  vulnerability_management = {
    ring_assignment        = "ga"
    pinned_content_version = length(data.crowdstrike_content_category_versions.available.vulnerability_management) > 0 ? data.crowdstrike_content_category_versions.available.vulnerability_management[0] : null
  }

  rapid_response = {
    ring_assignment        = "ea"
    pinned_content_version = length(data.crowdstrike_content_category_versions.available.rapid_response) > 0 ? data.crowdstrike_content_category_versions.available.rapid_response[0] : null
  }
}

data "crowdstrike_content_update_policies" "test" {
  ids = [crowdstrike_content_update_policy.test.id]

  depends_on = [crowdstrike_content_update_policy.test]
}
`, rName)
}

func testAccContentUpdatePoliciesDataSourceConfigWithCreatedByFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "all" {}

data "crowdstrike_content_update_policies" "test" {
  created_by = data.crowdstrike_content_update_policies.all.policies[0].created_by
}
`
}

func testAccContentUpdatePoliciesDataSourceConfigWithModifiedByFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "all" {}

data "crowdstrike_content_update_policies" "test" {
  modified_by = data.crowdstrike_content_update_policies.all.policies[0].modified_by
}
`
}

func testAccContentUpdatePoliciesDataSourceConfigValidationFilterCreatedBy() string {
	return acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "test" {
  ids         = ["00000000000000000000000000000001"]
  created_by = "testuser@example.com"
}
`
}

func testAccContentUpdatePoliciesDataSourceConfigValidationIDsModifiedBy() string {
	return acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "test" {
  ids         = ["00000000000000000000000000000001"]
  modified_by = "testuser@example.com"
}
`
}

func testAccContentUpdatePoliciesDataSourceConfigValidationFilterDescription() string {
	return acctest.ProviderConfig + `
data "crowdstrike_content_update_policies" "test" {
  ids         = ["00000000000000000000000000000001"]
  description = "*malware*"
}
`
}

var (
	testBoolTrue  = true
	testBoolFalse = false
)

var testPolicies = []*models.ContentUpdatePolicyV1{
	{
		ID:          utils.Addr("policy-001"),
		Name:        utils.Addr("Production Policy"),
		Description: utils.Addr("malware protection"),
		CreatedBy:   utils.Addr("admin@example.com"),
		ModifiedBy:  utils.Addr("security@example.com"),
		Enabled:     &testBoolTrue,
	},
	{
		ID:          utils.Addr("policy-002"),
		Name:        utils.Addr("Production Backup"),
		Description: utils.Addr("malware protection enabled"),
		CreatedBy:   utils.Addr("admin@example.com"),
		ModifiedBy:  utils.Addr("admin@example.com"),
		Enabled:     &testBoolTrue,
	},
	{
		ID:          utils.Addr("policy-003"),
		Name:        utils.Addr("Production Desktop"),
		Description: utils.Addr("endpoint protection"),
		CreatedBy:   utils.Addr("user@example.com"),
		ModifiedBy:  utils.Addr("security@example.com"),
		Enabled:     &testBoolTrue,
	},
	{
		ID:          utils.Addr("policy-004"),
		Name:        utils.Addr("Test Policy"),
		Description: utils.Addr("malware detection"),
		CreatedBy:   utils.Addr("user@example.com"),
		ModifiedBy:  utils.Addr("user@example.com"),
		Enabled:     &testBoolFalse,
	},
	{
		ID:          utils.Addr("policy-005"),
		Name:        utils.Addr("Test Environment"),
		Description: utils.Addr("ransomware protection"),
		CreatedBy:   utils.Addr("admin@crowdstrike.com"),
		ModifiedBy:  utils.Addr("admin@crowdstrike.com"),
		Enabled:     &testBoolTrue,
	},
	{
		ID:          utils.Addr("policy-006"),
		Name:        utils.Addr("Windows Policy"),
		Description: utils.Addr("Windows protection"),
		CreatedBy:   utils.Addr("admin@example.com"),
		ModifiedBy:  utils.Addr("admin@example.com"),
		Enabled:     &testBoolTrue,
	},
	{
		ID:          utils.Addr("policy-007"),
		Name:        utils.Addr("Linux Policy"),
		Description: utils.Addr("Linux protection"),
		CreatedBy:   utils.Addr("user@example.com"),
		ModifiedBy:  utils.Addr("user@example.com"),
		Enabled:     &testBoolFalse,
	},
	{
		ID:          utils.Addr("policy-008"),
		Name:        utils.Addr("PRODUCTION Server"),
		Description: utils.Addr("Server protection"),
		CreatedBy:   utils.Addr("admin@example.com"),
		ModifiedBy:  utils.Addr("admin@example.com"),
		Enabled:     &testBoolTrue,
	},
	{
		ID:          utils.Addr("policy-009"),
		Name:        utils.Addr("production server"),
		Description: utils.Addr("Desktop protection"),
		CreatedBy:   utils.Addr("admin@example.com"),
		ModifiedBy:  utils.Addr("admin@example.com"),
		Enabled:     &testBoolFalse,
	},
	{
		ID:          utils.Addr("policy-010"),
		Name:        nil,
		Description: utils.Addr("Description with no name"),
		CreatedBy:   utils.Addr("admin@example.com"),
		ModifiedBy:  utils.Addr("admin@example.com"),
		Enabled:     &testBoolTrue,
	},
	{
		ID:          utils.Addr("policy-011"),
		Name:        utils.Addr("Policy with no description"),
		Description: nil,
		CreatedBy:   utils.Addr("admin@example.com"),
		ModifiedBy:  utils.Addr("admin@example.com"),
		Enabled:     &testBoolTrue,
	},
	{
		ID:          utils.Addr("policy-012"),
		Name:        utils.Addr("Policy with no user info"),
		Description: utils.Addr("Description C"),
		CreatedBy:   nil,
		ModifiedBy:  nil,
		Enabled:     &testBoolTrue,
	},
}

func policiesByID(allPolicies []*models.ContentUpdatePolicyV1, ids ...string) []*models.ContentUpdatePolicyV1 {
	result := make([]*models.ContentUpdatePolicyV1, 0, len(ids))
	policyMap := make(map[string]*models.ContentUpdatePolicyV1)

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

func TestFilterPoliciesByIDs(t *testing.T) {
	tests := []struct {
		name             string
		inputPolicies    []*models.ContentUpdatePolicyV1
		requestedIDs     []string
		expectedPolicies []*models.ContentUpdatePolicyV1
	}{
		{
			name:             "all_ids_found",
			inputPolicies:    testPolicies,
			requestedIDs:     []string{"policy-001", "policy-003", "policy-005"},
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-003", "policy-005"),
		},
		{
			name:             "partial_ids_found",
			inputPolicies:    testPolicies,
			requestedIDs:     []string{"policy-001", "non-existent", "policy-003"},
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-003"),
		},
		{
			name:             "no_ids_found",
			inputPolicies:    testPolicies,
			requestedIDs:     []string{"non-existent-1", "non-existent-2"},
			expectedPolicies: []*models.ContentUpdatePolicyV1{},
		},
		{
			name:             "empty_id_list",
			inputPolicies:    testPolicies,
			requestedIDs:     []string{},
			expectedPolicies: []*models.ContentUpdatePolicyV1{},
		},
		{
			name:             "nil_policies",
			inputPolicies:    nil,
			requestedIDs:     []string{"policy-001"},
			expectedPolicies: []*models.ContentUpdatePolicyV1{},
		},
		{
			name:             "empty_policies",
			inputPolicies:    []*models.ContentUpdatePolicyV1{},
			requestedIDs:     []string{"policy-001"},
			expectedPolicies: []*models.ContentUpdatePolicyV1{},
		},
		{
			name: "nil_policy_in_slice",
			inputPolicies: []*models.ContentUpdatePolicyV1{
				testPolicies[0],
				nil,
				testPolicies[1],
			},
			requestedIDs:     []string{"policy-001", "policy-002"},
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002"),
		},
		{
			name: "policy_with_nil_id",
			inputPolicies: []*models.ContentUpdatePolicyV1{
				testPolicies[0],
				{
					ID:          nil,
					Name:        utils.Addr("Policy with no ID"),
					Description: utils.Addr("Test policy"),
				},
				testPolicies[1],
			},
			requestedIDs:     []string{"policy-001", "policy-002"},
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002"),
		},
		{
			name:             "single_id_match",
			inputPolicies:    testPolicies,
			requestedIDs:     []string{"policy-006"},
			expectedPolicies: policiesByID(testPolicies, "policy-006"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := contentupdatepolicy.FilterPoliciesByIDs(tt.inputPolicies, tt.requestedIDs)
			assert.ElementsMatch(t, tt.expectedPolicies, filtered, "Filtered policies don't match expected policies")
		})
	}
}

func TestFilterPoliciesByAttributes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		filters          *contentupdatepolicy.ContentUpdatePoliciesDataSourceModel
		inputPolicies    []*models.ContentUpdatePolicyV1
		expectedPolicies []*models.ContentUpdatePolicyV1
	}{
		{
			name: "name_no_matches",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				Name: types.StringValue("mac*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: []*models.ContentUpdatePolicyV1{},
		},
		{
			name: "name_wildcard_at_start",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				Name: types.StringValue("*Policy"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-004", "policy-006", "policy-007"),
		},
		{
			name: "name_wildcard_at_end",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				Name: types.StringValue("Test*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-004", "policy-005"),
		},
		{
			name: "name_wildcard_in_middle",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				Name: types.StringValue("Production*Desktop"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-003"),
		},
		{
			name: "name_multiple_wildcards",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				Name: types.StringValue("*Production*Serv*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-008", "policy-009"),
		},
		{
			name: "description_exact_match",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				Description: types.StringValue("malware protection"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001"),
		},
		{
			name: "description_no_matches",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				Description: types.StringValue("nonexistent*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: []*models.ContentUpdatePolicyV1{},
		},
		{
			name: "description_wildcard_at_start",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				Description: types.StringValue("*protection"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-003", "policy-005", "policy-006", "policy-007", "policy-008", "policy-009"),
		},
		{
			name: "description_wildcard_at_end",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				Description: types.StringValue("malware*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-004"),
		},
		{
			name: "description_wildcard_in_middle",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				Description: types.StringValue("malware*protection"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001"),
		},
		{
			name: "description_multiple_wildcards",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				Description: types.StringValue("*ware*prote*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-005"),
		},
		{
			name: "created_by_exact_match",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				CreatedBy: types.StringValue("admin@example.com"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-006", "policy-008", "policy-009", "policy-010", "policy-011"),
		},
		{
			name: "created_by_no_matches",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				CreatedBy: types.StringValue("nonexistent@example.com"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: []*models.ContentUpdatePolicyV1{},
		},
		{
			name: "created_by_wildcard_at_start",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				CreatedBy: types.StringValue("*@example.com"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-003", "policy-004", "policy-006", "policy-007", "policy-008", "policy-009", "policy-010", "policy-011"),
		},
		{
			name: "created_by_wildcard_at_end",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				CreatedBy: types.StringValue("user@*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-003", "policy-004", "policy-007"),
		},
		{
			name: "created_by_wildcard_in_middle",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				CreatedBy: types.StringValue("admin@*example.com"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-006", "policy-008", "policy-009", "policy-010", "policy-011"),
		},
		{
			name: "created_by_multiple_wildcards",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				CreatedBy: types.StringValue("*admin*example*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-006", "policy-008", "policy-009", "policy-010", "policy-011"),
		},
		{
			name: "modified_by_exact_match",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				ModifiedBy: types.StringValue("admin@example.com"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-002", "policy-006", "policy-008", "policy-009", "policy-010", "policy-011"),
		},
		{
			name: "modified_by_no_matches",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				ModifiedBy: types.StringValue("nonexistent@example.com"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: []*models.ContentUpdatePolicyV1{},
		},
		{
			name: "modified_by_wildcard_at_start",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				ModifiedBy: types.StringValue("*@example.com"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-003", "policy-004", "policy-006", "policy-007", "policy-008", "policy-009", "policy-010", "policy-011"),
		},
		{
			name: "modified_by_wildcard_at_end",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				ModifiedBy: types.StringValue("security@*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-003"),
		},
		{
			name: "modified_by_wildcard_in_middle",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				ModifiedBy: types.StringValue("security@*example.com"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-003"),
		},
		{
			name: "modified_by_multiple_wildcards",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				ModifiedBy: types.StringValue("*admin*example*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-002", "policy-006", "policy-008", "policy-009", "policy-010", "policy-011"),
		},
		{
			name: "enabled_true",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				Enabled: types.BoolValue(true),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-003", "policy-005", "policy-006", "policy-008", "policy-010", "policy-011", "policy-012"),
		},
		{
			name: "enabled_false",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				Enabled: types.BoolValue(false),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-004", "policy-007", "policy-009"),
		},
		{
			name: "name_and_description",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				Name:        types.StringValue("*Policy"),
				Description: types.StringValue("*protection"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-006", "policy-007"),
		},
		{
			name: "all_filters",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				Name:        types.StringValue("*Policy"),
				Description: types.StringValue("Windows protection"),
				CreatedBy:   types.StringValue("admin@example.com"),
				ModifiedBy:  types.StringValue("admin@example.com"),
				Enabled:     types.BoolValue(true),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-006"),
		},
		{
			name: "name_and_created_by",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				Name:      types.StringValue("Production*"),
				CreatedBy: types.StringValue("admin@*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-008", "policy-009"),
		},
		{
			name: "description_and_user_filters",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				Description: types.StringValue("*protection"),
				CreatedBy:   types.StringValue("admin@example.com"),
				ModifiedBy:  types.StringValue("admin@example.com"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-006", "policy-008", "policy-009"),
		},
		{
			name: "no_filtering",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				Name:        types.StringNull(),
				Description: types.StringNull(),
				CreatedBy:   types.StringNull(),
				ModifiedBy:  types.StringNull(),
				Enabled:     types.BoolNull(),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: testPolicies,
		},
		{
			name:             "empty_input",
			filters:          &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{},
			inputPolicies:    []*models.ContentUpdatePolicyV1{},
			expectedPolicies: []*models.ContentUpdatePolicyV1{},
		},
		{
			name:             "nil_input",
			filters:          &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{},
			inputPolicies:    nil,
			expectedPolicies: []*models.ContentUpdatePolicyV1{},
		},
		{
			name: "nil_policy_in_slice",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				Name: types.StringValue("*Policy"),
			},
			inputPolicies: []*models.ContentUpdatePolicyV1{
				testPolicies[0],
				nil,
				testPolicies[3],
			},
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-004"),
		},
		{
			name: "filter_nil_name_field",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				Name: types.StringValue("*Policy"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-004", "policy-006", "policy-007"),
		},
		{
			name: "filter_nil_description_field",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				Description: types.StringValue("*protection"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-003", "policy-005", "policy-006", "policy-007", "policy-008", "policy-009"),
		},
		{
			name: "filter_nil_created_by_field",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				CreatedBy: types.StringValue("admin@*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-005", "policy-006", "policy-008", "policy-009", "policy-010", "policy-011"),
		},
		{
			name: "filter_nil_modified_by_field",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				ModifiedBy: types.StringValue("security@*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-003"),
		},
		{
			name: "filter_nil_enabled_field",
			filters: &contentupdatepolicy.ContentUpdatePoliciesDataSourceModel{
				Enabled: types.BoolValue(true),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-003", "policy-005", "policy-006", "policy-008", "policy-010", "policy-011", "policy-012"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := contentupdatepolicy.FilterPoliciesByAttributes(tt.inputPolicies, tt.filters)
			assert.ElementsMatch(t, tt.expectedPolicies, filtered, "Filtered policies don't match expected policies")
		})
	}
}
