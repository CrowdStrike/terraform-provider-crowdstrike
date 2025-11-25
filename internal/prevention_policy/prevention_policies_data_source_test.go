package preventionpolicy_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	preventionpolicy "github.com/crowdstrike/terraform-provider-crowdstrike/internal/prevention_policy"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/types"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
)

func TestAccPreventionPoliciesDataSource_Basic(t *testing.T) {
	dataSourceName := "data.crowdstrike_prevention_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccPreventionPoliciesDataSourceConfigBasic(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.#"),
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.0.id"),
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.0.name"),
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.0.platform_name"),
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.0.enabled"),
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.0.created_by"),
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.0.created_timestamp"),
				),
			},
		},
	})
}

func TestAccPreventionPoliciesDataSource_WithFilter(t *testing.T) {
	dataSourceName := "data.crowdstrike_prevention_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccPreventionPoliciesDataSourceConfigWithFilterWindows(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.#"),
					resource.TestCheckResourceAttr(dataSourceName, "policies.0.platform_name", "Windows"),
				),
			},
			{
				Config: testAccPreventionPoliciesDataSourceConfigWithFilterEnabled(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.#"),
					resource.TestCheckResourceAttr(dataSourceName, "policies.0.enabled", "true"),
				),
			},
			{
				Config: testAccPreventionPoliciesDataSourceConfigWithFilterComplex(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.#"),
				),
			},
		},
	})
}

func TestAccPreventionPoliciesDataSource_WithIDs(t *testing.T) {
	allDataSourceName := "data.crowdstrike_prevention_policies.all"
	dataSourceName := "data.crowdstrike_prevention_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccPreventionPoliciesDataSourceConfigWithIDs(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.#"),
					resource.TestCheckResourceAttrPair(allDataSourceName, "policies.0.id", dataSourceName, "policies.0.id"),
					resource.TestCheckResourceAttrPair(allDataSourceName, "policies.0.name", dataSourceName, "policies.0.name"),
					resource.TestCheckResourceAttrPair(allDataSourceName, "policies.0.platform_name", dataSourceName, "policies.0.platform_name"),
					resource.TestCheckResourceAttrPair(allDataSourceName, "policies.0.enabled", dataSourceName, "policies.0.enabled"),
					resource.TestCheckResourceAttrPair(allDataSourceName, "policies.0.description", dataSourceName, "policies.0.description"),
				),
			},
		},
	})
}

func TestAccPreventionPoliciesDataSource_WithIndividualFilters(t *testing.T) {
	dataSourceName := "data.crowdstrike_prevention_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccPreventionPoliciesDataSourceConfigWithPlatformFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.#"),
					resource.TestCheckResourceAttr(dataSourceName, "policies.0.platform_name", "Windows"),
				),
			},
			{
				Config: testAccPreventionPoliciesDataSourceConfigWithEnabledFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.#"),
					resource.TestCheckResourceAttr(dataSourceName, "policies.0.enabled", "true"),
				),
			},
			{
				Config: testAccPreventionPoliciesDataSourceConfigWithNameFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.#"),
				),
			},
			{
				Config: testAccPreventionPoliciesDataSourceConfigWithDescriptionFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.#"),
				),
			},
			{
				Config: testAccPreventionPoliciesDataSourceConfigWithCombinedFilters(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.#"),
					resource.TestCheckResourceAttr(dataSourceName, "policies.0.platform_name", "Windows"),
					resource.TestCheckResourceAttr(dataSourceName, "policies.0.enabled", "true"),
				),
			},
			{
				Config: testAccPreventionPoliciesDataSourceConfigWithCreatedByFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.#"),
				),
			},
			{
				Config: testAccPreventionPoliciesDataSourceConfigWithModifiedByFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.#"),
				),
			},
		},
	})
}

func TestAccPreventionPoliciesDataSource_WithSorting(t *testing.T) {
	dataSourceName := "data.crowdstrike_prevention_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccPreventionPoliciesDataSourceConfigWithSortingAsc(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.#"),
				),
			},
			{
				Config: testAccPreventionPoliciesDataSourceConfigWithSortingDesc(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.#"),
				),
			},
			{
				Config: testAccPreventionPoliciesDataSourceConfigWithSortingFiltered(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.#"),
				),
			},
		},
	})
}

func TestAccPreventionPoliciesDataSource_ValidationErrors(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		configFunc  func() string
		expectError *regexp.Regexp
	}{
		"filter_with_ids": {
			configFunc:  testAccPreventionPoliciesDataSourceConfigValidationFilterIDs,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"filter_with_individual": {
			configFunc:  testAccPreventionPoliciesDataSourceConfigValidationFilterIndividual,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"ids_with_individual": {
			configFunc:  testAccPreventionPoliciesDataSourceConfigValidationIDsIndividual,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"all_three": {
			configFunc:  testAccPreventionPoliciesDataSourceConfigValidationAllThree,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"multiple_filter_methods": {
			configFunc:  testAccPreventionPoliciesDataSourceConfigValidationMultipleFilter,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"filter_with_created_by": {
			configFunc:  testAccPreventionPoliciesDataSourceConfigValidationFilterCreatedBy,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"ids_with_modified_by": {
			configFunc:  testAccPreventionPoliciesDataSourceConfigValidationIDsModifiedBy,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"filter_with_description": {
			configFunc:  testAccPreventionPoliciesDataSourceConfigValidationFilterDescription,
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

func TestAccPreventionPoliciesDataSource_EmptyResults(t *testing.T) {
	dataSourceName := "data.crowdstrike_prevention_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccPreventionPoliciesDataSourceConfigEmptyResults(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, "policies.#", "0"),
				),
			},
		},
	})
}

func TestAccPreventionPoliciesDataSource_404Handling(t *testing.T) {
	dataSourceName := "data.crowdstrike_prevention_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccPreventionPoliciesDataSourceConfig404NonExistentID(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, "policies.#", "0"),
				),
			},
			{
				Config: testAccPreventionPoliciesDataSourceConfig404PartialResults(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, "policies.#", "1"),
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.0.id"),
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.0.name"),
				),
			},
		},
	})
}

func TestAccPreventionPoliciesDataSource_AllAttributes(t *testing.T) {
	dataSourceName := "data.crowdstrike_prevention_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccPreventionPoliciesDataSourceConfigBasic(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.0.id"),
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.0.name"),
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.0.platform_name"),
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.0.enabled"),
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.0.created_by"),
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.0.created_timestamp"),
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.0.modified_by"),
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.0.modified_timestamp"),
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.0.host_groups.#"),
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.0.ioa_rule_groups.#"),
				),
			},
		},
	})
}

func TestAccPreventionPoliciesDataSource_ResourceMatch(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	dataSourceName := "data.crowdstrike_prevention_policies.test"
	resourceName := "crowdstrike_prevention_policy_windows.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccPreventionPoliciesDataSourceConfigResourceMatch(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(resourceName, "id", dataSourceName, "policies.0.id"),
					resource.TestCheckResourceAttrPair(resourceName, "name", dataSourceName, "policies.0.name"),
					resource.TestCheckResourceAttr(dataSourceName, "policies.0.platform_name", "Windows"),
					resource.TestCheckResourceAttrPair(resourceName, "enabled", dataSourceName, "policies.0.enabled"),
					resource.TestCheckResourceAttrPair(resourceName, "description", dataSourceName, "policies.0.description"),
					resource.TestCheckResourceAttrPair(resourceName, "host_groups.0", dataSourceName, "policies.0.host_groups.0"),
					resource.TestCheckResourceAttr(dataSourceName, "policies.0.ioa_rule_groups.#", "0"),
				),
			},
		},
	})
}

func testAccPreventionPoliciesDataSourceConfigBasic() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {}
`
}

func testAccPreventionPoliciesDataSourceConfigWithFilterWindows() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  filter = "platform_name:'Windows'"
}
`
}

func testAccPreventionPoliciesDataSourceConfigWithFilterEnabled() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  filter = "enabled:true"
}
`
}

func testAccPreventionPoliciesDataSourceConfigWithFilterComplex() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  filter = "platform_name:'Windows'+enabled:true"
}
`
}

func testAccPreventionPoliciesDataSourceConfigWithIDs() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "all" {}

data "crowdstrike_prevention_policies" "test" {
  ids = [
    data.crowdstrike_prevention_policies.all.policies[0].id,
    length(data.crowdstrike_prevention_policies.all.policies) > 1 ? data.crowdstrike_prevention_policies.all.policies[1].id : data.crowdstrike_prevention_policies.all.policies[0].id
  ]
}
`
}

func testAccPreventionPoliciesDataSourceConfigWithPlatformFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  platform_name = "Windows"
}
`
}

func testAccPreventionPoliciesDataSourceConfigWithEnabledFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  enabled = true
}
`
}

func testAccPreventionPoliciesDataSourceConfigWithNameFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  name = "*policy*"
}
`
}

func testAccPreventionPoliciesDataSourceConfigWithDescriptionFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  description = "*protection*"
}
`
}

func testAccPreventionPoliciesDataSourceConfigWithCombinedFilters() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  platform_name = "Windows"
  enabled       = true
}
`
}

func testAccPreventionPoliciesDataSourceConfigWithSortingAsc() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  sort = "name.asc"
}
`
}

func testAccPreventionPoliciesDataSourceConfigWithSortingDesc() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  sort = "created_timestamp.desc"
}
`
}

func testAccPreventionPoliciesDataSourceConfigWithSortingFiltered() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  filter = "platform_name:'Windows'"
  sort   = "name.asc"
}
`
}

func testAccPreventionPoliciesDataSourceConfigValidationFilterIDs() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  filter = "platform_name:'Windows'"
  ids    = ["00000000000000000000000000000001", "00000000000000000000000000000002"]
}
`
}

func testAccPreventionPoliciesDataSourceConfigValidationFilterIndividual() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  filter        = "platform_name:'Windows'"
  platform_name = "Linux"
}
`
}

func testAccPreventionPoliciesDataSourceConfigValidationIDsIndividual() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  ids     = ["00000000000000000000000000000001"]
  enabled = true
}
`
}

func testAccPreventionPoliciesDataSourceConfigValidationAllThree() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  filter        = "platform_name:'Windows'"
  ids           = ["00000000000000000000000000000001"]
  platform_name = "Linux"
}
`
}

func testAccPreventionPoliciesDataSourceConfigValidationMultipleFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  filter        = "name:'test'"
  platform_name = "Windows"
  enabled       = true
  name          = "MyPolicy"
}
`
}

func testAccPreventionPoliciesDataSourceConfigEmptyResults() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  filter = "name:'NonExistentPolicyThatShouldNeverExist12345'"
}
`
}

func testAccPreventionPoliciesDataSourceConfig404NonExistentID() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  ids = ["00000000000000000000000000000000"]
}
`
}

func testAccPreventionPoliciesDataSourceConfig404PartialResults() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "all" {}

data "crowdstrike_prevention_policies" "test" {
  ids = [
    data.crowdstrike_prevention_policies.all.policies[0].id,
    "00000000000000000000000000000000"
  ]
}
`
}

func testAccPreventionPoliciesDataSourceConfigResourceMatch(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name        = %[1]q
  description = "Test host group for data source acceptance test"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_prevention_policy_windows" "test" {
  name            = %[1]q
  description     = "Test policy for data source acceptance test"
  enabled         = true
  host_groups     = [crowdstrike_host_group.test.id]
  ioa_rule_groups = []
}

data "crowdstrike_prevention_policies" "test" {
  ids = [crowdstrike_prevention_policy_windows.test.id]

  depends_on = [crowdstrike_prevention_policy_windows.test]
}
`, rName)
}

func testAccPreventionPoliciesDataSourceConfigWithCreatedByFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "all" {}

data "crowdstrike_prevention_policies" "test" {
  created_by = data.crowdstrike_prevention_policies.all.policies[0].created_by
}
`
}

func testAccPreventionPoliciesDataSourceConfigWithModifiedByFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "all" {}

data "crowdstrike_prevention_policies" "test" {
  modified_by = data.crowdstrike_prevention_policies.all.policies[0].modified_by
}
`
}

func testAccPreventionPoliciesDataSourceConfigValidationFilterCreatedBy() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  filter     = "platform_name:'Windows'"
  created_by = "testuser@example.com"
}
`
}

func testAccPreventionPoliciesDataSourceConfigValidationIDsModifiedBy() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  ids         = ["00000000000000000000000000000001"]
  modified_by = "testuser@example.com"
}
`
}

func testAccPreventionPoliciesDataSourceConfigValidationFilterDescription() string {
	return acctest.ProviderConfig + `
data "crowdstrike_prevention_policies" "test" {
  filter      = "platform_name:'Windows'"
  description = "*malware*"
}
`
}

var (
	testBoolTrue  = true
	testBoolFalse = false
)

var testPolicies = []*models.PreventionPolicyV1{
	{
		ID:           utils.Addr("policy-001"),
		Name:         utils.Addr("Production Policy"),
		Description:  utils.Addr("malware protection"),
		CreatedBy:    utils.Addr("admin@example.com"),
		ModifiedBy:   utils.Addr("security@example.com"),
		Enabled:      &testBoolTrue,
		PlatformName: utils.Addr("Windows"),
	},
	{
		ID:           utils.Addr("policy-002"),
		Name:         utils.Addr("Production Backup"),
		Description:  utils.Addr("malware protection enabled"),
		CreatedBy:    utils.Addr("admin@example.com"),
		ModifiedBy:   utils.Addr("admin@example.com"),
		Enabled:      &testBoolTrue,
		PlatformName: utils.Addr("Linux"),
	},
	{
		ID:           utils.Addr("policy-003"),
		Name:         utils.Addr("Production Desktop"),
		Description:  utils.Addr("endpoint protection"),
		CreatedBy:    utils.Addr("user@example.com"),
		ModifiedBy:   utils.Addr("security@example.com"),
		Enabled:      &testBoolTrue,
		PlatformName: utils.Addr("Windows"),
	},
	{
		ID:           utils.Addr("policy-004"),
		Name:         utils.Addr("Test Policy"),
		Description:  utils.Addr("malware detection"),
		CreatedBy:    utils.Addr("user@example.com"),
		ModifiedBy:   utils.Addr("user@example.com"),
		Enabled:      &testBoolFalse,
		PlatformName: utils.Addr("Mac"),
	},
	{
		ID:           utils.Addr("policy-005"),
		Name:         utils.Addr("Test Environment"),
		Description:  utils.Addr("ransomware protection"),
		CreatedBy:    utils.Addr("admin@crowdstrike.com"),
		ModifiedBy:   utils.Addr("admin@crowdstrike.com"),
		Enabled:      &testBoolTrue,
		PlatformName: utils.Addr("WINDOWS"),
	},
	{
		ID:           utils.Addr("policy-006"),
		Name:         utils.Addr("Windows Policy"),
		Description:  utils.Addr("Windows protection"),
		CreatedBy:    utils.Addr("admin@example.com"),
		ModifiedBy:   utils.Addr("admin@example.com"),
		Enabled:      &testBoolTrue,
		PlatformName: utils.Addr("windows"),
	},
	{
		ID:           utils.Addr("policy-007"),
		Name:         utils.Addr("Linux Policy"),
		Description:  utils.Addr("Linux protection"),
		CreatedBy:    utils.Addr("user@example.com"),
		ModifiedBy:   utils.Addr("user@example.com"),
		Enabled:      &testBoolFalse,
		PlatformName: utils.Addr("linux"),
	},
	{
		ID:           utils.Addr("policy-008"),
		Name:         utils.Addr("PRODUCTION Server"),
		Description:  utils.Addr("Server protection"),
		CreatedBy:    utils.Addr("admin@example.com"),
		ModifiedBy:   utils.Addr("admin@example.com"),
		Enabled:      &testBoolTrue,
		PlatformName: utils.Addr("Linux"),
	},
	{
		ID:           utils.Addr("policy-009"),
		Name:         utils.Addr("production server"),
		Description:  utils.Addr("Desktop protection"),
		CreatedBy:    utils.Addr("admin@example.com"),
		ModifiedBy:   utils.Addr("admin@example.com"),
		Enabled:      &testBoolFalse,
		PlatformName: utils.Addr("Mac"),
	},
	{
		ID:           utils.Addr("policy-010"),
		Name:         nil,
		Description:  utils.Addr("Description with no name"),
		CreatedBy:    utils.Addr("admin@example.com"),
		ModifiedBy:   utils.Addr("admin@example.com"),
		Enabled:      &testBoolTrue,
		PlatformName: utils.Addr("Windows"),
	},
	{
		ID:           utils.Addr("policy-011"),
		Name:         utils.Addr("Policy with no description"),
		Description:  nil,
		CreatedBy:    utils.Addr("admin@example.com"),
		ModifiedBy:   utils.Addr("admin@example.com"),
		Enabled:      &testBoolTrue,
		PlatformName: utils.Addr("Linux"),
	},
	{
		ID:           utils.Addr("policy-012"),
		Name:         utils.Addr("Policy with no user info"),
		Description:  utils.Addr("Description C"),
		CreatedBy:    nil,
		ModifiedBy:   nil,
		Enabled:      &testBoolTrue,
		PlatformName: utils.Addr("Windows"),
	},
}

func policiesByID(allPolicies []*models.PreventionPolicyV1, ids ...string) []*models.PreventionPolicyV1 {
	result := make([]*models.PreventionPolicyV1, 0, len(ids))
	policyMap := make(map[string]*models.PreventionPolicyV1)

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
	t.Parallel()

	tests := []struct {
		name             string
		inputPolicies    []*models.PreventionPolicyV1
		requestedIDs     []string
		expectedPolicies []*models.PreventionPolicyV1
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
			expectedPolicies: []*models.PreventionPolicyV1{},
		},
		{
			name:             "empty_id_list",
			inputPolicies:    testPolicies,
			requestedIDs:     []string{},
			expectedPolicies: []*models.PreventionPolicyV1{},
		},
		{
			name:             "nil_policies",
			inputPolicies:    nil,
			requestedIDs:     []string{"policy-001"},
			expectedPolicies: []*models.PreventionPolicyV1{},
		},
		{
			name:             "empty_policies",
			inputPolicies:    []*models.PreventionPolicyV1{},
			requestedIDs:     []string{"policy-001"},
			expectedPolicies: []*models.PreventionPolicyV1{},
		},
		{
			name: "nil_policy_in_slice",
			inputPolicies: []*models.PreventionPolicyV1{
				testPolicies[0],
				nil,
				testPolicies[1],
			},
			requestedIDs:     []string{"policy-001", "policy-002"},
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002"),
		},
		{
			name: "policy_with_nil_id",
			inputPolicies: []*models.PreventionPolicyV1{
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
			filtered := preventionpolicy.FilterPoliciesByIDs(tt.inputPolicies, tt.requestedIDs)
			assert.ElementsMatch(t, tt.expectedPolicies, filtered, "Filtered policies don't match expected policies")
		})
	}
}

func TestFilterPoliciesByAttributes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		filters          *preventionpolicy.PreventionPoliciesDataSourceModel
		inputPolicies    []*models.PreventionPolicyV1
		expectedPolicies []*models.PreventionPolicyV1
	}{
		{
			name: "name_no_matches",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				Name: types.StringValue("mac*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: []*models.PreventionPolicyV1{},
		},
		{
			name: "name_wildcard_at_start",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				Name: types.StringValue("*Policy"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-004", "policy-006", "policy-007"),
		},
		{
			name: "name_wildcard_at_end",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				Name: types.StringValue("Test*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-004", "policy-005"),
		},
		{
			name: "name_wildcard_in_middle",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				Name: types.StringValue("Production*Desktop"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-003"),
		},
		{
			name: "name_multiple_wildcards",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				Name: types.StringValue("*Production*Serv*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-008", "policy-009"),
		},
		{
			name: "description_exact_match",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				Description: types.StringValue("malware protection"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001"),
		},
		{
			name: "description_no_matches",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				Description: types.StringValue("nonexistent*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: []*models.PreventionPolicyV1{},
		},
		{
			name: "description_wildcard_at_start",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				Description: types.StringValue("*protection"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-003", "policy-005", "policy-006", "policy-007", "policy-008", "policy-009"),
		},
		{
			name: "description_wildcard_at_end",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				Description: types.StringValue("malware*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-004"),
		},
		{
			name: "description_wildcard_in_middle",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				Description: types.StringValue("malware*protection"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001"),
		},
		{
			name: "description_multiple_wildcards",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				Description: types.StringValue("*ware*prote*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-005"),
		},
		{
			name: "created_by_exact_match",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				CreatedBy: types.StringValue("admin@example.com"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-006", "policy-008", "policy-009", "policy-010", "policy-011"),
		},
		{
			name: "created_by_no_matches",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				CreatedBy: types.StringValue("nonexistent@example.com"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: []*models.PreventionPolicyV1{},
		},
		{
			name: "created_by_wildcard_at_start",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				CreatedBy: types.StringValue("*@example.com"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-003", "policy-004", "policy-006", "policy-007", "policy-008", "policy-009", "policy-010", "policy-011"),
		},
		{
			name: "created_by_wildcard_at_end",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				CreatedBy: types.StringValue("user@*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-003", "policy-004", "policy-007"),
		},
		{
			name: "created_by_wildcard_in_middle",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				CreatedBy: types.StringValue("admin@*example.com"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-006", "policy-008", "policy-009", "policy-010", "policy-011"),
		},
		{
			name: "created_by_multiple_wildcards",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				CreatedBy: types.StringValue("*admin*example*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-006", "policy-008", "policy-009", "policy-010", "policy-011"),
		},
		{
			name: "modified_by_exact_match",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				ModifiedBy: types.StringValue("admin@example.com"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-002", "policy-006", "policy-008", "policy-009", "policy-010", "policy-011"),
		},
		{
			name: "modified_by_no_matches",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				ModifiedBy: types.StringValue("nonexistent@example.com"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: []*models.PreventionPolicyV1{},
		},
		{
			name: "modified_by_wildcard_at_start",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				ModifiedBy: types.StringValue("*@example.com"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-003", "policy-004", "policy-006", "policy-007", "policy-008", "policy-009", "policy-010", "policy-011"),
		},
		{
			name: "modified_by_wildcard_at_end",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				ModifiedBy: types.StringValue("security@*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-003"),
		},
		{
			name: "modified_by_wildcard_in_middle",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				ModifiedBy: types.StringValue("security@*example.com"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-003"),
		},
		{
			name: "modified_by_multiple_wildcards",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				ModifiedBy: types.StringValue("*admin*example*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-002", "policy-006", "policy-008", "policy-009", "policy-010", "policy-011"),
		},
		{
			name: "enabled_true",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				Enabled: types.BoolValue(true),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-003", "policy-005", "policy-006", "policy-008", "policy-010", "policy-011", "policy-012"),
		},
		{
			name: "enabled_false",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				Enabled: types.BoolValue(false),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-004", "policy-007", "policy-009"),
		},
		{
			name: "platform_name_exact_match",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				PlatformName: types.StringValue("Windows"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-003", "policy-005", "policy-006", "policy-010", "policy-012"),
		},
		{
			name: "platform_name_case_insensitive_lowercase",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				PlatformName: types.StringValue("windows"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-003", "policy-005", "policy-006", "policy-010", "policy-012"),
		},
		{
			name: "platform_name_case_insensitive_uppercase",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				PlatformName: types.StringValue("WINDOWS"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-003", "policy-005", "policy-006", "policy-010", "policy-012"),
		},
		{
			name: "platform_name_linux",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				PlatformName: types.StringValue("Linux"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-002", "policy-007", "policy-008", "policy-011"),
		},
		{
			name: "platform_name_mac",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				PlatformName: types.StringValue("Mac"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-004", "policy-009"),
		},
		{
			name: "name_and_description",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				Name:        types.StringValue("*Policy"),
				Description: types.StringValue("*protection"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-006", "policy-007"),
		},
		{
			name: "all_filters",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				Name:         types.StringValue("*Policy"),
				Description:  types.StringValue("Windows protection"),
				CreatedBy:    types.StringValue("admin@example.com"),
				ModifiedBy:   types.StringValue("admin@example.com"),
				Enabled:      types.BoolValue(true),
				PlatformName: types.StringValue("windows"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-006"),
		},
		{
			name: "name_and_created_by",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				Name:      types.StringValue("Production*"),
				CreatedBy: types.StringValue("admin@*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-008", "policy-009"),
		},
		{
			name: "description_and_user_filters",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				Description: types.StringValue("*protection"),
				CreatedBy:   types.StringValue("admin@example.com"),
				ModifiedBy:  types.StringValue("admin@example.com"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-006", "policy-008", "policy-009"),
		},
		{
			name: "enabled_and_platform",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				Enabled:      types.BoolValue(true),
				PlatformName: types.StringValue("Linux"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-002", "policy-008", "policy-011"),
		},
		{
			name: "no_filtering",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				Name:         types.StringNull(),
				Description:  types.StringNull(),
				CreatedBy:    types.StringNull(),
				ModifiedBy:   types.StringNull(),
				Enabled:      types.BoolNull(),
				PlatformName: types.StringNull(),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: testPolicies,
		},
		{
			name:             "empty_input",
			filters:          &preventionpolicy.PreventionPoliciesDataSourceModel{},
			inputPolicies:    []*models.PreventionPolicyV1{},
			expectedPolicies: []*models.PreventionPolicyV1{},
		},
		{
			name:             "nil_input",
			filters:          &preventionpolicy.PreventionPoliciesDataSourceModel{},
			inputPolicies:    nil,
			expectedPolicies: []*models.PreventionPolicyV1{},
		},
		{
			name: "nil_policy_in_slice",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				Name: types.StringValue("*Policy"),
			},
			inputPolicies: []*models.PreventionPolicyV1{
				testPolicies[0],
				nil,
				testPolicies[3],
			},
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-004"),
		},
		{
			name: "filter_nil_name_field",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				Name: types.StringValue("*Policy"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-004", "policy-006", "policy-007"),
		},
		{
			name: "filter_nil_description_field",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				Description: types.StringValue("*protection"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-003", "policy-005", "policy-006", "policy-007", "policy-008", "policy-009"),
		},
		{
			name: "filter_nil_created_by_field",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				CreatedBy: types.StringValue("admin@*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-005", "policy-006", "policy-008", "policy-009", "policy-010", "policy-011"),
		},
		{
			name: "filter_nil_modified_by_field",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				ModifiedBy: types.StringValue("security@*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-003"),
		},
		{
			name: "filter_nil_enabled_field",
			filters: &preventionpolicy.PreventionPoliciesDataSourceModel{
				Enabled: types.BoolValue(true),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-003", "policy-005", "policy-006", "policy-008", "policy-010", "policy-011", "policy-012"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := preventionpolicy.FilterPoliciesByAttributes(tt.inputPolicies, tt.filters)
			assert.ElementsMatch(t, tt.expectedPolicies, filtered, "Filtered policies don't match expected policies")
		})
	}
}
