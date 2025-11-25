package sensorupdatepolicy_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sensorupdatepolicy "github.com/crowdstrike/terraform-provider-crowdstrike/internal/sensor_update_policy"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/types"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
)

func TestAccSensorUpdatePoliciesDataSource_Basic(t *testing.T) {
	resourceName := "data.crowdstrike_sensor_update_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccSensorUpdatePoliciesDataSourceConfigBasic(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.id"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.name"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.platform_name"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.enabled"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.created_by"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.created_timestamp"),
				),
			},
		},
	})
}

func TestAccSensorUpdatePoliciesDataSource_WithFilter(t *testing.T) {
	resourceName := "data.crowdstrike_sensor_update_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccSensorUpdatePoliciesDataSourceConfigWithFilterWindows(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
					resource.TestCheckResourceAttr(resourceName, "policies.0.platform_name", "Windows"),
				),
			},
			{
				Config: testAccSensorUpdatePoliciesDataSourceConfigWithFilterEnabled(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
					resource.TestCheckResourceAttr(resourceName, "policies.0.enabled", "true"),
				),
			},
			{
				Config: testAccSensorUpdatePoliciesDataSourceConfigWithFilterComplex(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
				),
			},
		},
	})
}

func TestAccSensorUpdatePoliciesDataSource_WithIDs(t *testing.T) {
	resourceName := "data.crowdstrike_sensor_update_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccSensorUpdatePoliciesDataSourceConfigWithIDs(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
					resource.TestMatchResourceAttr(resourceName, "policies.#", regexp.MustCompile(`^[12]$`)),
				),
			},
		},
	})
}

func TestAccSensorUpdatePoliciesDataSource_WithIndividualFilters(t *testing.T) {
	resourceName := "data.crowdstrike_sensor_update_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccSensorUpdatePoliciesDataSourceConfigWithPlatformFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
					resource.TestCheckResourceAttr(resourceName, "policies.0.platform_name", "Windows"),
				),
			},
			{
				Config: testAccSensorUpdatePoliciesDataSourceConfigWithEnabledFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
					resource.TestCheckResourceAttr(resourceName, "policies.0.enabled", "true"),
				),
			},
			{
				Config: testAccSensorUpdatePoliciesDataSourceConfigWithNameFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
				),
			},
			{
				Config: testAccSensorUpdatePoliciesDataSourceConfigWithDescriptionFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
				),
			},
			{
				Config: testAccSensorUpdatePoliciesDataSourceConfigWithCombinedFilters(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
					resource.TestCheckResourceAttr(resourceName, "policies.0.platform_name", "Windows"),
					resource.TestCheckResourceAttr(resourceName, "policies.0.enabled", "true"),
				),
			},
			{
				Config: testAccSensorUpdatePoliciesDataSourceConfigWithCreatedByFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
				),
			},
			{
				Config: testAccSensorUpdatePoliciesDataSourceConfigWithModifiedByFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
				),
			},
		},
	})
}

func TestAccSensorUpdatePoliciesDataSource_WithSorting(t *testing.T) {
	resourceName := "data.crowdstrike_sensor_update_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccSensorUpdatePoliciesDataSourceConfigWithSortingAsc(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
				),
			},
			{
				Config: testAccSensorUpdatePoliciesDataSourceConfigWithSortingDesc(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
				),
			},
			{
				Config: testAccSensorUpdatePoliciesDataSourceConfigWithSortingFiltered(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.#"),
				),
			},
		},
	})
}

func TestAccSensorUpdatePoliciesDataSource_ValidationErrors(t *testing.T) {
	testCases := map[string]struct {
		configFunc  func() string
		expectError *regexp.Regexp
	}{
		"filter_with_ids": {
			configFunc:  testAccSensorUpdatePoliciesDataSourceConfigValidationFilterIDs,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"filter_with_individual": {
			configFunc:  testAccSensorUpdatePoliciesDataSourceConfigValidationFilterIndividual,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"ids_with_individual": {
			configFunc:  testAccSensorUpdatePoliciesDataSourceConfigValidationIDsIndividual,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"all_three": {
			configFunc:  testAccSensorUpdatePoliciesDataSourceConfigValidationAllThree,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"multiple_filter_methods": {
			configFunc:  testAccSensorUpdatePoliciesDataSourceConfigValidationMultipleFilter,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"filter_with_created_by": {
			configFunc:  testAccSensorUpdatePoliciesDataSourceConfigValidationFilterCreatedBy,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"ids_with_modified_by": {
			configFunc:  testAccSensorUpdatePoliciesDataSourceConfigValidationIDsModifiedBy,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"filter_with_description": {
			configFunc:  testAccSensorUpdatePoliciesDataSourceConfigValidationFilterDescription,
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

func TestAccSensorUpdatePoliciesDataSource_EmptyResults(t *testing.T) {
	resourceName := "data.crowdstrike_sensor_update_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccSensorUpdatePoliciesDataSourceConfigEmptyResults(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "policies.#", "0"),
				),
			},
		},
	})
}

func TestAccSensorUpdatePoliciesDataSource_404Handling(t *testing.T) {
	resourceName := "data.crowdstrike_sensor_update_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccSensorUpdatePoliciesDataSourceConfig404NonExistentID(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "policies.#", "0"),
				),
			},
			{
				Config: testAccSensorUpdatePoliciesDataSourceConfig404PartialResults(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "policies.#", "1"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.id"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.name"),
				),
			},
		},
	})
}

func TestAccSensorUpdatePoliciesDataSource_AllAttributes(t *testing.T) {
	resourceName := "data.crowdstrike_sensor_update_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccSensorUpdatePoliciesDataSourceConfigBasic(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.id"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.name"),
					resource.TestCheckResourceAttrSet(resourceName, "policies.0.platform_name"),
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

func TestAccSensorUpdatePoliciesDataSource_ResourceMatch(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	dataSourceName := "data.crowdstrike_sensor_update_policies.test"
	resourceName := "crowdstrike_sensor_update_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccSensorUpdatePoliciesDataSourceConfigResourceMatch(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(resourceName, "id", dataSourceName, "policies.0.id"),
					resource.TestCheckResourceAttrPair(resourceName, "name", dataSourceName, "policies.0.name"),
					resource.TestCheckResourceAttr(dataSourceName, "policies.0.platform_name", "Windows"),
					resource.TestCheckResourceAttrPair(resourceName, "enabled", dataSourceName, "policies.0.enabled"),
					resource.TestCheckResourceAttrPair(resourceName, "description", dataSourceName, "policies.0.description"),
					resource.TestCheckResourceAttrPair(resourceName, "host_groups.0", dataSourceName, "policies.0.host_groups.0"),
				),
			},
		},
	})
}

func testAccSensorUpdatePoliciesDataSourceConfigBasic() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policies" "test" {}
`
}

func testAccSensorUpdatePoliciesDataSourceConfigWithFilterWindows() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policies" "test" {
  filter = "platform_name:'Windows'"
}
`
}

func testAccSensorUpdatePoliciesDataSourceConfigWithFilterEnabled() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policies" "test" {
  filter = "enabled:true"
}
`
}

func testAccSensorUpdatePoliciesDataSourceConfigWithFilterComplex() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policies" "test" {
  filter = "platform_name:'Windows'+enabled:true"
}
`
}

func testAccSensorUpdatePoliciesDataSourceConfigWithIDs() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policies" "all" {}

data "crowdstrike_sensor_update_policies" "test" {
  ids = [
    data.crowdstrike_sensor_update_policies.all.policies[0].id,
    length(data.crowdstrike_sensor_update_policies.all.policies) > 1 ? data.crowdstrike_sensor_update_policies.all.policies[1].id : data.crowdstrike_sensor_update_policies.all.policies[0].id
  ]
}
`
}

func testAccSensorUpdatePoliciesDataSourceConfigWithPlatformFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policies" "test" {
  platform_name = "Windows"
}
`
}

func testAccSensorUpdatePoliciesDataSourceConfigWithEnabledFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policies" "test" {
  enabled = true
}
`
}

func testAccSensorUpdatePoliciesDataSourceConfigWithNameFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policies" "test" {
  name = "*policy*"
}
`
}

func testAccSensorUpdatePoliciesDataSourceConfigWithDescriptionFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policies" "test" {
  description = "*update*"
}
`
}

func testAccSensorUpdatePoliciesDataSourceConfigWithCombinedFilters() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policies" "test" {
  platform_name = "Windows"
  enabled       = true
}
`
}

func testAccSensorUpdatePoliciesDataSourceConfigWithSortingAsc() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policies" "test" {
  sort = "name.asc"
}
`
}

func testAccSensorUpdatePoliciesDataSourceConfigWithSortingDesc() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policies" "test" {
  sort = "created_timestamp.desc"
}
`
}

func testAccSensorUpdatePoliciesDataSourceConfigWithSortingFiltered() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policies" "test" {
  filter = "platform_name:'Windows'"
  sort   = "name.asc"
}
`
}

func testAccSensorUpdatePoliciesDataSourceConfigValidationFilterIDs() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policies" "test" {
  filter = "platform_name:'Windows'"
  ids    = ["00000000000000000000000000000001", "00000000000000000000000000000002"]
}
`
}

func testAccSensorUpdatePoliciesDataSourceConfigValidationFilterIndividual() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policies" "test" {
  filter        = "platform_name:'Windows'"
  platform_name = "Linux"
}
`
}

func testAccSensorUpdatePoliciesDataSourceConfigValidationIDsIndividual() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policies" "test" {
  ids     = ["00000000000000000000000000000001"]
  enabled = true
}
`
}

func testAccSensorUpdatePoliciesDataSourceConfigValidationAllThree() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policies" "test" {
  filter        = "platform_name:'Windows'"
  ids           = ["00000000000000000000000000000001"]
  platform_name = "Linux"
}
`
}

func testAccSensorUpdatePoliciesDataSourceConfigValidationMultipleFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policies" "test" {
  filter        = "name:'test'"
  platform_name = "Windows"
  enabled       = true
  name          = "MyPolicy"
}
`
}

func testAccSensorUpdatePoliciesDataSourceConfigEmptyResults() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policies" "test" {
  filter = "name:'NonExistentPolicyThatShouldNeverExist12345'"
}
`
}

func testAccSensorUpdatePoliciesDataSourceConfig404NonExistentID() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policies" "test" {
  ids = ["00000000000000000000000000000000"]
}
`
}

func testAccSensorUpdatePoliciesDataSourceConfig404PartialResults() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policies" "all" {}

data "crowdstrike_sensor_update_policies" "test" {
  ids = [
    data.crowdstrike_sensor_update_policies.all.policies[0].id,
    "00000000000000000000000000000000"
  ]
}
`
}

func testAccSensorUpdatePoliciesDataSourceConfigResourceMatch(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name        = %[1]q
  description = "Test host group for data source acceptance test"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_sensor_update_policy" "test" {
  name          = %[1]q
  description   = "Test policy for data source acceptance test"
  enabled       = true
  platform_name = "Windows"
  build         = ""
  host_groups   = [crowdstrike_host_group.test.id]
  
  schedule = {
    enabled = false
  }
}

data "crowdstrike_sensor_update_policies" "test" {
  ids = [crowdstrike_sensor_update_policy.test.id]

  depends_on = [crowdstrike_sensor_update_policy.test]
}
`, rName)
}

func testAccSensorUpdatePoliciesDataSourceConfigWithCreatedByFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policies" "all" {}

data "crowdstrike_sensor_update_policies" "test" {
  created_by = data.crowdstrike_sensor_update_policies.all.policies[0].created_by
}
`
}

func testAccSensorUpdatePoliciesDataSourceConfigWithModifiedByFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policies" "all" {}

data "crowdstrike_sensor_update_policies" "test" {
  modified_by = data.crowdstrike_sensor_update_policies.all.policies[0].modified_by
}
`
}

func testAccSensorUpdatePoliciesDataSourceConfigValidationFilterCreatedBy() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policies" "test" {
  filter     = "platform_name:'Windows'"
  created_by = "testuser@example.com"
}
`
}

func testAccSensorUpdatePoliciesDataSourceConfigValidationIDsModifiedBy() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policies" "test" {
  ids         = ["00000000000000000000000000000001"]
  modified_by = "testuser@example.com"
}
`
}

func testAccSensorUpdatePoliciesDataSourceConfigValidationFilterDescription() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policies" "test" {
  filter      = "platform_name:'Windows'"
  description = "*sensor*"
}
`
}

var (
	testBoolTrue  = true
	testBoolFalse = false
)

var testPolicies = []*models.SensorUpdatePolicyV2{
	{
		ID:           utils.Addr("policy-001"),
		Name:         utils.Addr("Production Policy"),
		Description:  utils.Addr("sensor update management"),
		CreatedBy:    utils.Addr("admin@example.com"),
		ModifiedBy:   utils.Addr("security@example.com"),
		Enabled:      &testBoolTrue,
		PlatformName: utils.Addr("Windows"),
	},
	{
		ID:           utils.Addr("policy-002"),
		Name:         utils.Addr("Production Backup"),
		Description:  utils.Addr("sensor update enabled"),
		CreatedBy:    utils.Addr("admin@example.com"),
		ModifiedBy:   utils.Addr("admin@example.com"),
		Enabled:      &testBoolTrue,
		PlatformName: utils.Addr("Linux"),
	},
	{
		ID:           utils.Addr("policy-003"),
		Name:         utils.Addr("Production Desktop"),
		Description:  utils.Addr("endpoint updates"),
		CreatedBy:    utils.Addr("user@example.com"),
		ModifiedBy:   utils.Addr("security@example.com"),
		Enabled:      &testBoolTrue,
		PlatformName: utils.Addr("Windows"),
	},
	{
		ID:           utils.Addr("policy-004"),
		Name:         utils.Addr("Test Policy"),
		Description:  utils.Addr("sensor testing"),
		CreatedBy:    utils.Addr("user@example.com"),
		ModifiedBy:   utils.Addr("user@example.com"),
		Enabled:      &testBoolFalse,
		PlatformName: utils.Addr("Mac"),
	},
	{
		ID:           utils.Addr("policy-005"),
		Name:         utils.Addr("Test Environment"),
		Description:  utils.Addr("update management"),
		CreatedBy:    utils.Addr("admin@crowdstrike.com"),
		ModifiedBy:   utils.Addr("admin@crowdstrike.com"),
		Enabled:      &testBoolTrue,
		PlatformName: utils.Addr("WINDOWS"),
	},
	{
		ID:           utils.Addr("policy-006"),
		Name:         utils.Addr("Windows Policy"),
		Description:  utils.Addr("Windows updates"),
		CreatedBy:    utils.Addr("admin@example.com"),
		ModifiedBy:   utils.Addr("admin@example.com"),
		Enabled:      &testBoolTrue,
		PlatformName: utils.Addr("windows"),
	},
	{
		ID:           utils.Addr("policy-007"),
		Name:         utils.Addr("Linux Policy"),
		Description:  utils.Addr("Linux updates"),
		CreatedBy:    utils.Addr("user@example.com"),
		ModifiedBy:   utils.Addr("user@example.com"),
		Enabled:      &testBoolFalse,
		PlatformName: utils.Addr("linux"),
	},
	{
		ID:           utils.Addr("policy-008"),
		Name:         utils.Addr("PRODUCTION Server"),
		Description:  utils.Addr("Server updates"),
		CreatedBy:    utils.Addr("admin@example.com"),
		ModifiedBy:   utils.Addr("admin@example.com"),
		Enabled:      &testBoolTrue,
		PlatformName: utils.Addr("Linux"),
	},
	{
		ID:           utils.Addr("policy-009"),
		Name:         utils.Addr("production server"),
		Description:  utils.Addr("Desktop updates"),
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

func policiesByID(allPolicies []*models.SensorUpdatePolicyV2, ids ...string) []*models.SensorUpdatePolicyV2 {
	result := make([]*models.SensorUpdatePolicyV2, 0, len(ids))
	policyMap := make(map[string]*models.SensorUpdatePolicyV2)

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
		inputPolicies    []*models.SensorUpdatePolicyV2
		requestedIDs     []string
		expectedPolicies []*models.SensorUpdatePolicyV2
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
			expectedPolicies: []*models.SensorUpdatePolicyV2{},
		},
		{
			name:             "empty_id_list",
			inputPolicies:    testPolicies,
			requestedIDs:     []string{},
			expectedPolicies: []*models.SensorUpdatePolicyV2{},
		},
		{
			name:             "nil_policies",
			inputPolicies:    nil,
			requestedIDs:     []string{"policy-001"},
			expectedPolicies: []*models.SensorUpdatePolicyV2{},
		},
		{
			name:             "empty_policies",
			inputPolicies:    []*models.SensorUpdatePolicyV2{},
			requestedIDs:     []string{"policy-001"},
			expectedPolicies: []*models.SensorUpdatePolicyV2{},
		},
		{
			name: "nil_policy_in_slice",
			inputPolicies: []*models.SensorUpdatePolicyV2{
				testPolicies[0],
				nil,
				testPolicies[1],
			},
			requestedIDs:     []string{"policy-001", "policy-002"},
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002"),
		},
		{
			name: "policy_with_nil_id",
			inputPolicies: []*models.SensorUpdatePolicyV2{
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
			filtered := sensorupdatepolicy.FilterPoliciesByIDs(tt.inputPolicies, tt.requestedIDs)
			assert.ElementsMatch(t, tt.expectedPolicies, filtered, "Filtered policies don't match expected policies")
		})
	}
}

func TestFilterPoliciesByAttributes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		filters          *sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel
		inputPolicies    []*models.SensorUpdatePolicyV2
		expectedPolicies []*models.SensorUpdatePolicyV2
	}{
		{
			name: "name_no_matches",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				Name: types.StringValue("mac*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: []*models.SensorUpdatePolicyV2{},
		},
		{
			name: "name_wildcard_at_start",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				Name: types.StringValue("*Policy"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-004", "policy-006", "policy-007"),
		},
		{
			name: "name_wildcard_at_end",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				Name: types.StringValue("Test*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-004", "policy-005"),
		},
		{
			name: "name_wildcard_in_middle",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				Name: types.StringValue("Production*Desktop"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-003"),
		},
		{
			name: "name_multiple_wildcards",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				Name: types.StringValue("*Production*Serv*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-008", "policy-009"),
		},
		{
			name: "description_exact_match",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				Description: types.StringValue("sensor update management"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001"),
		},
		{
			name: "description_no_matches",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				Description: types.StringValue("nonexistent*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: []*models.SensorUpdatePolicyV2{},
		},
		{
			name: "description_wildcard_at_start",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				Description: types.StringValue("*updates"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-003", "policy-006", "policy-007", "policy-008", "policy-009"),
		},
		{
			name: "description_wildcard_at_end",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				Description: types.StringValue("sensor*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-004"),
		},
		{
			name: "description_wildcard_in_middle",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				Description: types.StringValue("sensor*management"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001"),
		},
		{
			name: "description_multiple_wildcards",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				Description: types.StringValue("*update*mana*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-005"),
		},
		{
			name: "created_by_exact_match",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				CreatedBy: types.StringValue("admin@example.com"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-006", "policy-008", "policy-009", "policy-010", "policy-011"),
		},
		{
			name: "created_by_no_matches",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				CreatedBy: types.StringValue("nonexistent@example.com"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: []*models.SensorUpdatePolicyV2{},
		},
		{
			name: "created_by_wildcard_at_start",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				CreatedBy: types.StringValue("*@example.com"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-003", "policy-004", "policy-006", "policy-007", "policy-008", "policy-009", "policy-010", "policy-011"),
		},
		{
			name: "created_by_wildcard_at_end",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				CreatedBy: types.StringValue("user@*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-003", "policy-004", "policy-007"),
		},
		{
			name: "created_by_wildcard_in_middle",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				CreatedBy: types.StringValue("admin@*example.com"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-006", "policy-008", "policy-009", "policy-010", "policy-011"),
		},
		{
			name: "created_by_multiple_wildcards",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				CreatedBy: types.StringValue("*admin*example*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-006", "policy-008", "policy-009", "policy-010", "policy-011"),
		},
		{
			name: "modified_by_exact_match",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				ModifiedBy: types.StringValue("admin@example.com"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-002", "policy-006", "policy-008", "policy-009", "policy-010", "policy-011"),
		},
		{
			name: "modified_by_no_matches",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				ModifiedBy: types.StringValue("nonexistent@example.com"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: []*models.SensorUpdatePolicyV2{},
		},
		{
			name: "modified_by_wildcard_at_start",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				ModifiedBy: types.StringValue("*@example.com"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-003", "policy-004", "policy-006", "policy-007", "policy-008", "policy-009", "policy-010", "policy-011"),
		},
		{
			name: "modified_by_wildcard_at_end",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				ModifiedBy: types.StringValue("security@*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-003"),
		},
		{
			name: "modified_by_wildcard_in_middle",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				ModifiedBy: types.StringValue("security@*example.com"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-003"),
		},
		{
			name: "modified_by_multiple_wildcards",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				ModifiedBy: types.StringValue("*admin*example*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-002", "policy-006", "policy-008", "policy-009", "policy-010", "policy-011"),
		},
		{
			name: "enabled_true",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				Enabled: types.BoolValue(true),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-003", "policy-005", "policy-006", "policy-008", "policy-010", "policy-011", "policy-012"),
		},
		{
			name: "enabled_false",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				Enabled: types.BoolValue(false),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-004", "policy-007", "policy-009"),
		},
		{
			name: "platform_name_exact_match",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				PlatformName: types.StringValue("Windows"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-003", "policy-005", "policy-006", "policy-010", "policy-012"),
		},
		{
			name: "platform_name_case_insensitive_lowercase",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				PlatformName: types.StringValue("windows"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-003", "policy-005", "policy-006", "policy-010", "policy-012"),
		},
		{
			name: "platform_name_case_insensitive_uppercase",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				PlatformName: types.StringValue("WINDOWS"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-003", "policy-005", "policy-006", "policy-010", "policy-012"),
		},
		{
			name: "platform_name_linux",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				PlatformName: types.StringValue("Linux"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-002", "policy-007", "policy-008", "policy-011"),
		},
		{
			name: "platform_name_mac",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				PlatformName: types.StringValue("Mac"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-004", "policy-009"),
		},
		{
			name: "name_and_description",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				Name:        types.StringValue("*Policy"),
				Description: types.StringValue("*updates"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-006", "policy-007"),
		},
		{
			name: "all_filters",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				Name:         types.StringValue("*Policy"),
				Description:  types.StringValue("Windows updates"),
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
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				Name:      types.StringValue("Production*"),
				CreatedBy: types.StringValue("admin@*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-008", "policy-009"),
		},
		{
			name: "description_and_user_filters",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				Description: types.StringValue("*updates"),
				CreatedBy:   types.StringValue("admin@example.com"),
				ModifiedBy:  types.StringValue("admin@example.com"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-006", "policy-008", "policy-009"),
		},
		{
			name: "enabled_and_platform",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				Enabled:      types.BoolValue(true),
				PlatformName: types.StringValue("Linux"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-002", "policy-008", "policy-011"),
		},
		{
			name: "no_filtering",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
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
			filters:          &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{},
			inputPolicies:    []*models.SensorUpdatePolicyV2{},
			expectedPolicies: []*models.SensorUpdatePolicyV2{},
		},
		{
			name:             "nil_input",
			filters:          &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{},
			inputPolicies:    nil,
			expectedPolicies: []*models.SensorUpdatePolicyV2{},
		},
		{
			name: "nil_policy_in_slice",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				Name: types.StringValue("*Policy"),
			},
			inputPolicies: []*models.SensorUpdatePolicyV2{
				testPolicies[0],
				nil,
				testPolicies[3],
			},
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-004"),
		},
		{
			name: "filter_nil_name_field",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				Name: types.StringValue("*Policy"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-004", "policy-006", "policy-007"),
		},
		{
			name: "filter_nil_description_field",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				Description: types.StringValue("*updates"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-003", "policy-006", "policy-007", "policy-008", "policy-009"),
		},
		{
			name: "filter_nil_created_by_field",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				CreatedBy: types.StringValue("admin@*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-005", "policy-006", "policy-008", "policy-009", "policy-010", "policy-011"),
		},
		{
			name: "filter_nil_modified_by_field",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				ModifiedBy: types.StringValue("security@*"),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-003"),
		},
		{
			name: "filter_nil_enabled_field",
			filters: &sensorupdatepolicy.SensorUpdatePoliciesDataSourceModel{
				Enabled: types.BoolValue(true),
			},
			inputPolicies:    testPolicies,
			expectedPolicies: policiesByID(testPolicies, "policy-001", "policy-002", "policy-003", "policy-005", "policy-006", "policy-008", "policy-010", "policy-011", "policy-012"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := sensorupdatepolicy.FilterPoliciesByAttributes(tt.inputPolicies, tt.filters)
			assert.ElementsMatch(t, tt.expectedPolicies, filtered, "Filtered policies don't match expected policies")
		})
	}
}
