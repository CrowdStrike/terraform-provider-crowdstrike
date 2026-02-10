package sensorvisibilityexclusion_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sensorvisibilityexclusion "github.com/crowdstrike/terraform-provider-crowdstrike/internal/sensor_visibility_exclusion"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/types"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
)

var testExclusions = []*models.SvExclusionsSVExclusionV1{
	{
		ID:              utils.Addr("exclusion-001"),
		Value:           utils.Addr("C:\\Program Files\\Test\\*.exe"),
		AppliedGlobally: utils.Addr(true),
		CreatedBy:       utils.Addr("admin@example.com"),
		ModifiedBy:      utils.Addr("security@example.com"),
	},
	{
		ID:              utils.Addr("exclusion-002"),
		Value:           utils.Addr("C:\\Temp\\*.dll"),
		AppliedGlobally: utils.Addr(false),
		CreatedBy:       utils.Addr("admin@example.com"),
		ModifiedBy:      utils.Addr("admin@example.com"),
	},
	{
		ID:              utils.Addr("exclusion-003"),
		Value:           utils.Addr("/opt/test/*.so"),
		AppliedGlobally: utils.Addr(true),
		CreatedBy:       utils.Addr("user@example.com"),
		ModifiedBy:      utils.Addr("security@example.com"),
	},
	{
		ID:              utils.Addr("exclusion-004"),
		Value:           utils.Addr("C:\\Windows\\System32\\test.exe"),
		AppliedGlobally: utils.Addr(false),
		CreatedBy:       utils.Addr("user@example.com"),
		ModifiedBy:      utils.Addr("user@example.com"),
	},
	{
		ID:              utils.Addr("exclusion-005"),
		Value:           utils.Addr("/usr/bin/testapp"),
		AppliedGlobally: utils.Addr(true),
		CreatedBy:       utils.Addr("admin@crowdstrike.com"),
		ModifiedBy:      utils.Addr("admin@crowdstrike.com"),
	},
}

func exclusionsByID(allExclusions []*models.SvExclusionsSVExclusionV1, ids ...string) []*models.SvExclusionsSVExclusionV1 {
	result := make([]*models.SvExclusionsSVExclusionV1, 0, len(ids))
	exclusionMap := make(map[string]*models.SvExclusionsSVExclusionV1)

	for _, exclusion := range allExclusions {
		if exclusion.ID != nil {
			exclusionMap[*exclusion.ID] = exclusion
		}
	}

	for _, id := range ids {
		if exclusion, ok := exclusionMap[id]; ok {
			result = append(result, exclusion)
		}
	}

	return result
}

func TestFilterExclusionsByAttributes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		filters            *sensorvisibilityexclusion.SensorVisibilityExclusionsDataSourceModel
		inputExclusions    []*models.SvExclusionsSVExclusionV1
		expectedExclusions []*models.SvExclusionsSVExclusionV1
	}{
		{
			name: "applied_globally_true",
			filters: &sensorvisibilityexclusion.SensorVisibilityExclusionsDataSourceModel{
				AppliedGlobally: types.BoolValue(true),
			},
			inputExclusions:    testExclusions,
			expectedExclusions: exclusionsByID(testExclusions, "exclusion-001", "exclusion-003", "exclusion-005"),
		},
		{
			name: "applied_globally_false",
			filters: &sensorvisibilityexclusion.SensorVisibilityExclusionsDataSourceModel{
				AppliedGlobally: types.BoolValue(false),
			},
			inputExclusions:    testExclusions,
			expectedExclusions: exclusionsByID(testExclusions, "exclusion-002", "exclusion-004"),
		},
		{
			name: "created_by_exact_match",
			filters: &sensorvisibilityexclusion.SensorVisibilityExclusionsDataSourceModel{
				CreatedBy: types.StringValue("admin@example.com"),
			},
			inputExclusions:    testExclusions,
			expectedExclusions: exclusionsByID(testExclusions, "exclusion-001", "exclusion-002"),
		},
		{
			name: "created_by_wildcard",
			filters: &sensorvisibilityexclusion.SensorVisibilityExclusionsDataSourceModel{
				CreatedBy: types.StringValue("admin@*"),
			},
			inputExclusions:    testExclusions,
			expectedExclusions: exclusionsByID(testExclusions, "exclusion-001", "exclusion-002", "exclusion-005"),
		},
		{
			name: "value_wildcard",
			filters: &sensorvisibilityexclusion.SensorVisibilityExclusionsDataSourceModel{
				Value: types.StringValue("*.exe"),
			},
			inputExclusions:    testExclusions,
			expectedExclusions: exclusionsByID(testExclusions, "exclusion-001", "exclusion-004"),
		},
		{
			name: "combined_filters",
			filters: &sensorvisibilityexclusion.SensorVisibilityExclusionsDataSourceModel{
				AppliedGlobally: types.BoolValue(true),
				CreatedBy:       types.StringValue("admin@*"),
			},
			inputExclusions:    testExclusions,
			expectedExclusions: exclusionsByID(testExclusions, "exclusion-001", "exclusion-005"),
		},
		{
			name: "no_matches",
			filters: &sensorvisibilityexclusion.SensorVisibilityExclusionsDataSourceModel{
				Value: types.StringValue("nonexistent*"),
			},
			inputExclusions:    testExclusions,
			expectedExclusions: []*models.SvExclusionsSVExclusionV1{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := sensorvisibilityexclusion.FilterExclusionsByAttributes(tt.inputExclusions, tt.filters)
			assert.ElementsMatch(t, tt.expectedExclusions, filtered, "Filtered exclusions don't match expected exclusions")
		})
	}
}

func TestAccSensorVisibilityExclusionsDataSource_ValidationErrors(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		configFunc  func() string
		expectError *regexp.Regexp
	}{
		"filter_with_ids": {
			configFunc:  testAccSensorVisibilityExclusionsDataSourceConfigValidationFilterIDs,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"filter_with_individual": {
			configFunc:  testAccSensorVisibilityExclusionsDataSourceConfigValidationFilterIndividual,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"ids_with_individual": {
			configFunc:  testAccSensorVisibilityExclusionsDataSourceConfigValidationIDsIndividual,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"all_three": {
			configFunc:  testAccSensorVisibilityExclusionsDataSourceConfigValidationAllThree,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"multiple_filter_methods": {
			configFunc:  testAccSensorVisibilityExclusionsDataSourceConfigValidationMultipleFilter,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"filter_with_created_by": {
			configFunc:  testAccSensorVisibilityExclusionsDataSourceConfigValidationFilterCreatedBy,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"ids_with_modified_by": {
			configFunc:  testAccSensorVisibilityExclusionsDataSourceConfigValidationIDsModifiedBy,
			expectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		"filter_with_value": {
			configFunc:  testAccSensorVisibilityExclusionsDataSourceConfigValidationFilterValue,
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

func TestAccSensorVisibilityExclusionsDataSource_404Handling(t *testing.T) {
	dataSourceName := "data.crowdstrike_sensor_visibility_exclusions.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccSensorVisibilityExclusionsDataSourceConfig404NonExistentID(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, "exclusions.#", "0"),
				),
			},
		},
	})
}

func TestAccSensorVisibilityExclusionsDataSource_ResourceMatch(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	dataSourceName := "data.crowdstrike_sensor_visibility_exclusions.test"
	resourceName := "crowdstrike_sensor_visibility_exclusion.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccSensorVisibilityExclusionsDataSourceConfigResourceMatch(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(resourceName, "id", dataSourceName, "exclusions.0.id"),
					resource.TestCheckResourceAttrPair(resourceName, "value", dataSourceName, "exclusions.0.value"),
					resource.TestCheckResourceAttrPair(resourceName, "apply_globally", dataSourceName, "exclusions.0.applied_globally"),
					resource.TestCheckResourceAttrPair(resourceName, "apply_to_descendant_processes", dataSourceName, "exclusions.0.apply_to_descendant_processes"),
					resource.TestCheckResourceAttrPair(resourceName, "host_groups.0", dataSourceName, "exclusions.0.host_groups.0"),
				),
			},
		},
	})
}

func testAccSensorVisibilityExclusionsDataSourceConfigValidationFilterIDs() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_visibility_exclusions" "test" {
  filter = "applied_globally:true"
  ids    = ["00000000000000000000000000000001", "00000000000000000000000000000002"]
}
`
}

func testAccSensorVisibilityExclusionsDataSourceConfigValidationFilterIndividual() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_visibility_exclusions" "test" {
  filter           = "applied_globally:true"
  applied_globally = false
}
`
}

func testAccSensorVisibilityExclusionsDataSourceConfigValidationIDsIndividual() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_visibility_exclusions" "test" {
  ids              = ["00000000000000000000000000000001"]
  applied_globally = true
}
`
}

func testAccSensorVisibilityExclusionsDataSourceConfigValidationAllThree() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_visibility_exclusions" "test" {
  filter           = "applied_globally:true"
  ids              = ["00000000000000000000000000000001"]
  applied_globally = false
}
`
}

func testAccSensorVisibilityExclusionsDataSourceConfigValidationMultipleFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_visibility_exclusions" "test" {
  filter           = "value:'*.exe'"
  applied_globally = true
  created_by      = "admin*"
  value           = "*.dll"
}
`
}

func testAccSensorVisibilityExclusionsDataSourceConfig404NonExistentID() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_visibility_exclusions" "test" {
  ids = ["00000000000000000000000000000000"]
}
`
}

func testAccSensorVisibilityExclusionsDataSourceConfigResourceMatch(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name        = %[1]q
  description = "Test host group for data source acceptance test"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_sensor_visibility_exclusion" "test" {
  value                         = "C:\\Program Files\\%[1]s\\*.exe"
  apply_globally                = false
  apply_to_descendant_processes = true
  host_groups                   = [crowdstrike_host_group.test.id]
}

data "crowdstrike_sensor_visibility_exclusions" "test" {
  ids = [crowdstrike_sensor_visibility_exclusion.test.id]

  depends_on = [crowdstrike_sensor_visibility_exclusion.test]
}
`, rName)
}

func testAccSensorVisibilityExclusionsDataSourceConfigValidationFilterCreatedBy() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_visibility_exclusions" "test" {
  filter     = "applied_globally:true"
  created_by = "testuser@example.com"
}
`
}

func testAccSensorVisibilityExclusionsDataSourceConfigValidationIDsModifiedBy() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_visibility_exclusions" "test" {
  ids         = ["00000000000000000000000000000001"]
  modified_by = "testuser@example.com"
}
`
}

func testAccSensorVisibilityExclusionsDataSourceConfigValidationFilterValue() string {
	return acctest.ProviderConfig + `
data "crowdstrike_sensor_visibility_exclusions" "test" {
  filter = "applied_globally:true"
  value  = "*.exe"
}
`
}
