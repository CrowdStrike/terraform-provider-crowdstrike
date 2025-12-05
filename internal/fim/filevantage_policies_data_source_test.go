package fim_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/fim"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/types"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
)

func TestAccFilevantagePoliciesDataSource_WithIDs(t *testing.T) {
	allDataSourceName := "data.crowdstrike_filevantage_policies.all"
	dataSourceName := "data.crowdstrike_filevantage_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFilevantagePoliciesDataSourceConfigWithIDs(),
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

func TestAccFilevantagePoliciesDataSource_404Handling(t *testing.T) {
	dataSourceName := "data.crowdstrike_filevantage_policies.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFilevantagePoliciesDataSourceConfig404NonExistentID(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, "policies.#", "0"),
				),
			},
			{
				Config: testAccFilevantagePoliciesDataSourceConfig404PartialResults(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, "policies.#", "1"),
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.0.id"),
					resource.TestCheckResourceAttrSet(dataSourceName, "policies.0.name"),
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
					resource.TestCheckResourceAttrPair(resourceName, "host_groups.0", dataSourceName, "policies.0.host_groups.0"),
				),
			},
		},
	})
}

func testAccFilevantagePoliciesDataSourceConfigWithIDs() string {
	return acctest.ProviderConfig + `
data "crowdstrike_filevantage_policies" "all" {
  platform_names = ["Windows"]
}

data "crowdstrike_filevantage_policies" "test" {
  ids = [
    data.crowdstrike_filevantage_policies.all.policies[0].id,
    length(data.crowdstrike_filevantage_policies.all.policies) > 1 ? data.crowdstrike_filevantage_policies.all.policies[1].id : data.crowdstrike_filevantage_policies.all.policies[0].id
  ]
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
  platform_names = ["Windows"]
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
  name          = %[1]q
  description   = "Test policy for data source acceptance test"
  platform_name = "Windows"
  enabled       = false
  host_groups   = [crowdstrike_host_group.test.id]
}

data "crowdstrike_filevantage_policies" "test" {
  ids = [crowdstrike_filevantage_policy.test.id]

  depends_on = [crowdstrike_filevantage_policy.test]
}
`, rName)
}

var testFilevantagePolicies = []*models.PoliciesPolicy{
	{
		ID:          utils.Addr("policy-001"),
		Name:        "Production Windows Policy",
		Description: "file integrity monitoring",
		Enabled:     utils.Addr(true),
		Platform:    "Windows",
		CreatedBy:   "admin@example.com",
		ModifiedBy:  utils.Addr("admin@example.com"),
		HostGroups: []*models.PoliciesAssignedHostGroup{
			{ID: utils.Addr("host-group-001")},
		},
		RuleGroups: []*models.PoliciesAssignedRuleGroup{
			{ID: utils.Addr("rule-group-001")},
		},
	},
	{
		ID:          utils.Addr("policy-002"),
		Name:        "Production Linux Policy",
		Description: "file monitoring enabled",
		Enabled:     utils.Addr(true),
		Platform:    "Linux",
		CreatedBy:   "admin@example.com",
		ModifiedBy:  utils.Addr("admin@example.com"),
		HostGroups: []*models.PoliciesAssignedHostGroup{
			{ID: utils.Addr("host-group-002")},
		},
		RuleGroups: []*models.PoliciesAssignedRuleGroup{},
	},
	{
		ID:          utils.Addr("policy-003"),
		Name:        "Test Windows Policy",
		Description: "file testing",
		Enabled:     utils.Addr(false),
		Platform:    "Windows",
		CreatedBy:   "user@example.com",
		ModifiedBy:  utils.Addr("modifier@example.com"),
		HostGroups: []*models.PoliciesAssignedHostGroup{
			{ID: utils.Addr("host-group-003")},
		},
		RuleGroups: []*models.PoliciesAssignedRuleGroup{},
	},
	{
		ID:          utils.Addr("policy-004"),
		Name:        "Windows Monitoring Policy",
		Description: "Windows file monitoring",
		Enabled:     utils.Addr(true),
		Platform:    "Windows",
		CreatedBy:   "admin@example.com",
		ModifiedBy:  utils.Addr("admin@example.com"),
		HostGroups: []*models.PoliciesAssignedHostGroup{
			{ID: utils.Addr("host-group-004")},
		},
		RuleGroups: []*models.PoliciesAssignedRuleGroup{},
	},
	{
		ID:          utils.Addr("policy-005"),
		Name:        "Linux Monitoring Policy",
		Description: "Linux file monitoring",
		Enabled:     utils.Addr(false),
		Platform:    "Linux",
		CreatedBy:   "user@example.com",
		ModifiedBy:  utils.Addr("modifier@example.com"),
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

func TestFilterPoliciesByAttributes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		filters          *fim.FilevantagePoliciesDataSourceModel
		inputPolicies    []*models.PoliciesPolicy
		expectedPolicies []*models.PoliciesPolicy
	}{
		{
			name: "name_no_matches",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				Name: types.StringValue("NonExistent*"),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: []*models.PoliciesPolicy{},
		},
		{
			name: "name_wildcard_at_start",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				Name: types.StringValue("*Policy"),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-001", "policy-002", "policy-003", "policy-004", "policy-005"),
		},
		{
			name: "name_wildcard_at_end",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				Name: types.StringValue("Production*"),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-001", "policy-002"),
		},
		{
			name: "name_wildcard_in_middle",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				Name: types.StringValue("*Monitoring*"),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-004", "policy-005"),
		},
		{
			name: "name_multiple_wildcards",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				Name: types.StringValue("*Windows*Policy"),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-001", "policy-003", "policy-004"),
		},
		{
			name: "name_case_insensitive",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				Name: types.StringValue("production*"),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-001", "policy-002"),
		},
		{
			name: "description_exact_match",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				Description: types.StringValue("file integrity monitoring"),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-001"),
		},
		{
			name: "description_no_matches",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				Description: types.StringValue("nonexistent*"),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: []*models.PoliciesPolicy{},
		},
		{
			name: "description_wildcard_at_start",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				Description: types.StringValue("*monitoring"),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-001", "policy-004", "policy-005"),
		},
		{
			name: "description_wildcard_at_end",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				Description: types.StringValue("file*"),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-001", "policy-002", "policy-003"),
		},
		{
			name: "description_wildcard_in_middle",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				Description: types.StringValue("*integrity*"),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-001"),
		},
		{
			name: "description_multiple_wildcards",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				Description: types.StringValue("*file*monitoring"),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-001", "policy-004", "policy-005"),
		},
		{
			name: "created_by_exact_match",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				CreatedBy: types.StringValue("admin@example.com"),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-001", "policy-002", "policy-004"),
		},
		{
			name: "created_by_no_matches",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				CreatedBy: types.StringValue("nonexistent@example.com"),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: []*models.PoliciesPolicy{},
		},
		{
			name: "created_by_wildcard_at_start",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				CreatedBy: types.StringValue("*@example.com"),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: testFilevantagePolicies,
		},
		{
			name: "created_by_wildcard_at_end",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				CreatedBy: types.StringValue("user@*"),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-003", "policy-005"),
		},
		{
			name: "created_by_wildcard_in_middle",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				CreatedBy: types.StringValue("admin@*example.com"),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-001", "policy-002", "policy-004"),
		},
		{
			name: "created_by_multiple_wildcards",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				CreatedBy: types.StringValue("*admin*example*"),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-001", "policy-002", "policy-004"),
		},
		{
			name: "modified_by_exact_match",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				ModifiedBy: types.StringValue("admin@example.com"),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-001", "policy-002", "policy-004"),
		},
		{
			name: "modified_by_no_matches",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				ModifiedBy: types.StringValue("nonexistent@example.com"),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: []*models.PoliciesPolicy{},
		},
		{
			name: "modified_by_wildcard_at_start",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				ModifiedBy: types.StringValue("*@example.com"),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: testFilevantagePolicies,
		},
		{
			name: "modified_by_wildcard_at_end",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				ModifiedBy: types.StringValue("modifier@*"),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-003", "policy-005"),
		},
		{
			name: "modified_by_wildcard_in_middle",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				ModifiedBy: types.StringValue("admin@*example.com"),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-001", "policy-002", "policy-004"),
		},
		{
			name: "modified_by_multiple_wildcards",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				ModifiedBy: types.StringValue("*modifier*example*"),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-003", "policy-005"),
		},
		{
			name: "enabled_true",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				Enabled: types.BoolValue(true),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-001", "policy-002", "policy-004"),
		},
		{
			name: "enabled_false",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				Enabled: types.BoolValue(false),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-003", "policy-005"),
		},
		{
			name: "multiple_filters_name_and_enabled",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				Name:    types.StringValue("*Production*"),
				Enabled: types.BoolValue(true),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-001", "policy-002"),
		},
		{
			name: "multiple_filters_description_and_created_by",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				Description: types.StringValue("*monitoring*"),
				CreatedBy:   types.StringValue("admin@example.com"),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-001", "policy-002", "policy-004"),
		},
		{
			name: "multiple_filters_all_match",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				Name:       types.StringValue("*Windows*"),
				Enabled:    types.BoolValue(true),
				CreatedBy:  types.StringValue("admin@example.com"),
				ModifiedBy: types.StringValue("admin@example.com"),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-001", "policy-004"),
		},
		{
			name: "multiple_filters_no_match",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				Name:    types.StringValue("*Windows*"),
				Enabled: types.BoolValue(false),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-003"),
		},
		{
			name: "no_filtering",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				Name:        types.StringNull(),
				Description: types.StringNull(),
				Enabled:     types.BoolNull(),
				CreatedBy:   types.StringNull(),
				ModifiedBy:  types.StringNull(),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: testFilevantagePolicies,
		},
		{
			name:             "empty_input",
			filters:          &fim.FilevantagePoliciesDataSourceModel{},
			inputPolicies:    []*models.PoliciesPolicy{},
			expectedPolicies: []*models.PoliciesPolicy{},
		},
		{
			name:             "nil_input",
			filters:          &fim.FilevantagePoliciesDataSourceModel{},
			inputPolicies:    nil,
			expectedPolicies: []*models.PoliciesPolicy{},
		},
		{
			name: "nil_policy_in_slice",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				Enabled: types.BoolValue(true),
			},
			inputPolicies: []*models.PoliciesPolicy{
				testFilevantagePolicies[0],
				nil,
				testFilevantagePolicies[1],
			},
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-001", "policy-002"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := fim.FilterPoliciesByAttributes(tt.inputPolicies, tt.filters)
			assert.ElementsMatch(t, tt.expectedPolicies, filtered, "Filtered policies don't match expected policies")
		})
	}
}
