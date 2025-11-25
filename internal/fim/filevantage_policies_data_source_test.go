package fim_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/fim"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/attr"
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

var (
	testBoolTrue  = true
	testBoolFalse = false
)

var testFilevantagePolicies = []*models.PoliciesPolicy{
	{
		ID:          utils.Addr("policy-001"),
		Name:        "Production Windows Policy",
		Description: "file integrity monitoring",
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
		Name:        "Production Linux Policy",
		Description: "file monitoring enabled",
		Enabled:     &testBoolTrue,
		Platform:    "Linux",
		HostGroups: []*models.PoliciesAssignedHostGroup{
			{ID: utils.Addr("host-group-002")},
		},
		RuleGroups: []*models.PoliciesAssignedRuleGroup{},
	},
	{
		ID:          utils.Addr("policy-003"),
		Name:        "Production Mac Policy",
		Description: "endpoint monitoring",
		Enabled:     &testBoolTrue,
		Platform:    "Mac",
		HostGroups:  []*models.PoliciesAssignedHostGroup{},
		RuleGroups: []*models.PoliciesAssignedRuleGroup{
			{ID: utils.Addr("rule-group-002")},
		},
	},
	{
		ID:          utils.Addr("policy-004"),
		Name:        "Test Windows Policy",
		Description: "file testing",
		Enabled:     &testBoolFalse,
		Platform:    "Windows",
		HostGroups: []*models.PoliciesAssignedHostGroup{
			{ID: utils.Addr("host-group-003")},
		},
		RuleGroups: []*models.PoliciesAssignedRuleGroup{},
	},
	{
		ID:          utils.Addr("policy-005"),
		Name:        "Test Linux Environment",
		Description: "monitoring management",
		Enabled:     &testBoolTrue,
		Platform:    "Linux",
		HostGroups:  []*models.PoliciesAssignedHostGroup{},
		RuleGroups:  []*models.PoliciesAssignedRuleGroup{},
	},
	{
		ID:          utils.Addr("policy-006"),
		Name:        "Windows Monitoring Policy",
		Description: "Windows file monitoring",
		Enabled:     &testBoolTrue,
		Platform:    "Windows",
		HostGroups: []*models.PoliciesAssignedHostGroup{
			{ID: utils.Addr("host-group-004")},
		},
		RuleGroups: []*models.PoliciesAssignedRuleGroup{},
	},
	{
		ID:          utils.Addr("policy-007"),
		Name:        "Linux Monitoring Policy",
		Description: "Linux file monitoring",
		Enabled:     &testBoolFalse,
		Platform:    "Linux",
		HostGroups:  []*models.PoliciesAssignedHostGroup{},
		RuleGroups:  []*models.PoliciesAssignedRuleGroup{},
	},
	{
		ID:          utils.Addr("policy-008"),
		Name:        "PRODUCTION Server",
		Description: "Server monitoring",
		Enabled:     &testBoolTrue,
		Platform:    "Linux",
		HostGroups: []*models.PoliciesAssignedHostGroup{
			{ID: utils.Addr("host-group-005")},
		},
		RuleGroups: []*models.PoliciesAssignedRuleGroup{},
	},
	{
		ID:          utils.Addr("policy-009"),
		Name:        "production server",
		Description: "Desktop monitoring",
		Enabled:     &testBoolFalse,
		Platform:    "Mac",
		HostGroups:  []*models.PoliciesAssignedHostGroup{},
		RuleGroups:  []*models.PoliciesAssignedRuleGroup{},
	},
	{
		ID:          utils.Addr("policy-010"),
		Name:        "",
		Description: "Description with no name",
		Enabled:     &testBoolTrue,
		Platform:    "Windows",
		HostGroups:  []*models.PoliciesAssignedHostGroup{},
		RuleGroups:  []*models.PoliciesAssignedRuleGroup{},
	},
	{
		ID:          utils.Addr("policy-011"),
		Name:        "Policy with no description",
		Description: "",
		Enabled:     &testBoolTrue,
		Platform:    "Linux",
		HostGroups:  []*models.PoliciesAssignedHostGroup{},
		RuleGroups:  []*models.PoliciesAssignedRuleGroup{},
	},
	{
		ID:          utils.Addr("policy-012"),
		Name:        "Policy with no groups",
		Description: "Description C",
		Enabled:     &testBoolTrue,
		Platform:    "Windows",
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
			name: "platform_windows",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				PlatformNames: types.SetValueMust(types.StringType, []attr.Value{types.StringValue("Windows")}),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-001", "policy-004", "policy-006", "policy-010", "policy-012"),
		},
		{
			name: "platform_linux",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				PlatformNames: types.SetValueMust(types.StringType, []attr.Value{types.StringValue("Linux")}),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-002", "policy-005", "policy-007", "policy-008", "policy-011"),
		},
		{
			name: "platform_mac",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				PlatformNames: types.SetValueMust(types.StringType, []attr.Value{types.StringValue("Mac")}),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-003", "policy-009"),
		},
		{
			name: "multiple_platforms",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				PlatformNames: types.SetValueMust(types.StringType, []attr.Value{
					types.StringValue("Windows"),
					types.StringValue("Linux"),
				}),
			},
			inputPolicies:    testFilevantagePolicies,
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-001", "policy-002", "policy-004", "policy-005", "policy-006", "policy-007", "policy-008", "policy-010", "policy-011", "policy-012"),
		},
		{
			name: "no_filtering",
			filters: &fim.FilevantagePoliciesDataSourceModel{
				PlatformNames: types.SetNull(types.StringType),
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
				PlatformNames: types.SetValueMust(types.StringType, []attr.Value{types.StringValue("Windows")}),
			},
			inputPolicies: []*models.PoliciesPolicy{
				testFilevantagePolicies[0],
				nil,
				testFilevantagePolicies[3],
			},
			expectedPolicies: policiesByID(testFilevantagePolicies, "policy-001", "policy-004"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := fim.FilterPoliciesByAttributes(tt.inputPolicies, tt.filters)
			assert.ElementsMatch(t, tt.expectedPolicies, filtered, "Filtered policies don't match expected policies")
		})
	}
}
