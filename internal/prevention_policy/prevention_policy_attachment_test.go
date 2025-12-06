package preventionpolicy_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	preventionpolicy "github.com/crowdstrike/terraform-provider-crowdstrike/internal/prevention_policy"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
)

func TestMergeSetItems(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name        string
		existingSet types.Set
		planSet     types.Set
		expected    []string
	}{
		{
			name:        "both null",
			existingSet: types.SetNull(types.StringType),
			planSet:     types.SetNull(types.StringType),
			expected:    []string{},
		},
		{
			name:        "one null",
			existingSet: types.SetNull(types.StringType),
			planSet:     acctest.StringSetOrNull("group1", "group2"),
			expected:    []string{"group1", "group2"},
		},
		{
			name:        "no overlap",
			existingSet: acctest.StringSetOrNull("group1", "group2"),
			planSet:     acctest.StringSetOrNull("group3", "group4"),
			expected:    []string{"group1", "group2", "group3", "group4"},
		},
		{
			name:        "duplicates",
			existingSet: acctest.StringSetOrNull("group1", "group1", "group2"),
			planSet:     acctest.StringSetOrNull("group2", "group2", "group3"),
			expected:    []string{"group1", "group2", "group3"},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var diags diag.Diagnostics
			result := preventionpolicy.MergeSetItems(t.Context(), tc.existingSet, tc.planSet, &diags)

			assert.False(t, diags.HasError(), "unexpected diagnostics errors: %v", diags.Errors())

			resultElements := result.Elements()
			assert.Len(t, resultElements, len(tc.expected))

			resultMap := make(map[string]bool)
			for _, elem := range resultElements {
				resultMap[elem.(types.String).ValueString()] = true
			}

			for _, expectedID := range tc.expected {
				assert.True(t, resultMap[expectedID], "expected to find %s in result", expectedID)
			}
		})
	}
}

func TestFindGroupsToRemove(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		state    types.Set
		plan     types.Set
		expected []string
	}{
		{
			name:     "state null",
			state:    types.SetNull(types.StringType),
			plan:     acctest.StringSetOrNull("group1"),
			expected: nil,
		},
		{
			name:     "plan null",
			state:    acctest.StringSetOrNull("group1", "group2"),
			plan:     types.SetNull(types.StringType),
			expected: []string{"group1", "group2"},
		},
		{
			name:     "no changes",
			state:    acctest.StringSetOrNull("group1", "group2"),
			plan:     acctest.StringSetOrNull("group1", "group2"),
			expected: nil,
		},
		{
			name:     "remove one",
			state:    acctest.StringSetOrNull("group1", "group2", "group3"),
			plan:     acctest.StringSetOrNull("group1", "group3"),
			expected: []string{"group2"},
		},
		{
			name:     "remove multiple",
			state:    acctest.StringSetOrNull("group1", "group2", "group3"),
			plan:     acctest.StringSetOrNull("group1"),
			expected: []string{"group2", "group3"},
		},
		{
			name:     "plan adds new",
			state:    acctest.StringSetOrNull("group1"),
			plan:     acctest.StringSetOrNull("group1", "group2"),
			expected: nil,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var diags diag.Diagnostics
			result := preventionpolicy.FindGroupsToRemove(t.Context(), tc.state, tc.plan, &diags)

			assert.False(t, diags.HasError(), "unexpected diagnostics errors: %v", diags.Errors())

			if tc.expected == nil {
				assert.Nil(t, result)
				return
			}

			assert.NotNil(t, result)
			assert.Len(t, result, len(tc.expected))

			resultMap := make(map[string]bool)
			for _, id := range result {
				resultMap[id.ValueString()] = true
			}

			for _, expectedID := range tc.expected {
				assert.True(t, resultMap[expectedID], "expected to find %s in result", expectedID)
			}
		})
	}
}

func TestAccPreventionPolicyAttachmentResource_basic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test")
	}

	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_prevention_policy_attachment.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck: func() {
			acctest.PreCheck(t, acctest.RequireIOARuleGroupID)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccPreventionPolicyAttachmentConfig_basic(rName, os.Getenv("IOA_RULE_GROUP_ID")),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "exclusive", "true"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "1"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "host_groups.*", "crowdstrike_host_group.test", "id"),
					resource.TestCheckResourceAttr(resourceName, "ioa_rule_groups.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "ioa_rule_groups.*", os.Getenv("IOA_RULE_GROUP_ID")),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated", "exclusive"},
			},
		},
	})
}

func TestAccPreventionPolicyAttachmentResource_exclusiveFalse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test")
	}

	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_prevention_policy_attachment.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck: func() {
			acctest.PreCheck(t, acctest.RequireIOARuleGroupID)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccPreventionPolicyAttachmentConfig_exclusiveFalse(rName, os.Getenv("IOA_RULE_GROUP_ID")),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "exclusive", "false"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "1"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "host_groups.*", "crowdstrike_host_group.test", "id"),
					resource.TestCheckResourceAttr(resourceName, "ioa_rule_groups.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "ioa_rule_groups.*", os.Getenv("IOA_RULE_GROUP_ID")),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
				),
			},
			{
				Config: testAccPreventionPolicyAttachmentConfig_exclusiveFalseUpdate(rName, os.Getenv("IOA_RULE_GROUP_ID")),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "exclusive", "false"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "2"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "host_groups.*", "crowdstrike_host_group.test", "id"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "host_groups.*", "crowdstrike_host_group.test2", "id"),
					resource.TestCheckResourceAttr(resourceName, "ioa_rule_groups.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "ioa_rule_groups.*", os.Getenv("IOA_RULE_GROUP_ID")),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
				),
			},
			{
				Config: testAccPreventionPolicyAttachmentConfig_exclusiveFalseRemoveAll(rName, os.Getenv("IOA_RULE_GROUP_ID")),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "exclusive", "false"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "ioa_rule_groups.#", "0"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
				),
			},
		},
	})
}

func testAccPreventionPolicyAttachmentConfig_basic(rName, ruleGroupID string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_prevention_policy_windows" "test" {
  name            = "%s-policy"
  enabled         = true
  description     = "test policy for attachment tests"
  host_groups     = []
  ioa_rule_groups = []

  lifecycle {
    ignore_changes = [host_groups, ioa_rule_groups]
  }
}

resource "crowdstrike_host_group" "test" {
  name        = "%s-hg"
  description = "test host group for attachment tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_prevention_policy_attachment" "test" {
  id              = crowdstrike_prevention_policy_windows.test.id
  exclusive       = true
  host_groups     = [crowdstrike_host_group.test.id]
  ioa_rule_groups = ["%s"]
}
`, rName, rName, ruleGroupID)
}

func testAccPreventionPolicyAttachmentConfig_exclusiveFalse(rName, ruleGroupID string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "existing" {
  name        = "%[1]s-existing"
  description = "existing host group attached to policy"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_prevention_policy_windows" "test" {
  name            = %[1]q
  enabled         = true
  description     = "test policy for attachment tests"
  host_groups     = [crowdstrike_host_group.existing.id]
  ioa_rule_groups = []

  lifecycle {
    ignore_changes = [host_groups, ioa_rule_groups]
  }
}

resource "crowdstrike_host_group" "test" {
  name        = %[1]q
  description = "test host group for attachment tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_prevention_policy_attachment" "test" {
  id              = crowdstrike_prevention_policy_windows.test.id
  exclusive       = false
  host_groups     = [crowdstrike_host_group.test.id]
  ioa_rule_groups = [%[2]q]
}
`, rName, ruleGroupID)
}

func testAccPreventionPolicyAttachmentConfig_exclusiveFalseUpdate(rName, ruleGroupID string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "existing" {
  name        = "%[1]s-existing"
  description = "existing host group attached to policy"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_prevention_policy_windows" "test" {
  name            = %[1]q
  enabled         = true
  description     = "test policy for attachment tests"
  host_groups     = [crowdstrike_host_group.existing.id]
  ioa_rule_groups = []

  lifecycle {
    ignore_changes = [host_groups, ioa_rule_groups]
  }
}

resource "crowdstrike_host_group" "test" {
  name        = %[1]q
  description = "test host group for attachment tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_host_group" "test2" {
  name        = "%[1]s-2"
  description = "second test host group for attachment tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_prevention_policy_attachment" "test" {
  id              = crowdstrike_prevention_policy_windows.test.id
  exclusive       = false
  host_groups     = [crowdstrike_host_group.test.id, crowdstrike_host_group.test2.id]
  ioa_rule_groups = [%[2]q]
}
`, rName, ruleGroupID)
}

func testAccPreventionPolicyAttachmentConfig_exclusiveFalseRemoveAll(rName, ruleGroupID string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "existing" {
  name        = "%[1]s-existing"
  description = "existing host group attached to policy"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_prevention_policy_windows" "test" {
  name            = %[1]q
  enabled         = true
  description     = "test policy for attachment tests"
  host_groups     = [crowdstrike_host_group.existing.id]
  ioa_rule_groups = []

  lifecycle {
    ignore_changes = [host_groups, ioa_rule_groups]
  }
}

resource "crowdstrike_host_group" "test" {
  name        = %[1]q
  description = "test host group for attachment tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_host_group" "test2" {
  name        = "%[1]s-2"
  description = "second test host group for attachment tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_prevention_policy_attachment" "test" {
  id              = crowdstrike_prevention_policy_windows.test.id
  exclusive       = false
}
`, rName, ruleGroupID)
}
