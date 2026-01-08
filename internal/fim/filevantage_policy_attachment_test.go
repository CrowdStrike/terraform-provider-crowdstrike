package fim_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/fim"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
)

func TestMergeAttachmentSetItems(t *testing.T) {
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
			result := fim.MergeAttachmentSetItems(t.Context(), tc.existingSet, tc.planSet, &diags)

			assert.False(t, diags.HasError(), "unexpected diagnostics errors: %v", diags.Errors())

			expected := acctest.StringSetOrNull(tc.expected...)
			assert.True(t, result.Equal(expected), "expected %v, got %v", expected, result)
		})
	}
}

func TestFindAttachmentGroupsToRemove(t *testing.T) {
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
			result := fim.FindAttachmentGroupsToRemove(t.Context(), tc.state, tc.plan, &diags)

			assert.False(t, diags.HasError(), "unexpected diagnostics errors: %v", diags.Errors())

			if tc.expected == nil {
				assert.Nil(t, result)
				return
			}

			resultSet := acctest.StringSetOrNull(convertToStrings(result)...)
			expectedSet := acctest.StringSetOrNull(tc.expected...)
			assert.True(t, resultSet.Equal(expectedSet), "expected %v, got %v", expectedSet, resultSet)
		})
	}
}

func convertToStrings(items []types.String) []string {
	result := make([]string, len(items))
	for i, item := range items {
		result[i] = item.ValueString()
	}
	return result
}

func TestAccFilevantagePolicyAttachmentResource_basic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test")
	}

	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_filevantage_policy_attachment.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck: func() {
			acctest.PreCheck(t)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccFilevantagePolicyAttachmentConfig_basic(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "exclusive", "true"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "1"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "host_groups.*", "crowdstrike_host_group.test", "id"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.#", "1"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "rule_groups.*", "crowdstrike_filevantage_rule_group.test", "id"),
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

func TestAccFilevantagePolicyAttachmentResource_exclusiveFalse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test")
	}

	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_filevantage_policy_attachment.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck: func() {
			acctest.PreCheck(t)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccFilevantagePolicyAttachmentConfig_exclusiveFalse(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "exclusive", "false"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "1"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "host_groups.*", "crowdstrike_host_group.test", "id"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.#", "1"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "rule_groups.*", "crowdstrike_filevantage_rule_group.test", "id"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
				),
			},
			{
				Config: testAccFilevantagePolicyAttachmentConfig_exclusiveFalseUpdate(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "exclusive", "false"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "2"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "host_groups.*", "crowdstrike_host_group.test", "id"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "host_groups.*", "crowdstrike_host_group.test2", "id"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.#", "1"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "rule_groups.*", "crowdstrike_filevantage_rule_group.test", "id"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
				),
			},
			{
				Config: testAccFilevantagePolicyAttachmentConfig_exclusiveFalseRemoveAll(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "exclusive", "false"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "rule_groups.#", "0"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
				),
			},
		},
	})
}

func testAccFilevantagePolicyAttachmentConfig_basic(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_filevantage_policy" "test" {
  name          = "%s-policy"
  enabled       = true
  description   = "test policy for attachment tests"
  platform_name = "Windows"
  host_groups   = []
  rule_groups   = []

  lifecycle {
    ignore_changes = [host_groups, rule_groups]
  }
}

resource "crowdstrike_host_group" "test" {
  name        = "%s-hg"
  description = "test host group for attachment tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_filevantage_rule_group" "test" {
  name        = "%s-rg"
  type        = "WindowsFiles"
  description = "test rule group for attachment tests"
}

resource "crowdstrike_filevantage_policy_attachment" "test" {
  id          = crowdstrike_filevantage_policy.test.id
  exclusive   = true
  host_groups = [crowdstrike_host_group.test.id]
  rule_groups = [crowdstrike_filevantage_rule_group.test.id]
}
`, rName, rName, rName)
}

func testAccFilevantagePolicyAttachmentConfig_exclusiveFalse(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "existing" {
  name        = "%[1]s-existing"
  description = "existing host group attached to policy"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_filevantage_policy" "test" {
  name          = %[1]q
  enabled       = true
  description   = "test policy for attachment tests"
  platform_name = "Windows"
  host_groups   = [crowdstrike_host_group.existing.id]
  rule_groups   = []

  lifecycle {
    ignore_changes = [host_groups, rule_groups]
  }
}

resource "crowdstrike_host_group" "test" {
  name        = %[1]q
  description = "test host group for attachment tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_filevantage_rule_group" "test" {
  name        = "%[1]s-rg"
  type        = "WindowsFiles"
  description = "test rule group for attachment tests"
}

resource "crowdstrike_filevantage_policy_attachment" "test" {
  id          = crowdstrike_filevantage_policy.test.id
  exclusive   = false
  host_groups = [crowdstrike_host_group.test.id]
  rule_groups = [crowdstrike_filevantage_rule_group.test.id]
}
`, rName)
}

func testAccFilevantagePolicyAttachmentConfig_exclusiveFalseUpdate(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "existing" {
  name        = "%[1]s-existing"
  description = "existing host group attached to policy"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_filevantage_policy" "test" {
  name          = %[1]q
  enabled       = true
  description   = "test policy for attachment tests"
  platform_name = "Windows"
  host_groups   = [crowdstrike_host_group.existing.id]
  rule_groups   = []

  lifecycle {
    ignore_changes = [host_groups, rule_groups]
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

resource "crowdstrike_filevantage_rule_group" "test" {
  name        = "%[1]s-rg"
  type        = "WindowsFiles"
  description = "test rule group for attachment tests"
}

resource "crowdstrike_filevantage_policy_attachment" "test" {
  id          = crowdstrike_filevantage_policy.test.id
  exclusive   = false
  host_groups = [crowdstrike_host_group.test.id, crowdstrike_host_group.test2.id]
  rule_groups = [crowdstrike_filevantage_rule_group.test.id]
}
`, rName)
}

func testAccFilevantagePolicyAttachmentConfig_exclusiveFalseRemoveAll(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "existing" {
  name        = "%[1]s-existing"
  description = "existing host group attached to policy"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_filevantage_policy" "test" {
  name          = %[1]q
  enabled       = true
  description   = "test policy for attachment tests"
  platform_name = "Windows"
  host_groups   = [crowdstrike_host_group.existing.id]
  rule_groups   = []

  lifecycle {
    ignore_changes = [host_groups, rule_groups]
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

resource "crowdstrike_filevantage_rule_group" "test" {
  name        = "%[1]s-rg"
  type        = "WindowsFiles"
  description = "test rule group for attachment tests"
}

resource "crowdstrike_filevantage_policy_attachment" "test" {
  id        = crowdstrike_filevantage_policy.test.id
  exclusive = false
}
`, rName)
}
