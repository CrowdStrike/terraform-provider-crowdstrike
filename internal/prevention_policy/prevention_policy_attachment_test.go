package preventionpolicy_test

import (
	"context"
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

func TestFindGroupsToRemove(t *testing.T) {
	ctx := context.Background()

	testcases := []struct {
		name     string
		state    types.Set
		plan     types.Set
		expected []string
	}{
		{
			name:     "state is null",
			state:    types.SetNull(types.StringType),
			plan:     acctest.StringSetOrNull("group1"),
			expected: nil,
		},
		{
			name:     "plan is null - remove all from state",
			state:    acctest.StringSetOrNull("group1", "group2"),
			plan:     types.SetNull(types.StringType),
			expected: []string{"group1", "group2"},
		},
		{
			name:     "no groups to remove",
			state:    acctest.StringSetOrNull("group1", "group2"),
			plan:     acctest.StringSetOrNull("group1", "group2"),
			expected: nil,
		},
		{
			name:     "remove one group",
			state:    acctest.StringSetOrNull("group1", "group2", "group3"),
			plan:     acctest.StringSetOrNull("group1", "group3"),
			expected: []string{"group2"},
		},
		{
			name:     "remove multiple groups",
			state:    acctest.StringSetOrNull("group1", "group2", "group3"),
			plan:     acctest.StringSetOrNull("group1"),
			expected: []string{"group2", "group3"},
		},
		{
			name:     "plan has new groups - nothing to remove",
			state:    acctest.StringSetOrNull("group1"),
			plan:     acctest.StringSetOrNull("group1", "group2"),
			expected: nil,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var diags diag.Diagnostics
			result := preventionpolicy.FindGroupsToRemove(ctx, tc.state, tc.plan, &diags)

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
				ImportStateVerifyIgnore: []string{"last_updated", "exclusive", "host_groups", "ioa_rule_groups"},
			},
		},
	})
}

func TestAccPreventionPolicyAttachmentResource_exclusiveFalse(t *testing.T) {
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
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated", "exclusive", "host_groups", "ioa_rule_groups"},
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
  exclusive       = false
  host_groups     = [crowdstrike_host_group.test.id]
  ioa_rule_groups = ["%s"]
}
`, rName, rName, ruleGroupID)
}
