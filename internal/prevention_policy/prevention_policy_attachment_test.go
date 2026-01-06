package preventionpolicy_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

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
