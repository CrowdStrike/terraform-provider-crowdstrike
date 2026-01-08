package fim_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

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
