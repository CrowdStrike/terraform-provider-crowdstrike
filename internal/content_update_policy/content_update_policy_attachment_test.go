package contentupdatepolicy_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccContentUpdatePolicyAttachmentResource_basic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test")
	}

	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_content_update_policy_attachment.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck: func() {
			acctest.PreCheck(t)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccContentUpdatePolicyAttachmentConfig_basic(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "exclusive", "true"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "1"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "host_groups.*", "crowdstrike_host_group.test", "id"),
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

func TestAccContentUpdatePolicyAttachmentResource_exclusiveFalse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test")
	}

	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_content_update_policy_attachment.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck: func() {
			acctest.PreCheck(t)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccContentUpdatePolicyAttachmentConfig_exclusiveFalse(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "exclusive", "false"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "1"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "host_groups.*", "crowdstrike_host_group.test", "id"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
				),
			},
			{
				Config: testAccContentUpdatePolicyAttachmentConfig_exclusiveFalseUpdate(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "exclusive", "false"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "2"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "host_groups.*", "crowdstrike_host_group.test", "id"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "host_groups.*", "crowdstrike_host_group.test2", "id"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
				),
			},
			{
				Config: testAccContentUpdatePolicyAttachmentConfig_exclusiveFalseRemoveAll(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "exclusive", "false"),
					resource.TestCheckNoResourceAttr(resourceName, "host_groups"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
				),
			},
		},
	})
}

func testAccContentUpdatePolicyAttachmentConfig_basic(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_content_update_policy" "test" {
  name        = "%s-policy"
  enabled     = true
  description = "test policy for attachment tests"
  host_groups = []

  sensor_operations = {
    ring_assignment = "ga"
  }

  system_critical = {
    ring_assignment = "ga"
  }

  vulnerability_management = {
    ring_assignment = "ga"
  }

  rapid_response = {
    ring_assignment = "ga"
  }

  lifecycle {
    ignore_changes = [host_groups]
  }
}

resource "crowdstrike_host_group" "test" {
  name        = "%s-hg"
  description = "test host group for attachment tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_content_update_policy_attachment" "test" {
  id          = crowdstrike_content_update_policy.test.id
  exclusive   = true
  host_groups = [crowdstrike_host_group.test.id]
}
`, rName, rName)
}

func testAccContentUpdatePolicyAttachmentConfig_exclusiveFalse(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "existing" {
  name        = "%[1]s-existing"
  description = "existing host group attached to policy"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_content_update_policy" "test" {
  name        = %[1]q
  enabled     = true
  description = "test policy for attachment tests"
  host_groups = [crowdstrike_host_group.existing.id]

  sensor_operations = {
    ring_assignment = "ga"
  }

  system_critical = {
    ring_assignment = "ga"
  }

  vulnerability_management = {
    ring_assignment = "ga"
  }

  rapid_response = {
    ring_assignment = "ga"
  }

  lifecycle {
    ignore_changes = [host_groups]
  }
}

resource "crowdstrike_host_group" "test" {
  name        = %[1]q
  description = "test host group for attachment tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_content_update_policy_attachment" "test" {
  id          = crowdstrike_content_update_policy.test.id
  exclusive   = false
  host_groups = [crowdstrike_host_group.test.id]
}
`, rName)
}

func testAccContentUpdatePolicyAttachmentConfig_exclusiveFalseUpdate(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "existing" {
  name        = "%[1]s-existing"
  description = "existing host group attached to policy"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_content_update_policy" "test" {
  name        = %[1]q
  enabled     = true
  description = "test policy for attachment tests"
  host_groups = [crowdstrike_host_group.existing.id]

  sensor_operations = {
    ring_assignment = "ga"
  }

  system_critical = {
    ring_assignment = "ga"
  }

  vulnerability_management = {
    ring_assignment = "ga"
  }

  rapid_response = {
    ring_assignment = "ga"
  }

  lifecycle {
    ignore_changes = [host_groups]
  }
}

resource "crowdstrike_host_group" "test" {
  name        = %[1]q
  description = "test host group for attachment tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_host_group" "test2" {
  name        = "%[1]s-hg2"
  description = "second test host group for attachment tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_content_update_policy_attachment" "test" {
  id          = crowdstrike_content_update_policy.test.id
  exclusive   = false
  host_groups = [crowdstrike_host_group.test.id, crowdstrike_host_group.test2.id]
}
`, rName)
}

func testAccContentUpdatePolicyAttachmentConfig_exclusiveFalseRemoveAll(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "existing" {
  name        = "%[1]s-existing"
  description = "existing host group attached to policy"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_content_update_policy" "test" {
  name        = %[1]q
  enabled     = true
  description = "test policy for attachment tests"
  host_groups = [crowdstrike_host_group.existing.id]

  sensor_operations = {
    ring_assignment = "ga"
  }

  system_critical = {
    ring_assignment = "ga"
  }

  vulnerability_management = {
    ring_assignment = "ga"
  }

  rapid_response = {
    ring_assignment = "ga"
  }

  lifecycle {
    ignore_changes = [host_groups]
  }
}

resource "crowdstrike_host_group" "test" {
  name        = %[1]q
  description = "test host group for attachment tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_host_group" "test2" {
  name        = "%[1]s-hg2"
  description = "second test host group for attachment tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_content_update_policy_attachment" "test" {
  id        = crowdstrike_content_update_policy.test.id
  exclusive = false
}
`, rName)
}
