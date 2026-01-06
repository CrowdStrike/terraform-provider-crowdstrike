package sensorupdatepolicy_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccSensorUpdatePolicyHostGroupAttachmentResource_basic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test")
	}

	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_sensor_update_policy_host_group_attachment.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck: func() {
			acctest.PreCheck(t)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccSensorUpdatePolicyHostGroupAttachmentConfig_basic(rName),
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
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
		},
	})
}

func TestAccSensorUpdatePolicyHostGroupAttachmentResource_exclusiveFalse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test")
	}

	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_sensor_update_policy_host_group_attachment.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck: func() {
			acctest.PreCheck(t)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccSensorUpdatePolicyHostGroupAttachmentConfig_exclusiveFalse(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "exclusive", "false"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "1"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "host_groups.*", "crowdstrike_host_group.test", "id"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
				),
			},
			{
				Config: testAccSensorUpdatePolicyHostGroupAttachmentConfig_exclusiveFalseUpdate(rName),
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
				Config: testAccSensorUpdatePolicyHostGroupAttachmentConfig_exclusiveFalseRemoveAll(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "exclusive", "false"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "0"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
				),
			},
		},
	})
}

func testAccSensorUpdatePolicyHostGroupAttachmentConfig_basic(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
data "crowdstrike_sensor_update_policy_builds" "all" {}

resource "crowdstrike_sensor_update_policy" "test" {
  name                 = "%[1]s-policy"
  enabled              = true
  description          = "test policy for attachment tests"
  platform_name        = "Windows"
  build                = data.crowdstrike_sensor_update_policy_builds.all.windows.n1.build
  uninstall_protection = false
  host_groups          = []
  schedule = {
    enabled = false
  }

  lifecycle {
    ignore_changes = [host_groups]
  }
}

resource "crowdstrike_host_group" "test" {
  name        = "%[1]s-hg"
  description = "test host group for attachment tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_sensor_update_policy_host_group_attachment" "test" {
  id          = crowdstrike_sensor_update_policy.test.id
  exclusive   = true
  host_groups = [crowdstrike_host_group.test.id]
}
`, rName)
}

func testAccSensorUpdatePolicyHostGroupAttachmentConfig_exclusiveFalse(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
data "crowdstrike_sensor_update_policy_builds" "all" {}

resource "crowdstrike_host_group" "existing" {
  name        = "%[1]s-existing"
  description = "existing host group attached to policy"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_sensor_update_policy" "test" {
  name                 = %[1]q
  enabled              = true
  description          = "test policy for attachment tests"
  platform_name        = "Windows"
  build                = data.crowdstrike_sensor_update_policy_builds.all.windows.n1.build
  uninstall_protection = false
  host_groups          = [crowdstrike_host_group.existing.id]
  schedule = {
    enabled = false
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

resource "crowdstrike_sensor_update_policy_host_group_attachment" "test" {
  id          = crowdstrike_sensor_update_policy.test.id
  exclusive   = false
  host_groups = [crowdstrike_host_group.test.id]
}
`, rName)
}

func testAccSensorUpdatePolicyHostGroupAttachmentConfig_exclusiveFalseUpdate(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
data "crowdstrike_sensor_update_policy_builds" "all" {}

resource "crowdstrike_host_group" "existing" {
  name        = "%[1]s-existing"
  description = "existing host group attached to policy"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_sensor_update_policy" "test" {
  name                 = %[1]q
  enabled              = true
  description          = "test policy for attachment tests"
  platform_name        = "Windows"
  build                = data.crowdstrike_sensor_update_policy_builds.all.windows.n1.build
  uninstall_protection = false
  host_groups          = [crowdstrike_host_group.existing.id]
  schedule = {
    enabled = false
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
  name        = "%[1]s-2"
  description = "second test host group for attachment tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_sensor_update_policy_host_group_attachment" "test" {
  id          = crowdstrike_sensor_update_policy.test.id
  exclusive   = false
  host_groups = [crowdstrike_host_group.test.id, crowdstrike_host_group.test2.id]
}
`, rName)
}

func testAccSensorUpdatePolicyHostGroupAttachmentConfig_exclusiveFalseRemoveAll(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
data "crowdstrike_sensor_update_policy_builds" "all" {}

resource "crowdstrike_host_group" "existing" {
  name        = "%[1]s-existing"
  description = "existing host group attached to policy"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_sensor_update_policy" "test" {
  name                 = %[1]q
  enabled              = true
  description          = "test policy for attachment tests"
  platform_name        = "Windows"
  build                = data.crowdstrike_sensor_update_policy_builds.all.windows.n1.build
  uninstall_protection = false
  host_groups          = [crowdstrike_host_group.existing.id]
  schedule = {
    enabled = false
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
  name        = "%[1]s-2"
  description = "second test host group for attachment tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_sensor_update_policy_host_group_attachment" "test" {
  id        = crowdstrike_sensor_update_policy.test.id
  exclusive = false
}
`, rName)
}
