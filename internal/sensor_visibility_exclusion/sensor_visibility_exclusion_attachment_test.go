package sensorvisibilityexclusion_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccSensorVisibilityExclusionAttachmentResource_basic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test")
	}

	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_sensor_visibility_exclusion_attachment.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck: func() {
			acctest.PreCheck(t)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccSensorVisibilityExclusionAttachmentConfig_basic(rName),
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

func TestAccSensorVisibilityExclusionAttachmentResource_exclusiveFalse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test")
	}

	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_sensor_visibility_exclusion_attachment.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck: func() {
			acctest.PreCheck(t)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccSensorVisibilityExclusionAttachmentConfig_exclusiveFalse(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "exclusive", "false"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "1"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "host_groups.*", "crowdstrike_host_group.test", "id"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
				),
			},
			{
				Config: testAccSensorVisibilityExclusionAttachmentConfig_exclusiveFalseUpdate(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "exclusive", "false"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "2"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "host_groups.*", "crowdstrike_host_group.test", "id"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "host_groups.*", "crowdstrike_host_group.test2", "id"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
				),
			},
		},
	})
}

func testAccSensorVisibilityExclusionAttachmentConfig_basic(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_sensor_visibility_exclusion" "test" {
  value                         = "/test/path/%[1]s"
  apply_to_descendant_processes = false
  apply_globally                = true

  lifecycle {
    ignore_changes = [host_groups, apply_globally]
  }
}

resource "crowdstrike_host_group" "test" {
  name        = "%[1]s-hg"
  description = "test host group for attachment tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_sensor_visibility_exclusion_attachment" "test" {
  id          = crowdstrike_sensor_visibility_exclusion.test.id
  exclusive   = true
  host_groups = [crowdstrike_host_group.test.id]

  depends_on = [
    crowdstrike_sensor_visibility_exclusion.test
  ]
}
`, rName)
}

func testAccSensorVisibilityExclusionAttachmentConfig_exclusiveFalse(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "existing" {
  name        = "%[1]s-existing"
  description = "existing host group attached to exclusion"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_sensor_visibility_exclusion" "test" {
  value                         = "/test/path/%[1]s"
  apply_to_descendant_processes = false
  host_groups                   = [crowdstrike_host_group.existing.id]

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

resource "crowdstrike_sensor_visibility_exclusion_attachment" "test" {
  id          = crowdstrike_sensor_visibility_exclusion.test.id
  exclusive   = false
  host_groups = [crowdstrike_host_group.test.id]
}
`, rName)
}

func testAccSensorVisibilityExclusionAttachmentConfig_exclusiveFalseUpdate(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "existing" {
  name        = "%[1]s-existing"
  description = "existing host group attached to exclusion"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_sensor_visibility_exclusion" "test" {
  value                         = "/test/path/%[1]s"
  apply_to_descendant_processes = false
  host_groups                   = [crowdstrike_host_group.existing.id]

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

resource "crowdstrike_sensor_visibility_exclusion_attachment" "test" {
  id          = crowdstrike_sensor_visibility_exclusion.test.id
  exclusive   = false
  host_groups = [crowdstrike_host_group.test.id, crowdstrike_host_group.test2.id]
}
`, rName)
}
