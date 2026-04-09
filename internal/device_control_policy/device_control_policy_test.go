package devicecontrolpolicy_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccDeviceControlPolicyResource_basic(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_device_control_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccDeviceControlPolicyConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platform_name"), knownvalue.StringExact("Windows")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enforcement_mode"), knownvalue.StringExact("MONITOR_ENFORCE")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("end_user_notification"), knownvalue.StringExact("SILENT")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			{
				Config: testAccDeviceControlPolicyConfig_update(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName+"-updated")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("updated description")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enforcement_mode"), knownvalue.StringExact("MONITOR_ONLY")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("end_user_notification"), knownvalue.StringExact("NOTIFY_USER")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
				},
			},
		},
	})
}

func TestAccDeviceControlPolicyResource_classes(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_device_control_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccDeviceControlPolicyConfig_classes(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enforcement_mode"), knownvalue.StringExact("MONITOR_ENFORCE")),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated", "classes"},
			},
		},
	})
}

func testAccDeviceControlPolicyConfig_basic(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_device_control_policy" "test" {
  name             = %[1]q
  platform_name    = "Windows"
  enabled          = true
  enforcement_mode = "MONITOR_ENFORCE"
}`, name)
}

func testAccDeviceControlPolicyConfig_update(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_device_control_policy" "test" {
  name                  = "%[1]s-updated"
  description           = "updated description"
  platform_name         = "Windows"
  enabled               = false
  enforcement_mode      = "MONITOR_ONLY"
  end_user_notification = "NOTIFY_USER"
}`, name)
}

func testAccDeviceControlPolicyConfig_classes(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_device_control_policy" "test" {
  name             = %[1]q
  platform_name    = "Windows"
  enforcement_mode = "MONITOR_ENFORCE"

  classes = [
    {
      id     = "MASS_STORAGE"
      action = "BLOCK_EXECUTE"
      exceptions = [
        {
          vendor_id   = "781"
          action      = "FULL_ACCESS"
          description = "Allow SanDisk devices"
        },
      ]
    },
    {
      id     = "WIRELESS"
      action = "FULL_ACCESS"
    },
  ]
}`, name)
}
