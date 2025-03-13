package sensorupdatepolicy_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"

	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccDefaultSensorUpdatePolicyResource(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-default")
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_default_sensor_update_policy" "default" {
  name                 = "%s"
  enabled              = true
  description          = "made with terraform"
  host_groups          = []
  platform_name        = "Windows"
  build                = "18721"
  uninstall_protection = false 
  schedule = {
    enabled = false
  }
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"description",
						"made with terraform",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"enabled",
						"true",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"platform_name",
						"Windows",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"build",
						"18721",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"uninstall_protection",
						"false",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"schedule.enabled",
						"false",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_default_sensor_update_policy.default",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_default_sensor_update_policy.default",
						"last_updated",
					),
				),
			},
			// ImportState testing
			{
				ResourceName:            "crowdstrike_default_sensor_update_policy.default",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Update and Read testing
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_default_sensor_update_policy" "default" {
  name                 = "%s-updated"
  enabled              = false
  description          = "made with terraform updated"
  platform_name        = "Windows"
  host_groups          = []
  build                = "18721"
  uninstall_protection = true 
  schedule = {
    enabled = false
  }
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"name",
						rName+"-updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"description",
						"made with terraform updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"enabled",
						"false",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"platform_name",
						"Windows",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"build",
						"18721",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"uninstall_protection",
						"true",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"schedule.enabled",
						"false",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_default_sensor_update_policy.default",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_default_sensor_update_policy.default",
						"last_updated",
					),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestAccDefaultSensorUpdatePolicyResourceWithSchedule(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-default")
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_default_sensor_update_policy" "default" {
  name                 = "%s"
  enabled              = true
  description          = "made with terraform"
  platform_name        = "Windows"
  build                = "18721"
  uninstall_protection = false 
  schedule = {
    enabled = false
  }
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"description",
						"made with terraform",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"enabled",
						"true",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"platform_name",
						"Windows",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"build",
						"18721",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"uninstall_protection",
						"false",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"schedule.enabled",
						"false",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_default_sensor_update_policy.default",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_default_sensor_update_policy.default",
						"last_updated",
					),
				),
			},
			// Update and Read testing
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_default_sensor_update_policy" "default" {
  name                 = "%s-updated"
  enabled              = false
  description          = "made with terraform updated"
  platform_name        = "Windows"
  build                = "18721"
  uninstall_protection = true 
  schedule = {
    enabled = true 
    timezone = "Etc/UTC"
    time_blocks = [
     {
       days       = ["sunday", "wednesday"]
       start_time = "12:40"
       end_time   = "16:40"
     }
   ]
  }
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"name",
						rName+"-updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"description",
						"made with terraform updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"enabled",
						"false",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"platform_name",
						"Windows",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"build",
						"18721",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"uninstall_protection",
						"true",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"schedule.enabled",
						"true",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"schedule.timezone",
						"Etc/UTC",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"schedule.time_blocks.#",
						"1",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"schedule.time_blocks.0.days.#",
						"2",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"schedule.time_blocks.0.days.0",
						"sunday",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"schedule.time_blocks.0.days.1",
						"wednesday",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"schedule.time_blocks.0.start_time",
						"12:40",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_default_sensor_update_policy.default",
						"schedule.time_blocks.0.end_time",
						"16:40",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_default_sensor_update_policy.default",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_default_sensor_update_policy.default",
						"last_updated",
					),
				),
			},
			// ImportState testing
			{
				ResourceName:            "crowdstrike_default_sensor_update_policy.default",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
		},
	})
}
