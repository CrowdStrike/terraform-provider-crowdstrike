package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccSensorUpdatePolicyResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: providerConfig + `
resource "crowdstrike_sensor_update_policy" "test" {
  name                 = "tf-test"
  enabled              = true
  description          = "made with terraform"
  platform_name        = "Windows"
  build                = "18110"
  uninstall_protection = false 
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"name",
						"tf-test",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"description",
						"made with terraform",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"enabled",
						"true",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"platform_name",
						"Windows",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"build",
						"18110",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"uninstall_protection",
						"false",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_update_policy.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_update_policy.test",
						"last_updated",
					),
				),
			},
			// ImportState testing
			{
				ResourceName:            "crowdstrike_sensor_update_policy.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Update and Read testing
			{
				Config: providerConfig + `
resource "crowdstrike_sensor_update_policy" "test" {
  name                 = "tf-test-updated"
  enabled              = false
  description          = "made with terraform updated"
  platform_name        = "Windows"
  build                = "18110"
  uninstall_protection = true 
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"name",
						"tf-test-updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"description",
						"made with terraform updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"enabled",
						"false",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"platform_name",
						"Windows",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"build",
						"18110",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"uninstall_protection",
						"true",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_update_policy.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_update_policy.test",
						"last_updated",
					),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
