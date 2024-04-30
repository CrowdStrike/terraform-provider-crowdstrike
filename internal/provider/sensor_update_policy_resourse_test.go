package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccSensorUpdatePolicyResource(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acceptance-test")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		PreCheck:                 func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: providerConfig + fmt.Sprintf(`
resource "crowdstrike_sensor_update_policy" "test" {
  name                 = "%s"
  enabled              = true
  description          = "made with terraform"
  platform_name        = "Windows"
  build                = "18110"
  uninstall_protection = false 
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"name",
						rName,
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
				Config: providerConfig + fmt.Sprintf(`
resource "crowdstrike_sensor_update_policy" "test" {
  name                 = "%s-updated"
  enabled              = false
  description          = "made with terraform updated"
  platform_name        = "Windows"
  build                = "18110"
  uninstall_protection = true 
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"name",
						rName+"-updated",
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

func TestAccSensorUpdatePolicyResourceWithHostGroup(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acceptance-test")
	hostGroupID, _ := os.LookupEnv("HOST_GROUP_ID")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		PreCheck:                 func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: providerConfig + fmt.Sprintf(`
resource "crowdstrike_sensor_update_policy" "test" {
  name                 = "%s"
  enabled              = true
  host_groups          = ["%s"]
  description          = "made with terraform"
  platform_name        = "Windows"
  build                = "18110"
  uninstall_protection = false 
}
`, rName, hostGroupID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"name",
						rName,
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
					resource.TestCheckResourceAttr("crowdstrike_sensor_update_policy.test",
						"host_groups.#",
						"1",
					),
					resource.TestCheckResourceAttr("crowdstrike_sensor_update_policy.test",
						"host_groups.0",
						hostGroupID,
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
				Config: providerConfig + fmt.Sprintf(`
resource "crowdstrike_sensor_update_policy" "test" {
  name                 = "%s-updated"
  enabled              = false
  description          = "made with terraform updated"
  platform_name        = "Windows"
  build                = "18110"
  uninstall_protection = true 
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"name",
						rName+"-updated",
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
					resource.TestCheckNoResourceAttr(
						"crowdstrike_sensor_update_policy.test",
						"host_groups",
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
