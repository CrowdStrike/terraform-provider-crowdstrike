package sensorupdatepolicy_test

import (
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

const resourceName = "crowdstrike_default_sensor_update_policy.default"

func TestAccDefaultSensorUpdatePolicyResourceBadBuildUpdate(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.4.0"))),
		},
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + `
resource "crowdstrike_default_sensor_update_policy" "default" {
  platform_name        = "Windows"
  build                = "19507"
  uninstall_protection = false 
  schedule = {
    enabled = false
  }
}`,
			},
			{
				Config: acctest.ProviderConfig + `
resource "crowdstrike_default_sensor_update_policy" "default" {
  platform_name        = "Windows"
  build                = "invalid"
  uninstall_protection = false 
  schedule = {
    enabled = false
  }
}`,
				ExpectError: regexp.MustCompile(
					"The API returned a build that did not match the build in plan: \"invalid\"",
				),
			},
		},
	})
}

func TestAccDefaultSensorUpdatePolicyResourceWithSchedule(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.4.0"))),
		},
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + `
resource "crowdstrike_default_sensor_update_policy" "default" {
  platform_name        = "Windows"
  build                = "19507"
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
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						resourceName,
						"platform_name",
						"Windows",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"build",
						"19507",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"uninstall_protection",
						"true",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"schedule.enabled",
						"true",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"schedule.timezone",
						"Etc/UTC",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"schedule.time_blocks.#",
						"1",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"schedule.time_blocks.0.days.#",
						"2",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"schedule.time_blocks.0.days.0",
						"sunday",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"schedule.time_blocks.0.days.1",
						"wednesday",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"schedule.time_blocks.0.start_time",
						"12:40",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"schedule.time_blocks.0.end_time",
						"16:40",
					),
					resource.TestCheckResourceAttrSet(
						resourceName,
						"id",
					),
					resource.TestCheckResourceAttrSet(
						resourceName,
						"last_updated",
					),
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
