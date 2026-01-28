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
			tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
		},
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policy_builds" "all" {}
resource "crowdstrike_default_sensor_update_policy" "default" {
  platform_name        = "Windows"
  build                = data.crowdstrike_sensor_update_policy_builds.all.windows.n1.build
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
				ExpectError: regexp.MustCompile("(?i)(?s).*invalid(?s).*build invalid.*"),
			},
		},
	})
}

func TestAccDefaultSensorUpdatePolicyResourceWithSchedule(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
		},
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policy_builds" "all" {}
resource "crowdstrike_default_sensor_update_policy" "default" {
  platform_name        = "Windows"
  build                = data.crowdstrike_sensor_update_policy_builds.all.windows.n1.build
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

// regression test to handle unknown states https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues/136
func TestAccDefaultSensorUpdatePolicyResourceWithSchedule_unknown(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
		},
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + `
variable "schedule" {
  type = object({
    enabled     = bool
    timezone   = string
    time_blocks = list(object({
      days       = list(string)
      start_time = string
      end_time   = string
    }))
  })

  default = {
    enabled     = true
    timezone   = "Etc/UTC"
    time_blocks = [
      {
        days       = ["sunday", "wednesday"]
        start_time = "11:40"
        end_time   = "17:40"
      }
    ]
  }
}

data "crowdstrike_sensor_update_policy_builds" "all" {}
resource "crowdstrike_default_sensor_update_policy" "default" {
  platform_name        = "Windows"
  build                = data.crowdstrike_sensor_update_policy_builds.all.windows.n1.build
  uninstall_protection = true
  schedule = {
    enabled = var.schedule.enabled
    timezone = var.schedule.timezone
    time_blocks = var.schedule.time_blocks
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
						"11:40",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"schedule.time_blocks.0.end_time",
						"17:40",
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

func TestAccDefaultSensorUpdatePolicyResourceWithBulkMaintenanceMode(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policy_builds" "all" {}
resource "crowdstrike_default_sensor_update_policy" "default" {
  platform_name         = "Windows"
  build                 = data.crowdstrike_sensor_update_policy_builds.all.windows.n1.build
  uninstall_protection  = false
  bulk_maintenance_mode = false
  schedule = {
    enabled = false
  }
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						resourceName,
						"platform_name",
						"Windows",
					),
					resource.TestCheckResourceAttrSet(
						resourceName,
						"build",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"uninstall_protection",
						"false",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"bulk_maintenance_mode",
						"false",
					),
					resource.TestCheckResourceAttrSet(
						resourceName,
						"id",
					),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			{
				Config: acctest.ProviderConfig + `
resource "crowdstrike_default_sensor_update_policy" "default" {
  platform_name         = "Windows"
  build                 = ""
  uninstall_protection  = true
  bulk_maintenance_mode = true
  schedule = {
    enabled = false
  }
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						resourceName,
						"platform_name",
						"Windows",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"build",
						"",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"uninstall_protection",
						"true",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"bulk_maintenance_mode",
						"true",
					),
				),
			},
		},
	})
}

func TestAccDefaultSensorUpdatePolicyResourceWithBulkMaintenanceMode_Validation(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + `
resource "crowdstrike_default_sensor_update_policy" "default" {
  platform_name         = "Windows"
  build                 = ""
  uninstall_protection  = false
  bulk_maintenance_mode = true
  schedule = {
    enabled = false
  }
}
`,
				ExpectError: regexp.MustCompile("bulk_maintenance_mode is set to true"),
			},
			{
				Config: acctest.ProviderConfig + `
data "crowdstrike_sensor_update_policy_builds" "all" {}
resource "crowdstrike_default_sensor_update_policy" "default" {
  platform_name         = "Windows"
  build                 = data.crowdstrike_sensor_update_policy_builds.all.windows.n1.build
  uninstall_protection  = true
  bulk_maintenance_mode = true
  schedule = {
    enabled = false
  }
}
`,
				ExpectError: regexp.MustCompile(`disable sensor version updates`),
			},
		},
	})
}
