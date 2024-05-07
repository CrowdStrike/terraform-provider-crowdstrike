package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccSensorUpdatePolicyBuildsDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		PreCheck:                 func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: providerConfig + `data "crowdstrike_sensor_update_policy_builds" "test" {}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(
						"data.crowdstrike_sensor_update_policy_builds.test",
						"windows.latest.build",
					),
					resource.TestCheckResourceAttrSet(
						"data.crowdstrike_sensor_update_policy_builds.test",
						"windows.n1.build",
					),
					resource.TestCheckResourceAttrSet(
						"data.crowdstrike_sensor_update_policy_builds.test",
						"windows.n2.build",
					),
					resource.TestCheckResourceAttrSet(
						"data.crowdstrike_sensor_update_policy_builds.test",
						"linux.latest.build",
					),
					resource.TestCheckResourceAttrSet(
						"data.crowdstrike_sensor_update_policy_builds.test",
						"linux.n1.build",
					),
					resource.TestCheckResourceAttrSet(
						"data.crowdstrike_sensor_update_policy_builds.test",
						"linux.n2.build",
					),
					resource.TestCheckResourceAttrSet(
						"data.crowdstrike_sensor_update_policy_builds.test",
						"mac.latest.build",
					),
					resource.TestCheckResourceAttrSet(
						"data.crowdstrike_sensor_update_policy_builds.test",
						"mac.n1.build",
					),
					resource.TestCheckResourceAttrSet(
						"data.crowdstrike_sensor_update_policy_builds.test",
						"mac.n2.build",
					),
					resource.TestCheckResourceAttrSet(
						"data.crowdstrike_sensor_update_policy_builds.test",
						"windows.all.0.stage",
					),
					resource.TestCheckResourceAttrSet(
						"data.crowdstrike_sensor_update_policy_builds.test",
						"windows.all.0.platform",
					),
					resource.TestCheckResourceAttrSet(
						"data.crowdstrike_sensor_update_policy_builds.test",
						"windows.all.0.sensor_version",
					),
					resource.TestCheckResourceAttrSet(
						"data.crowdstrike_sensor_update_policy_builds.test",
						"windows.all.0.build",
					),
					resource.TestCheckResourceAttr(
						"data.crowdstrike_sensor_update_policy_builds.test",
						"id",
						"all",
					),
				),
			},
		},
	})
}
