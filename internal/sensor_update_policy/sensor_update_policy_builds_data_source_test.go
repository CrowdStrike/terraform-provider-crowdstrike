package sensorupdatepolicy_test

import (
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccSensorUpdatePolicyBuildsDataSource(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: acctest.ProviderConfig + `data "crowdstrike_sensor_update_policy_builds" "test" {}`,
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
