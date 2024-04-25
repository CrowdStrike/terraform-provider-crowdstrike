package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccSensorUpdatePolicyBuildsDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: providerConfig + `data "crowdstrike_sensor_update_policy_builds" "test" {}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(
						"data.crowdstrike_sensor_update_policy_builds.test",
						"sensor_update_policy_builds.0.build",
					),
					resource.TestCheckResourceAttrSet(
						"data.crowdstrike_sensor_update_policy_builds.test",
						"sensor_update_policy_builds.0.stage",
					),
					resource.TestCheckResourceAttrSet(
						"data.crowdstrike_sensor_update_policy_builds.test",
						"sensor_update_policy_builds.0.platform",
					),
					resource.TestCheckResourceAttrSet(
						"data.crowdstrike_sensor_update_policy_builds.test",
						"sensor_update_policy_builds.0.sensor_version",
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
