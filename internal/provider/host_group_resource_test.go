package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccHostGroupResource(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acceptance-test")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: providerConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name        = "%s"
  description = "made with terraform"
  type        = "dynamic"
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"description",
						"made with terraform",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"type",
						"dynamic",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"assignment_rule",
						"",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_host_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_host_group.test",
						"last_updated",
					),
				),
			},
			// ImportState testing
			{
				ResourceName:            "crowdstrike_host_group.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Update and Read testing
			{
				Config: providerConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name            = "%s-updated"
  description     = "made with terraform updated"
  type            = "dynamic"
  assignment_rule = "tags:'SensorGroupingTags/cloud-lab'+os_version:'Amazon Linux 2'"
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"name",
						rName+"-updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"description",
						"made with terraform updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"type",
						"dynamic",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"assignment_rule",
						"tags:'SensorGroupingTags/cloud-lab'+os_version:'Amazon Linux 2'",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_host_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_host_group.test",
						"last_updated",
					),
				),
			},
			// if no assignment_rule is passed we don't manage the value
			{
				Config: providerConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name            = "%s-updated"
  description     = "made with terraform updated"
  type            = "dynamic"
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"name",
						rName+"-updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"description",
						"made with terraform updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"type",
						"dynamic",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"assignment_rule",
						"tags:'SensorGroupingTags/cloud-lab'+os_version:'Amazon Linux 2'",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_host_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_host_group.test",
						"last_updated",
					),
				),
			},
			// remove assignment_rule
			{
				Config: providerConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name            = "%s-updated"
  description     = "made with terraform updated"
  type            = "dynamic"
  assignment_rule = ""
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"name",
						rName+"-updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"description",
						"made with terraform updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"type",
						"dynamic",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_host_group.test",
						"assignment_rule",
						"",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_host_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_host_group.test",
						"last_updated",
					),
				),
			},
		},
	})
}
