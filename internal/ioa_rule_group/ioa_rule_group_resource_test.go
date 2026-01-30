package ioarulegroup_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccIOARuleGroupResource(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = "%s"
  description = "made with terraform"
  platform    = "linux"
  comment     = "test comment"
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"description",
						"made with terraform",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"platform",
						"linux",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"comment",
						"test comment",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_ioa_rule_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_ioa_rule_group.test",
						"last_updated",
					),
				),
			},
			// ImportState testing
			{
				ResourceName:            "crowdstrike_ioa_rule_group.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Update testing - should work with comment
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = "%s-updated"
  description = "updated with terraform"
  platform    = "linux"
  comment     = "updated comment"
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"name",
						rName+"-updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"description",
						"updated with terraform",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"comment",
						"updated comment",
					),
				),
			},
		},
	})
}

func TestAccIOARuleGroupResourceUpdateWithoutComment(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create without comment
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name     = "%s"
  platform = "linux"
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"platform",
						"linux",
					),
				),
			},
			// Try to update without comment - should fail
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = "%s-updated"
  description = "updated description"
  platform    = "linux"
}
`, rName),
				ExpectError: regexp.MustCompile("Comment required for updates"),
			},
		},
	})
}

func TestAccIOARuleGroupResourceMinimal(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Test with minimal configuration (only required fields)
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name     = "%s-minimal"
  platform = "linux"
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"name",
						rName+"-minimal",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"platform",
						"linux",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_ioa_rule_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_ioa_rule_group.test",
						"last_updated",
					),
				),
			},
			// ImportState testing
			{
				ResourceName:            "crowdstrike_ioa_rule_group.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
		},
	})
}
