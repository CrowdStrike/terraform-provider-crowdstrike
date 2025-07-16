package fim_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccFilevantagePolicyConfig_basic(rName string, enabled bool) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_filevantage_policy" "test" {
  name                      = "%s"
  enabled                   = %t 
  platform_name             = "Windows"
  description               = "made with terraform"
}
`, rName, enabled)
}

func testAccFilevantagePolicyConfig_groups(
	rName string,
	hostGroupID string,
	enabled bool,
) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_filevantage_policy" "test" {
  name                      = "%s"
  host_groups               = ["%s"]
  enabled                   = %t 
  platform_name             = "Windows"
  description               = "made with terraform"
}
`, rName, hostGroupID, enabled)
}

func TestAccFilevantagePolicyResource(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	resourceName := "crowdstrike_filevantage_policy.test"
	hostGroupID, _ := os.LookupEnv("HOST_GROUP_ID")

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t, acctest.RequireHostGroupID) },
		Steps: []resource.TestStep{
			{
				Config: testAccFilevantagePolicyConfig_basic(rName, true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(
						resourceName,
						"description",
						"made with terraform",
					),
					resource.TestCheckResourceAttr(resourceName, "enabled", "true"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			{
				Config: testAccFilevantagePolicyConfig_groups(
					fmt.Sprintf("%s-updated", rName),
					hostGroupID,
					false,
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						resourceName,
						"name",
						rName+"-updated",
					),
					resource.TestCheckResourceAttr(
						resourceName,
						"enabled",
						"false",
					),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.0", hostGroupID),
				),
			},
		},
	})
}
