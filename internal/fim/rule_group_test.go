package fim_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccFilevantageRuleGroup_basic(t *testing.T, rgType string) resource.TestCase {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	rDescription := sdkacctest.RandString(20)
	config := acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_filevantage_rule_group" "test" {
  name        = "%s"
  type        = "%s"
  description = "%s"
}
`, rName, rgType, rDescription)

	resourceName := "crowdstrike_filevantage_rule_group.test"

	return resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", rDescription),
					resource.TestCheckResourceAttr(resourceName, "type", rgType),
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
		},
	}
}

func TestAccFilevantageRuleGroupResourceWindowsFiles(t *testing.T) {
	resource.ParallelTest(t, testAccFilevantageRuleGroup_basic(t, "WindowsFiles"))
}

func TestAccFilevantageRuleGroupResourceWindowsRegistry(t *testing.T) {
	resource.ParallelTest(t, testAccFilevantageRuleGroup_basic(t, "WindowsRegistry"))
}

func TestAccFilevantageRuleGroupResourceLinuxFiles(t *testing.T) {
	resource.ParallelTest(t, testAccFilevantageRuleGroup_basic(t, "LinuxFiles"))
}

func TestAccFilevantageRuleGroupResourceMacFiles(t *testing.T) {
	resource.ParallelTest(t, testAccFilevantageRuleGroup_basic(t, "MacFiles"))
}
