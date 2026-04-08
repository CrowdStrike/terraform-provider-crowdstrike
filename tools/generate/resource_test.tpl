package {{.PackageName}}_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAcc{{.PascalCaseName}}Resource_basic(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_{{.SnakeCaseName}}.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAcc{{.PascalCaseName}}Config_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
					// TODO: Add checks for required attributes
				},
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

func testAcc{{.PascalCaseName}}Config_basic(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_{{.SnakeCaseName}}" "test" {
  name = %[1]q
}`, name)
}
