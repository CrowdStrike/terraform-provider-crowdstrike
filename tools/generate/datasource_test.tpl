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

func TestAcc{{.PascalCaseName}}DataSource_basic(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "data.crowdstrike_{{.SnakeCaseName}}.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAcc{{.PascalCaseName}}DataSourceConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					// TODO: Add checks for expected attributes
				},
			},
		},
	})
}

func testAcc{{.PascalCaseName}}DataSourceConfig_basic(name string) string {
	return fmt.Sprintf(`
data "crowdstrike_{{.SnakeCaseName}}" "test" {
  // TODO: Add required filter attributes
}`, name)
}
