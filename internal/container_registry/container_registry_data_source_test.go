package containerregistry_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccContainerRegistryDataSource_basic(t *testing.T) {
	id := os.Getenv("TEST_CONTAINER_REGISTRY_ID")
	if id == "" {
		t.Skip("TEST_CONTAINER_REGISTRY_ID not set")
	}

	resourceName := "data.crowdstrike_container_registry.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccContainerRegistryDataSourceConfig_basic(id),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "id", id),
					resource.TestCheckResourceAttrSet(resourceName, "url"),
					resource.TestCheckResourceAttrSet(resourceName, "type"),
					resource.TestCheckResourceAttrSet(resourceName, "state"),
				),
			},
		},
	})
}

func testAccContainerRegistryDataSourceConfig_basic(id string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
data "crowdstrike_container_registry" "test" {
  id = %[1]q
}
`, id)
}
