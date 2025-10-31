package containerregistry_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	tfacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccContainerRegistriesDataSource(t *testing.T) {
	dataSourceName := "data.crowdstrike_container_registries.test"
	resourceName := "crowdstrike_container_registry.test"
	registryAlias := fmt.Sprintf("test-registry-%s", tfacctest.RandStringFromCharSet(8, tfacctest.CharSetAlpha))
	registryURL := "registry.example.com"
	registryType := "docker"
	username := "testuser"
	password := "testpass"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccContainerRegistriesDataSourceConfig(registryAlias, registryURL, registryType, username, password),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verify the data source returns at least one registry
					resource.TestCheckResourceAttrSet(dataSourceName, "registries.#"),
					resource.TestCheckResourceAttr(dataSourceName, "registries.#", "1"),

					// Verify the registry data matches what we created
					resource.TestCheckResourceAttrPair(dataSourceName, "registries.0.id", resourceName, "id"),
					resource.TestCheckResourceAttrPair(dataSourceName, "registries.0.user_defined_alias", resourceName, "user_defined_alias"),
					resource.TestCheckResourceAttrPair(dataSourceName, "registries.0.url", resourceName, "url"),
					resource.TestCheckResourceAttrPair(dataSourceName, "registries.0.type", resourceName, "type"),
					resource.TestCheckResourceAttrPair(dataSourceName, "registries.0.state", resourceName, "state"),
					resource.TestCheckResourceAttrPair(dataSourceName, "registries.0.created_at", resourceName, "created_at"),
					resource.TestCheckResourceAttrPair(dataSourceName, "registries.0.updated_at", resourceName, "updated_at"),

					// Verify computed fields exist
					resource.TestCheckResourceAttrSet(dataSourceName, "registries.0.refresh_interval"),
					resource.TestCheckResourceAttrSet(dataSourceName, "registries.0.credential_expired"),
				),
			},
		},
	})
}

// NOTE: Filter functionality is not currently implemented in the data source
// This test was removed because it referenced non-existent filter attributes
// If filter functionality is needed in the future, it should be implemented
// in the data source schema first, then tests can be added

func TestAccContainerRegistriesDataSource_empty(t *testing.T) {
	dataSourceName := "data.crowdstrike_container_registries.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccContainerRegistriesDataSourceConfig_empty(),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verify the data source handles empty results gracefully
					resource.TestCheckResourceAttrSet(dataSourceName, "registries.#"),
				),
			},
		},
	})
}

func TestAccContainerRegistriesDataSource_filtered(t *testing.T) {
	dataSourceName := "data.crowdstrike_container_registries.test"
	resourceName := "crowdstrike_container_registry.test"
	registryAlias := fmt.Sprintf("test-registry-%s", tfacctest.RandStringFromCharSet(8, tfacctest.CharSetAlpha))
	registryURL := "registry.example.com"
	registryType := "docker"
	username := "testuser"
	password := "testpass"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccContainerRegistriesDataSourceConfig_filtered(registryAlias, registryURL, registryType, username, password),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verify the data source filters correctly
					resource.TestCheckResourceAttr(dataSourceName, "registries.#", "1"),

					// Verify the filtered registry matches what we created
					resource.TestCheckResourceAttrPair(dataSourceName, "registries.0.id", resourceName, "id"),
					resource.TestCheckResourceAttrPair(dataSourceName, "registries.0.user_defined_alias", resourceName, "user_defined_alias"),
					resource.TestCheckResourceAttr(dataSourceName, "registries.0.type", registryType),
				),
			},
		},
	})
}

// Configuration with a registry resource and data source to read it.
func testAccContainerRegistriesDataSourceConfig(alias, url, registryType, username, password string) string {
	return fmt.Sprintf(`
resource "crowdstrike_container_registry" "test" {
  user_defined_alias  = "%s"
  url                 = "%s"
  type                = "%s"
  credential_username = "%s"
  credential_password = "%s"
}

data "crowdstrike_container_registries" "test" {
  depends_on = [crowdstrike_container_registry.test]
}
`, alias, url, registryType, username, password)
}

// Configuration with just the data source (no filter, should return all registries).
func testAccContainerRegistriesDataSourceConfig_empty() string {
	return `
data "crowdstrike_container_registries" "test" {
}
`
}

// Configuration with a registry resource and filtered data source.
func testAccContainerRegistriesDataSourceConfig_filtered(alias, url, registryType, username, password string) string {
	return fmt.Sprintf(`
resource "crowdstrike_container_registry" "test" {
  user_defined_alias  = "%s"
  url                 = "%s"
  type                = "%s"
  credential_username = "%s"
  credential_password = "%s"
}

data "crowdstrike_container_registries" "test" {
  ids = [crowdstrike_container_registry.test.id]
  depends_on = [crowdstrike_container_registry.test]
}
`, alias, url, registryType, username, password)
}
