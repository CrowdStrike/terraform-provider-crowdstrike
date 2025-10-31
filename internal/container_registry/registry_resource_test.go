package containerregistry_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	tfacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccContainerRegistryResource(t *testing.T) {
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
			// Create and Read testing
			{
				Config: testAccContainerRegistryConfig_basic(registryAlias, registryURL, registryType, username, password),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "user_defined_alias", registryAlias),
					resource.TestCheckResourceAttr(resourceName, "url", fmt.Sprintf("https://%s", registryURL)),
					resource.TestCheckResourceAttr(resourceName, "type", registryType),
					resource.TestCheckResourceAttr(resourceName, "credential_username", username),
					resource.TestCheckResourceAttr(resourceName, "credential_password", password),
					// Computed fields should exist
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "created_at"),
					resource.TestCheckResourceAttrSet(resourceName, "updated_at"),
					resource.TestCheckResourceAttrSet(resourceName, "state"),
					resource.TestCheckResourceAttrSet(resourceName, "refresh_interval"),
				),
			},
			// Import testing
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"credential_username",
					"credential_password", // Credentials are not returned by the API for security
				},
			},
			// Update testing
			{
				Config: testAccContainerRegistryConfig_update(registryAlias, registryURL, registryType, username, password),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "user_defined_alias", fmt.Sprintf("%s-updated", registryAlias)),
					resource.TestCheckResourceAttr(resourceName, "url", fmt.Sprintf("https://%s", registryURL)),
					resource.TestCheckResourceAttr(resourceName, "type", registryType),
					resource.TestCheckResourceAttr(resourceName, "credential_username", username),
					resource.TestCheckResourceAttr(resourceName, "credential_password", password),
					// Computed fields should exist
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "updated_at"),
				),
			},
		},
	})
}

func TestAccContainerRegistryResource_withURLKey(t *testing.T) {
	resourceName := "crowdstrike_container_registry.test"
	registryAlias := fmt.Sprintf("test-registry-%s", tfacctest.RandStringFromCharSet(8, tfacctest.CharSetAlpha))
	registryURL := "registry.example.com"
	registryType := "docker"
	urlKey := "example-key"
	username := "testuser"
	password := "testpass"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccContainerRegistryConfig_withURLKey(registryAlias, registryURL, registryType, urlKey, username, password),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "user_defined_alias", registryAlias),
					resource.TestCheckResourceAttr(resourceName, "url", fmt.Sprintf("https://%s", registryURL)),
					resource.TestCheckResourceAttr(resourceName, "type", registryType),
					resource.TestCheckResourceAttr(resourceName, "url_uniqueness_key", urlKey),
					resource.TestCheckResourceAttr(resourceName, "credential_username", username),
					resource.TestCheckResourceAttr(resourceName, "credential_password", password),
					// Computed fields should exist
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "created_at"),
					resource.TestCheckResourceAttrSet(resourceName, "state"),
				),
			},
		},
	})
}

// Basic configuration.
func testAccContainerRegistryConfig_basic(alias, url, registryType, username, password string) string {
	return fmt.Sprintf(`
resource "crowdstrike_container_registry" "test" {
  user_defined_alias    = "%s"
  url                   = "%s"
  type                  = "%s"
  credential_username   = "%s"
  credential_password   = "%s"
}
`, alias, url, registryType, username, password)
}

// Updated configuration.
func testAccContainerRegistryConfig_update(alias, url, registryType, username, password string) string {
	return fmt.Sprintf(`
resource "crowdstrike_container_registry" "test" {
  user_defined_alias    = "%s-updated"
  url                   = "%s"
  type                  = "%s"
  credential_username   = "%s"
  credential_password   = "%s"
}
`, alias, url, registryType, username, password)
}

// Configuration with URL uniqueness key.
func testAccContainerRegistryConfig_withURLKey(alias, url, registryType, urlKey, username, password string) string {
	return fmt.Sprintf(`
resource "crowdstrike_container_registry" "test" {
  user_defined_alias    = "%s"
  url                   = "%s"
  type                  = "%s"
  url_uniqueness_key    = "%s"
  credential_username   = "%s"
  credential_password   = "%s"
}
`, alias, url, registryType, urlKey, username, password)
}
