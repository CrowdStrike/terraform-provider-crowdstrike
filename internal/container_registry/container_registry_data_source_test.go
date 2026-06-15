package containerregistry_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccContainerRegistryDataSource_basic(t *testing.T) {
	role, externalID, url := requireECRCreds(t)

	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_container_registry.test"
	dataSourceByID := "data.crowdstrike_container_registry.by_id"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccContainerRegistryDataSourceConfig_basic(rName, url, role, externalID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("id"),
						dataSourceByID, tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("url"),
						dataSourceByID, tfjsonpath.New("url"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("type"),
						dataSourceByID, tfjsonpath.New("type"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("user_defined_alias"),
						dataSourceByID, tfjsonpath.New("user_defined_alias"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("url_uniqueness_alias"),
						dataSourceByID, tfjsonpath.New("url_uniqueness_alias"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("created_at"),
						dataSourceByID, tfjsonpath.New("created_at"),
						compare.ValuesSame(),
					),
					// state is server-driven and transitions asynchronously, so the
					// resource read and the data source read moments later can
					// legitimately differ.
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("refresh_interval"),
						dataSourceByID, tfjsonpath.New("refresh_interval"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("credential").AtMapKey("credential_id"),
						dataSourceByID, tfjsonpath.New("credential_id"),
						compare.ValuesSame(),
					),
					statecheck.ExpectKnownValue(dataSourceByID, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(dataSourceByID, tfjsonpath.New("url"), knownvalue.StringExact(url)),
					statecheck.ExpectKnownValue(dataSourceByID, tfjsonpath.New("type"), knownvalue.StringExact("ecr")),
					statecheck.ExpectKnownValue(dataSourceByID, tfjsonpath.New("user_defined_alias"), knownvalue.StringExact(rName)),
				},
			},
		},
	})
}

func TestAccContainerRegistryDataSource_notFound(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + `
data "crowdstrike_container_registry" "test" {
  id = "00000000-0000-0000-0000-000000000000"
}
`,
				ExpectError: regexp.MustCompile(`No container registry found with ID`),
			},
		},
	})
}

func testAccContainerRegistryDataSourceConfig_basic(alias, url, role, externalID string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_container_registry" "test" {
  url                = %[2]q
  type               = "ecr"
  user_defined_alias = %[1]q
  url_uniqueness_key = %[1]q

  credential = {
    aws_iam_role    = %[3]q
    aws_external_id = %[4]q
  }
}

data "crowdstrike_container_registry" "by_id" {
  id = crowdstrike_container_registry.test.id
}
`, alias, url, role, externalID)
}
