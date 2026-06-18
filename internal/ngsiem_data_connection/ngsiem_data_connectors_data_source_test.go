package ngsiemdataconnection_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccNgsiemDataConnectorsDataSource_basic(t *testing.T) {
	dataSourceName := "data.crowdstrike_ngsiem_data_connectors.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConnectorsDataSourceConfig(),
				ConfigStateChecks: []statecheck.StateCheck{
					// by_name resolves a concrete connector ID.
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					// The catalog is non-empty: the first connector has an id and a name.
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("connectors").AtSliceIndex(0).AtMapKey("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("connectors").AtSliceIndex(0).AtMapKey("name"), knownvalue.NotNull()),
				},
			},
			{
				// Without by_name, id must be null but the catalog still populated.
				Config: testAccConnectorsDataSourceConfigNoFilter(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("id"), knownvalue.Null()),
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("connectors").AtSliceIndex(0).AtMapKey("id"), knownvalue.NotNull()),
				},
			},
		},
	})
}

func testAccConnectorsDataSourceConfig() string {
	return fmt.Sprintf(`
data "crowdstrike_ngsiem_data_connectors" "test" {
  by_name = %[1]q
}
`, hecConnectorName)
}

func testAccConnectorsDataSourceConfigNoFilter() string {
	return `
data "crowdstrike_ngsiem_data_connectors" "test" {}
`
}

// by_name rejects a whitespace-only value at plan time via the StringNotWhitespace validator.
func TestAccNgsiemDataConnectorsDataSource_byNameValidation(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "crowdstrike_ngsiem_data_connectors" "test" {
  by_name = "   "
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`must not be empty or contain only`),
			},
		},
	})
}
