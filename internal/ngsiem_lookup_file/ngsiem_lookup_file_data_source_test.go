package lookupfile_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccNGSIEMLookupFileDataSource_basic(t *testing.T) {
	rName := acctest.RandomResourceName()
	filename := rName + ".csv"
	dataSourceName := "data.crowdstrike_ngsiem_lookup_files.test"

	csvContent := "user_id,name,region\n1,alice,US\n"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccNGSIEMLookupFileDataSourceConfig(filename, csvContent),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckLookupFileInDataSource(dataSourceName, filename),
				),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("repository"), knownvalue.StringExact("all")),
				},
			},
		},
	})
}

func TestAccNGSIEMLookupFileDataSource_withFilter(t *testing.T) {
	rName := acctest.RandomResourceName()
	filename := rName + ".csv"
	dataSourceName := "data.crowdstrike_ngsiem_lookup_files.test"

	csvContent := "user_id,name,region\n1,alice,US\n"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccNGSIEMLookupFileDataSourceConfig_withFilter(filename, csvContent),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckLookupFileInDataSource(dataSourceName, filename),
				),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("repository"), knownvalue.StringExact("all")),
				},
			},
		},
	})
}

// testAccCheckLookupFileInDataSource verifies that the given filename appears
// in the data source's lookup_files list.
func testAccCheckLookupFileInDataSource(dataSourceName, expectedFilename string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[dataSourceName]
		if !ok {
			return fmt.Errorf("data source not found: %s", dataSourceName)
		}

		count := rs.Primary.Attributes["lookup_files.#"]
		if count == "" || count == "0" {
			return fmt.Errorf("lookup_files list is empty, expected at least one entry")
		}

		for i := 0; ; i++ {
			key := fmt.Sprintf("lookup_files.%d.filename", i)
			val, exists := rs.Primary.Attributes[key]
			if !exists {
				break
			}
			if val == expectedFilename {
				// Also verify the id format
				idKey := fmt.Sprintf("lookup_files.%d.id", i)
				expectedID := "all:" + expectedFilename
				if rs.Primary.Attributes[idKey] != expectedID {
					return fmt.Errorf("expected id %q, got %q", expectedID, rs.Primary.Attributes[idKey])
				}
				return nil
			}
		}

		return fmt.Errorf("filename %q not found in lookup_files list", expectedFilename)
	}
}

func testAccNGSIEMLookupFileDataSourceConfig(filename, content string) string {
	return fmt.Sprintf(`
resource "crowdstrike_ngsiem_lookup_file" "test" {
  filename       = %[1]q
  repository     = "all"
  content        = %[2]q
  content_sha256 = %[3]q
}

data "crowdstrike_ngsiem_lookup_files" "test" {
  repository = "all"

  depends_on = [crowdstrike_ngsiem_lookup_file.test]
}
`, filename, content, sha256Hex(content))
}

func testAccNGSIEMLookupFileDataSourceConfig_withFilter(filename, content string) string {
	return fmt.Sprintf(`
resource "crowdstrike_ngsiem_lookup_file" "test" {
  filename       = %[1]q
  repository     = "all"
  content        = %[2]q
  content_sha256 = %[3]q
}

data "crowdstrike_ngsiem_lookup_files" "test" {
  repository = "all"
  filter     = "name:~'%[1]s'"

  depends_on = [crowdstrike_ngsiem_lookup_file.test]
}
`, filename, content, sha256Hex(content))
}
