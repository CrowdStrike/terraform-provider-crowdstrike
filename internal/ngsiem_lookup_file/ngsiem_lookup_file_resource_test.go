package lookupfile_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestAccNGSIEMLookupFileResource_basic(t *testing.T) {
	rName := acctest.RandomResourceName()
	filename := rName + ".csv"
	resourceName := "crowdstrike_ngsiem_lookup_file.test"

	csvContent := "user_id,name,region\n1,alice,US\n2,bob,EU\n"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccNGSIEMLookupConfig(filename, csvContent),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("filename"), knownvalue.StringExact(filename)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("repository"), knownvalue.StringExact("all")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("content_sha256"), knownvalue.StringExact(sha256Hex(csvContent))),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"content", "content_sha256"},
			},
		},
	})
}

func TestAccNGSIEMLookupFileResource_update(t *testing.T) {
	rName := acctest.RandomResourceName()
	filename := rName + ".csv"
	resourceName := "crowdstrike_ngsiem_lookup_file.test"

	csvContent1 := "user_id,name,region\n1,alice,US\n2,bob,EU\n"
	csvContent2 := "user_id,name,region\n1,alice,US\n2,bob,EU\n3,charlie,AU\n"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccNGSIEMLookupConfig(filename, csvContent1),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("filename"), knownvalue.StringExact(filename)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("content_sha256"), knownvalue.StringExact(sha256Hex(csvContent1))),
				},
			},
			{
				Config: testAccNGSIEMLookupConfig(filename, csvContent2),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("filename"), knownvalue.StringExact(filename)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("content_sha256"), knownvalue.StringExact(sha256Hex(csvContent2))),
				},
			},
		},
	})
}

func TestAccNGSIEMLookupFileResource_jsonFile(t *testing.T) {
	rName := acctest.RandomResourceName()
	filename := rName + ".json"
	resourceName := "crowdstrike_ngsiem_lookup_file.test"

	jsonContent := `{"1": {"name": "alice"}, "2": {"name": "bob"}}`

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccNGSIEMLookupConfig(filename, jsonContent),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("filename"), knownvalue.StringExact(filename)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("content_sha256"), knownvalue.StringExact(sha256Hex(jsonContent))),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"content", "content_sha256"},
			},
		},
	})
}

func TestAccNGSIEMLookupFileResource_assumeUnchanged(t *testing.T) {
	rName := acctest.RandomResourceName()
	filename := rName + ".csv"
	resourceName := "crowdstrike_ngsiem_lookup_file.test"

	csvContent := "user_id,name,region\n1,alice,US\n"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccNGSIEMLookupConfig_assumeUnchanged(filename, csvContent),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("assume_unchanged"), knownvalue.Bool(true)),
				},
			},
		},
	})
}

func TestAccNGSIEMLookupFileResource_invalidExtension(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccNGSIEMLookupConfig("invalid.txt", "some,data\n1,2\n"),
				ExpectError: regexp.MustCompile(`filename must end with`),
			},
		},
	})
}

func TestAccNGSIEMLookupFileResource_reservedPrefix(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccNGSIEMLookupConfig("cs_my_lookup.csv", "some,data\n1,2\n"),
				ExpectError: regexp.MustCompile(`[Rr]eserved.*prefix`),
			},
		},
	})
}

func TestAccNGSIEMLookupFileResource_sha256Mismatch(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccNGSIEMLookupConfig_sha256Mismatch(),
				ExpectError: regexp.MustCompile(`Content SHA256 mismatch`),
			},
		},
	})
}

func testAccNGSIEMLookupConfig(filename, content string) string {
	return fmt.Sprintf(`
resource "crowdstrike_ngsiem_lookup_file" "test" {
  filename       = %[1]q
  repository     = "all"
  content        = %[2]q
  content_sha256 = %[3]q
}
`, filename, content, sha256Hex(content))
}

func TestAccNGSIEMLookupFileResource_filenameRequiresReplace(t *testing.T) {
	rName := acctest.RandomResourceName()
	filename1 := rName + "_v1.csv"
	filename2 := rName + "_v2.csv"
	resourceName := "crowdstrike_ngsiem_lookup_file.test"

	csvContent := "user_id,name,region\n1,alice,US\n"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccNGSIEMLookupConfig(filename1, csvContent),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("filename"), knownvalue.StringExact(filename1)),
				},
			},
			{
				Config: testAccNGSIEMLookupConfig(filename2, csvContent),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("filename"), knownvalue.StringExact(filename2)),
				},
			},
		},
	})
}

func TestAccNGSIEMLookupFileResource_repositoryRequiresReplace(t *testing.T) {
	rName := acctest.RandomResourceName()
	filename := rName + ".csv"
	resourceName := "crowdstrike_ngsiem_lookup_file.test"

	csvContent := "user_id,name,region\n1,alice,US\n"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccNGSIEMLookupConfig_withRepo(filename, csvContent, "all"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("repository"), knownvalue.StringExact("all")),
				},
			},
			{
				Config: testAccNGSIEMLookupConfig_withRepo(filename, csvContent, "falcon"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("repository"), knownvalue.StringExact("falcon")),
				},
			},
		},
	})
}

func TestAccNGSIEMLookupFileResource_importInvalidID(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:            `resource "crowdstrike_ngsiem_lookup_file" "test" {}`,
				ResourceName:     "crowdstrike_ngsiem_lookup_file.test",
				ImportState:      true,
				ImportStateId:    "invalid-no-colon",
				ExpectError:      regexp.MustCompile(`Invalid Import ID`),
			},
		},
	})
}

func testAccNGSIEMLookupConfig_withRepo(filename, content, repository string) string {
	return fmt.Sprintf(`
resource "crowdstrike_ngsiem_lookup_file" "test" {
  filename       = %[1]q
  repository     = %[4]q
  content        = %[2]q
  content_sha256 = %[3]q
}
`, filename, content, sha256Hex(content), repository)
}

func testAccNGSIEMLookupConfig_sha256Mismatch() string {
	return `
resource "crowdstrike_ngsiem_lookup_file" "test" {
  filename       = "test.csv"
  repository     = "all"
  content        = "actual,content"
  content_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
}
`
}

func testAccNGSIEMLookupConfig_assumeUnchanged(filename, content string) string {
	return fmt.Sprintf(`
resource "crowdstrike_ngsiem_lookup_file" "test" {
  filename                  = %[1]q
  repository                = "all"
  content                   = %[2]q
  content_sha256            = %[3]q
  assume_unchanged          = true
}
`, filename, content, sha256Hex(content))
}
