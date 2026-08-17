package cloudgroup_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccCloudGroupDataSource_ByID(t *testing.T) {
	rName := acctest.RandomResourceName()
	dataSourceName := "data.crowdstrike_cloud_group.test"
	resourceName := "crowdstrike_cloud_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudGroupDataSourceConfigByID(rName),
				ConfigStateChecks: append(
					cloudGroupDataSourceAttributeChecks(resourceName, dataSourceName),
					// filter is input only, so it stays null on an ID lookup.
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("filter"),
						knownvalue.Null(),
					),
				),
			},
		},
	})
}

func TestAccCloudGroupDataSource_ByFilter(t *testing.T) {
	rName := acctest.RandomResourceName()
	dataSourceName := "data.crowdstrike_cloud_group.test"
	resourceName := "crowdstrike_cloud_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudGroupDataSourceConfigByFilter(rName),
				ConfigStateChecks: append(
					cloudGroupDataSourceAttributeChecks(resourceName, dataSourceName),
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("filter"),
						knownvalue.StringExact(fmt.Sprintf("name:'%s'", rName)),
					),
				),
			},
		},
	})
}

// TestAccCloudGroupDataSource_ByFilterMatching locks in the value matching rules
// the filter documentation promises: FQL special characters are matched literally
// and must not be backslash escaped, the match covers the whole value, and `name`
// is the only property matched case insensitively.
func TestAccCloudGroupDataSource_ByFilterMatching(t *testing.T) {
	// Cloud group names accept spaces and - _ : ; . ! ( ) & [ ], several of
	// which are FQL special characters.
	rName := acctest.RandomResourceName() + ": EU (west)"
	rDescription := "Desc " + rName
	dataSourceName := "data.crowdstrike_cloud_group.test"
	resourceName := "crowdstrike_cloud_group.test"

	resolvesToGroup := func(extra ...statecheck.StateCheck) []statecheck.StateCheck {
		return append([]statecheck.StateCheck{
			statecheck.CompareValuePairs(
				resourceName, tfjsonpath.New("id"),
				dataSourceName, tfjsonpath.New("id"),
				compare.ValuesSame(),
			),
		}, extra...)
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				// The special characters go into the filter unescaped.
				Config: testAccCloudGroupDataSourceConfigMatching(rName, rDescription, fmt.Sprintf("name:'%s'", rName)),
				ConfigStateChecks: resolvesToGroup(
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("name"),
						knownvalue.StringExact(rName),
					),
				),
			},
			{
				// Name matching covers the whole value and is case insensitive.
				Config:            testAccCloudGroupDataSourceConfigMatching(rName, rDescription, fmt.Sprintf("name:'%s'", strings.ToUpper(rName))),
				ConfigStateChecks: resolvesToGroup(),
			},
			{
				// Backslash escaping the special characters matches nothing.
				Config:      testAccCloudGroupDataSourceConfigMatching(rName, rDescription, fmt.Sprintf("name:'%s'", escapeFQLSpecials(rName))),
				ExpectError: regexp.MustCompile(`No cloud group matched the filter`),
			},
			{
				// description matches the whole value too.
				Config:            testAccCloudGroupDataSourceConfigMatching(rName, rDescription, fmt.Sprintf("description:'%s'", rDescription)),
				ConfigStateChecks: resolvesToGroup(),
			},
			{
				// Unlike name, description is case sensitive.
				Config:      testAccCloudGroupDataSourceConfigMatching(rName, rDescription, fmt.Sprintf("description:'%s'", strings.ToLower(rDescription))),
				ExpectError: regexp.MustCompile(`No cloud group matched the filter`),
			},
		},
	})
}

func TestAccCloudGroupDataSource_ValidationErrors(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		config      string
		expectError *regexp.Regexp
	}{
		"neither_id_nor_filter": {
			config: acctest.ProviderConfig + `
data "crowdstrike_cloud_group" "test" {
}
`,
			expectError: regexp.MustCompile(`No attribute specified when one \(and only one\) of \[filter,id\] is required`),
		},
		"both_id_and_filter": {
			config: acctest.ProviderConfig + `
data "crowdstrike_cloud_group" "test" {
  id     = "00000000-0000-0000-0000-000000000000"
  filter = "name:'some-name'"
}
`,
			expectError: regexp.MustCompile(`2 attributes specified when one \(and only one\) of \[filter,id\] is required`),
		},
		"empty_id": {
			config: acctest.ProviderConfig + `
data "crowdstrike_cloud_group" "test" {
  id = ""
}
`,
			expectError: regexp.MustCompile(`Attribute id string length must be at least 1`),
		},
		"empty_filter": {
			config: acctest.ProviderConfig + `
data "crowdstrike_cloud_group" "test" {
  filter = ""
}
`,
			expectError: regexp.MustCompile(`Attribute filter string length must be at least 1`),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			resource.ParallelTest(t, resource.TestCase{
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				PreCheck:                 func() { acctest.PreCheck(t) },
				Steps: []resource.TestStep{
					{
						Config:      tc.config,
						ExpectError: tc.expectError,
					},
				},
			})
		})
	}
}

func TestAccCloudGroupDataSource_NotFoundByID(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccCloudGroupDataSourceConfigNotFoundByID(),
				ExpectError: regexp.MustCompile(`No cloud group found with ID`),
			},
		},
	})
}

func TestAccCloudGroupDataSource_NotFoundByFilter(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccCloudGroupDataSourceConfigNotFoundByFilter(),
				ExpectError: regexp.MustCompile(`No cloud group matched the filter`),
			},
		},
	})
}

// TestAccCloudGroupDataSource_MultipleMatches covers a filter that resolves to
// more than one group. Group names are unique within a CID, so two groups cannot
// share the name an equality filter would match: the ambiguity has to come from
// another property. business_unit is free text and is filterable, so two groups
// can share one.
func TestAccCloudGroupDataSource_MultipleMatches(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudGroupDataSourceConfigSharedBusinessUnit(rName),
			},
			{
				Config: testAccCloudGroupDataSourceConfigSharedBusinessUnitLookup(rName),
				// Terraform wraps diagnostic detail, so match the summary only.
				ExpectError: regexp.MustCompile(`Multiple cloud groups matched`),
			},
		},
	})
}

func TestAccCloudGroupDataSource_InvalidFilter(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccCloudGroupDataSourceConfigInvalidFilter(),
				ExpectError: regexp.MustCompile(`400 Bad Request`),
			},
		},
	})
}

// cloudGroupDataSourceAttributeChecks asserts that every attribute the data
// source reads matches the resource that created the group.
func cloudGroupDataSourceAttributeChecks(resourceName, dataSourceName string) []statecheck.StateCheck {
	attributes := []string{
		"id",
		"name",
		"description",
		"business_impact",
		"business_unit",
		"environment",
		"owners",
		"aws",
		"azure",
		"gcp",
		"images",
		"created_at",
		"created_by",
	}

	checks := make([]statecheck.StateCheck, 0, len(attributes))
	for _, attribute := range attributes {
		checks = append(checks, statecheck.CompareValuePairs(
			resourceName, tfjsonpath.New(attribute),
			dataSourceName, tfjsonpath.New(attribute),
			compare.ValuesSame(),
		))
	}

	return checks
}

// Test config helpers.

// testAccCloudGroupDataSourceConfigGroup creates a group populating every
// attribute the data source reads back.
func testAccCloudGroupDataSourceConfigGroup(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name            = %[1]q
  description     = "Data source lookup test"
  business_impact = "high"
  business_unit   = "Security Operations"
  environment     = "prod"
  owners          = ["test@example.com"]

  aws = {
    account_ids = ["123456789012"]
    filters = {
      region = ["us-west-2"]
      tags   = ["Environment=Production"]
    }
  }

  images = [
    {
      registry     = "docker.io"
      repositories = ["nginx"]
      tags         = ["latest"]
    }
  ]
}
`, rName)
}

func testAccCloudGroupDataSourceConfigByID(rName string) string {
	return testAccCloudGroupDataSourceConfigGroup(rName) + `
data "crowdstrike_cloud_group" "test" {
  id = crowdstrike_cloud_group.test.id
}
`
}

func testAccCloudGroupDataSourceConfigByFilter(rName string) string {
	return testAccCloudGroupDataSourceConfigGroup(rName) + fmt.Sprintf(`
data "crowdstrike_cloud_group" "test" {
  filter = "name:'%[1]s'"

  depends_on = [crowdstrike_cloud_group.test]
}
`, rName)
}

// escapeFQLSpecials backslash escapes the FQL special characters a cloud group
// name is allowed to contain. The API matches these characters literally, so an
// escaped filter finds nothing. Only a single quote genuinely needs escaping, and
// a group name cannot contain one.
func escapeFQLSpecials(s string) string {
	replacer := strings.NewReplacer(
		":", `\:`,
		"!", `\!`,
		"(", `\(`,
		")", `\)`,
		"[", `\[`,
		"]", `\]`,
	)
	return replacer.Replace(s)
}

// testAccCloudGroupDataSourceConfigMatching creates a group with the given name
// and description, then looks it up with the given FQL filter, so a test can vary
// the filter independently of the group it created.
func testAccCloudGroupDataSourceConfigMatching(name, description, filter string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name        = %[1]q
  description = %[2]q
}

data "crowdstrike_cloud_group" "test" {
  filter = %[3]q

  depends_on = [crowdstrike_cloud_group.test]
}
`, name, description, filter)
}

func testAccCloudGroupDataSourceConfigNotFoundByID() string {
	// A well-formed UUID that does not exist. The API rejects IDs that are not
	// valid UUIDs with a 400, which would not exercise the not found path.
	return acctest.ProviderConfig + `
data "crowdstrike_cloud_group" "test" {
  id = "00000000-0000-0000-0000-000000000000"
}
`
}

func testAccCloudGroupDataSourceConfigNotFoundByFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_cloud_group" "test" {
  filter = "name:'tf-acc-test-nonexistent-cloud-group-that-should-never-exist'"
}
`
}

// testAccCloudGroupDataSourceConfigSharedBusinessUnit creates two groups that
// share a business_unit but have distinct names.
func testAccCloudGroupDataSourceConfigSharedBusinessUnit(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "first" {
  name          = "%[1]s-first"
  business_unit = %[1]q
}

resource "crowdstrike_cloud_group" "second" {
  name          = "%[1]s-second"
  business_unit = %[1]q
}
`, rName)
}

func testAccCloudGroupDataSourceConfigSharedBusinessUnitLookup(rName string) string {
	return testAccCloudGroupDataSourceConfigSharedBusinessUnit(rName) + fmt.Sprintf(`
data "crowdstrike_cloud_group" "test" {
  filter = "business_unit:'%[1]s'"
}
`, rName)
}

func testAccCloudGroupDataSourceConfigInvalidFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_cloud_group" "test" {
  filter = "this is not a valid fql filter"
}
`
}
