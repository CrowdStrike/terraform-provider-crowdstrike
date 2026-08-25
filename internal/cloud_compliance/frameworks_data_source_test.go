package cloudcompliance_test

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

// customFrameworkElement matches the authority, version, and active values every
// custom framework carries.
var customFrameworkElement = knownvalue.ObjectPartial(map[string]knownvalue.Check{
	"authority": knownvalue.StringExact("Custom"),
	"version":   knownvalue.StringExact("1.0"),
	"active":    knownvalue.Bool(false),
})

// frameworksChecks asserts the returned list holds one element per resource, that
// every element carries the custom framework values, and that each resource's id,
// name, and description appear among the elements.
func frameworksChecks(dataSourceName string, resourceNames ...string) []statecheck.StateCheck {
	elements := make(map[int]knownvalue.Check, len(resourceNames))
	for i := range resourceNames {
		elements[i] = customFrameworkElement
	}

	checks := []statecheck.StateCheck{
		statecheck.ExpectKnownValue(
			dataSourceName, tfjsonpath.New("frameworks"),
			knownvalue.ListSizeExact(len(resourceNames)),
		),
		statecheck.ExpectKnownValue(
			dataSourceName, tfjsonpath.New("frameworks"),
			knownvalue.ListPartial(elements),
		),
	}

	for _, resourceName := range resourceNames {
		for _, attribute := range []string{"id", "name", "description"} {
			checks = append(checks, statecheck.CompareValueCollection(
				dataSourceName,
				[]tfjsonpath.Path{tfjsonpath.New("frameworks"), tfjsonpath.New(attribute)},
				resourceName, tfjsonpath.New(attribute),
				compare.ValuesSame(),
			))
		}
	}

	return checks
}

// TestAccCloudComplianceFrameworksDataSource_filterMatch resolves a single
// framework with a name equality filter.
func TestAccCloudComplianceFrameworksDataSource_filterMatch(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_cloud_compliance_custom_framework.test"
	dataSourceName := "data.crowdstrike_cloud_compliance_frameworks.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:            testAccFrameworksDataSourceConfig_byNameFilter(rName, "Data source lookup"),
				ConfigStateChecks: frameworksChecks(dataSourceName, resourceName),
			},
		},
	})
}

// TestAccCloudComplianceFrameworksDataSource_byIDs hydrates an explicit list of
// framework identifiers.
func TestAccCloudComplianceFrameworksDataSource_byIDs(t *testing.T) {
	rName := acctest.RandomResourceName()
	firstResource := "crowdstrike_cloud_compliance_custom_framework.first"
	secondResource := "crowdstrike_cloud_compliance_custom_framework.second"
	dataSourceName := "data.crowdstrike_cloud_compliance_frameworks.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:            testAccFrameworksDataSourceConfig_byIDs(rName),
				ConfigStateChecks: frameworksChecks(dataSourceName, firstResource, secondResource),
			},
		},
	})
}

// TestAccCloudComplianceFrameworksDataSource_multipleMatches covers a filter that
// resolves to more than one framework. Two frameworks share a randomized name
// prefix, so a wildcard filter resolves to exactly those two.
func TestAccCloudComplianceFrameworksDataSource_multipleMatches(t *testing.T) {
	rName := acctest.RandomResourceName()
	firstResource := "crowdstrike_cloud_compliance_custom_framework.first"
	secondResource := "crowdstrike_cloud_compliance_custom_framework.second"
	dataSourceName := "data.crowdstrike_cloud_compliance_frameworks.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:            testAccFrameworksDataSourceConfig_duplicatePrefixLookup(rName),
				ConfigStateChecks: frameworksChecks(dataSourceName, firstResource, secondResource),
			},
		},
	})
}

// TestAccCloudComplianceFrameworksDataSource_noMatch covers a filter that resolves
// to nothing, which returns an empty list.
func TestAccCloudComplianceFrameworksDataSource_noMatch(t *testing.T) {
	dataSourceName := "data.crowdstrike_cloud_compliance_frameworks.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "crowdstrike_cloud_compliance_frameworks" "test" {
  filter = "compliance_framework_name:'tf-acc-nonexistent-custom-framework-that-should-never-exist'"
}
`,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("frameworks"),
						knownvalue.ListSizeExact(0),
					),
				},
			},
		},
	})
}

// TestAccCloudComplianceFrameworksDataSource_validationErrors groups the argument
// validation failures as consecutive ExpectError steps.
func TestAccCloudComplianceFrameworksDataSource_validationErrors(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "crowdstrike_cloud_compliance_frameworks" "test" {
  filter = "   "
}
`,
				ExpectError: regexp.MustCompile("must not be empty or contain only whitespace"),
			},
			{
				Config: `
data "crowdstrike_cloud_compliance_frameworks" "test" {
  filter = "compliance_framework_authority:'CIS'"
  ids    = ["00000000-0000-0000-0000-000000000000"]
}
`,
				ExpectError: regexp.MustCompile("cannot be specified when"),
			},
		},
	})
}

func testAccCloudComplianceFrameworksDataSourceConfig_customFramework(name, description string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_compliance_custom_framework" "test" {
  name        = %[1]q
  description = %[2]q
}
`, name, description)
}

func testAccFrameworksDataSourceConfig_byNameFilter(name, description string) string {
	return testAccCloudComplianceFrameworksDataSourceConfig_customFramework(name, description) + `
data "crowdstrike_cloud_compliance_frameworks" "test" {
  filter = "compliance_framework_name:'${crowdstrike_cloud_compliance_custom_framework.test.name}'"
}
`
}

// testAccFrameworksDataSourceConfig_duplicatePrefix creates two frameworks whose
// names share a randomized prefix so a wildcard filter resolves to both.
func testAccFrameworksDataSourceConfig_duplicatePrefix(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_compliance_custom_framework" "first" {
  name        = "%[1]s-first"
  description = "First framework sharing a name prefix"
}

resource "crowdstrike_cloud_compliance_custom_framework" "second" {
  name        = "%[1]s-second"
  description = "Second framework sharing a name prefix"
}
`, rName)
}

func testAccFrameworksDataSourceConfig_duplicatePrefixLookup(rName string) string {
	return testAccFrameworksDataSourceConfig_duplicatePrefix(rName) + fmt.Sprintf(`
data "crowdstrike_cloud_compliance_frameworks" "test" {
  filter = "compliance_framework_name:*'%[1]s*'"

  depends_on = [
    crowdstrike_cloud_compliance_custom_framework.first,
    crowdstrike_cloud_compliance_custom_framework.second,
  ]
}
`, rName)
}

func testAccFrameworksDataSourceConfig_byIDs(rName string) string {
	return testAccFrameworksDataSourceConfig_duplicatePrefix(rName) + `
data "crowdstrike_cloud_compliance_frameworks" "test" {
  ids = [
    crowdstrike_cloud_compliance_custom_framework.first.id,
    crowdstrike_cloud_compliance_custom_framework.second.id,
  ]
}
`
}
