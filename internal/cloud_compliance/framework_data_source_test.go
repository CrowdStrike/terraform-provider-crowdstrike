package cloudcompliance_test

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

// frameworkDataSourceChecks asserts that the id, name, and description the data
// source reports match the framework the resource created, and that the
// remaining computed attributes carry the values a custom framework has. The
// custom framework resource does not expose authority, version, or active.
func frameworkDataSourceChecks(resourceName, dataSourceName string) []statecheck.StateCheck {
	checks := []statecheck.StateCheck{}
	for _, attribute := range []string{"id", "name", "description"} {
		checks = append(checks, statecheck.CompareValuePairs(
			resourceName, tfjsonpath.New(attribute),
			dataSourceName, tfjsonpath.New(attribute),
			compare.ValuesSame(),
		))
	}

	checks = append(checks,
		// Custom frameworks are created under the Custom authority at version 1.0,
		// and are inactive until explicitly activated.
		statecheck.ExpectKnownValue(
			dataSourceName, tfjsonpath.New("authority"),
			knownvalue.StringExact("Custom"),
		),
		statecheck.ExpectKnownValue(
			dataSourceName, tfjsonpath.New("version"),
			knownvalue.StringExact("1.0"),
		),
		statecheck.ExpectKnownValue(
			dataSourceName, tfjsonpath.New("active"),
			knownvalue.Bool(false),
		),
	)

	return checks
}

// TestAccCloudComplianceFrameworkDataSource_basic resolves a single framework
// every way the data source supports: by id, by a name equality filter, by a
// combined name/authority/version filter, and finally proves the name filter is
// case sensitive. All steps read the same framework, so they reuse one created
// resource.
func TestAccCloudComplianceFrameworkDataSource_basic(t *testing.T) {
	// The name carries an uppercase word so the case-sensitivity step is meaningful.
	rName := acctest.RandomResourceName() + "-Alpha"
	resourceName := "crowdstrike_cloud_compliance_custom_framework.test"
	dataSourceName := "data.crowdstrike_cloud_compliance_framework.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccFrameworkDataSourceConfig_byID(rName, "Data source lookup"),
				ConfigStateChecks: append(
					frameworkDataSourceChecks(resourceName, dataSourceName),
					// filter is input-only, so it stays null on an id lookup.
					statecheck.ExpectKnownValue(
						dataSourceName, tfjsonpath.New("filter"),
						knownvalue.Null(),
					),
				),
			},
			{
				Config:            testAccFrameworkDataSourceConfig_byNameFilter(rName, "Data source lookup"),
				ConfigStateChecks: frameworkDataSourceChecks(resourceName, dataSourceName),
			},
			{
				Config:            testAccFrameworkDataSourceConfig_byCombinedFilter(rName, "Data source lookup"),
				ConfigStateChecks: frameworkDataSourceChecks(resourceName, dataSourceName),
			},
			{
				// A lowercased name does not match; equality is case sensitive.
				Config:      testAccFrameworkDataSourceConfig_byLiteralFilter(rName, "Data source lookup", strings.ToLower(rName)),
				ExpectError: regexp.MustCompile("Resource Not Found"),
			},
		},
	})
}

// TestAccCloudComplianceFrameworkDataSource_multipleMatches covers a filter that
// resolves to more than one framework. Custom framework names are unique, so the
// ambiguity comes from a wildcard pattern covering two names sharing a prefix.
func TestAccCloudComplianceFrameworkDataSource_multipleMatches(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccFrameworkDataSourceConfig_duplicatePrefix(rName),
			},
			{
				Config: testAccFrameworkDataSourceConfig_duplicatePrefixLookup(rName),
				// Terraform wraps diagnostic detail, so match the summary only.
				ExpectError: regexp.MustCompile("Multiple compliance frameworks matched"),
			},
		},
	})
}

// TestAccCloudComplianceFrameworkDataSource_notFound covers both lookup paths
// resolving to nothing: a filter that matches no framework, and an id that does
// not exist. Neither step creates anything.
func TestAccCloudComplianceFrameworkDataSource_notFound(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "crowdstrike_cloud_compliance_framework" "test" {
  filter = "compliance_framework_name:'tf-acc-nonexistent-custom-framework-that-should-never-exist'"
}
`,
				ExpectError: regexp.MustCompile("Resource Not Found"),
			},
			{
				Config: `
data "crowdstrike_cloud_compliance_framework" "test" {
  id = "00000000-0000-0000-0000-000000000000"
}
`,
				ExpectError: regexp.MustCompile("Resource Not Found"),
			},
		},
	})
}

// TestAccCloudComplianceFrameworkDataSource_validationErrors groups the argument
// validation failures as consecutive ExpectError steps; none create anything.
func TestAccCloudComplianceFrameworkDataSource_validationErrors(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "crowdstrike_cloud_compliance_framework" "test" {}
`,
				ExpectError: regexp.MustCompile(`No attribute specified when one \(and only one\) of \[filter,id\] is required`),
			},
			{
				Config: `
data "crowdstrike_cloud_compliance_framework" "test" {
  id     = "00000000-0000-0000-0000-000000000000"
  filter = "compliance_framework_name:'some-framework'"
}
`,
				ExpectError: regexp.MustCompile(`2 attributes specified when one \(and only one\) of \[filter,id\] is required`),
			},
			{
				Config: `
data "crowdstrike_cloud_compliance_framework" "test" {
  id = "   "
}
`,
				ExpectError: regexp.MustCompile("must not be empty or contain only whitespace"),
			},
			{
				Config: `
data "crowdstrike_cloud_compliance_framework" "test" {
  filter = "   "
}
`,
				ExpectError: regexp.MustCompile("must not be empty or contain only whitespace"),
			},
		},
	})
}

// testAccCloudComplianceFrameworkDataSourceConfig_customFramework returns the
// custom framework a lookup test resolves against. The data source reads only
// framework-level attributes, so the framework carries no sections.
func testAccCloudComplianceFrameworkDataSourceConfig_customFramework(name, description string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_compliance_custom_framework" "test" {
  name        = %[1]q
  description = %[2]q
}
`, name, description)
}

func testAccFrameworkDataSourceConfig_byID(name, description string) string {
	return testAccCloudComplianceFrameworkDataSourceConfig_customFramework(name, description) + `
data "crowdstrike_cloud_compliance_framework" "test" {
  id = crowdstrike_cloud_compliance_custom_framework.test.id
}
`
}

func testAccFrameworkDataSourceConfig_byNameFilter(name, description string) string {
	return testAccCloudComplianceFrameworkDataSourceConfig_customFramework(name, description) + `
data "crowdstrike_cloud_compliance_framework" "test" {
  filter = "compliance_framework_name:'${crowdstrike_cloud_compliance_custom_framework.test.name}'"
}
`
}

func testAccFrameworkDataSourceConfig_byCombinedFilter(name, description string) string {
	return testAccCloudComplianceFrameworkDataSourceConfig_customFramework(name, description) + `
data "crowdstrike_cloud_compliance_framework" "test" {
  filter = "compliance_framework_name:'${crowdstrike_cloud_compliance_custom_framework.test.name}'+compliance_framework_authority:'Custom'+compliance_framework_version:'1.0'"
}
`
}

// testAccFrameworkDataSourceConfig_byLiteralFilter looks the framework up with a
// caller-supplied literal name, used to prove case sensitivity.
func testAccFrameworkDataSourceConfig_byLiteralFilter(name, description, lookupName string) string {
	return testAccCloudComplianceFrameworkDataSourceConfig_customFramework(name, description) + fmt.Sprintf(`
data "crowdstrike_cloud_compliance_framework" "test" {
  filter = "compliance_framework_name:'%[1]s'"

  depends_on = [crowdstrike_cloud_compliance_custom_framework.test]
}
`, lookupName)
}

// testAccFrameworkDataSourceConfig_duplicatePrefix creates two frameworks whose
// names share a prefix so a wildcard filter resolves to both. Neither carries
// sections, since only the framework names matter to this test.
func testAccFrameworkDataSourceConfig_duplicatePrefix(rName string) string {
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

func testAccFrameworkDataSourceConfig_duplicatePrefixLookup(rName string) string {
	return testAccFrameworkDataSourceConfig_duplicatePrefix(rName) + fmt.Sprintf(`
data "crowdstrike_cloud_compliance_framework" "test" {
  filter = "compliance_framework_name:*'%[1]s*'"
}
`, rName)
}
