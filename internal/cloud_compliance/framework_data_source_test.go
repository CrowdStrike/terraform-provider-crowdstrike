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

const (
	frameworkDataSourceName         = "data.crowdstrike_cloud_compliance_framework.test"
	frameworkDataSourceResourceName = "crowdstrike_cloud_compliance_custom_framework.test"
)

// frameworkDataSourceFramework is the custom framework every data source test
// looks up.
func frameworkDataSourceFramework(name, description string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_compliance_custom_framework" "test" {
  name        = %[1]q
  description = %[2]q
  sections = {
    "section-1" = {
      name = "Section 1"
      controls = {
        "control-1" = {
          name        = "Control 1"
          description = "The first control"
          rules       = []
        }
      }
    }
  }
}
`, name, description)
}

func testAccFrameworkDataSourceConfigByID(name, description string) string {
	return acctest.ProviderConfig + frameworkDataSourceFramework(name, description) + `
data "crowdstrike_cloud_compliance_framework" "test" {
  id = crowdstrike_cloud_compliance_custom_framework.test.id
}
`
}

func testAccFrameworkDataSourceConfigByFilter(name, description string) string {
	return acctest.ProviderConfig + frameworkDataSourceFramework(name, description) + fmt.Sprintf(`
data "crowdstrike_cloud_compliance_framework" "test" {
  filter = "compliance_framework_name:'%[1]s'"

  depends_on = [crowdstrike_cloud_compliance_custom_framework.test]
}
`, name)
}

// testAccFrameworkDataSourceConfigByFilterWrongCase keeps the framework in
// place but looks it up with a lowercased name, which the API does not match
// because compliance_framework_name equality is case sensitive.
func testAccFrameworkDataSourceConfigByFilterWrongCase(name, description string) string {
	return acctest.ProviderConfig + frameworkDataSourceFramework(name, description) + fmt.Sprintf(`
data "crowdstrike_cloud_compliance_framework" "test" {
  filter = "compliance_framework_name:'%[1]s'"

  depends_on = [crowdstrike_cloud_compliance_custom_framework.test]
}
`, strings.ToLower(name))
}

// frameworkDataSourceComparisons asserts that every attribute the data
// source reports matches the framework the resource created.
func frameworkDataSourceComparisons() []statecheck.StateCheck {
	var checks []statecheck.StateCheck
	for _, attribute := range []string{"id", "name", "description", "sections"} {
		checks = append(checks, statecheck.CompareValuePairs(
			frameworkDataSourceResourceName, tfjsonpath.New(attribute),
			frameworkDataSourceName, tfjsonpath.New(attribute),
			compare.ValuesSame(),
		))
	}

	return checks
}

func TestAccCloudComplianceFrameworkDataSource_ByID(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccFrameworkDataSourceConfigByID(rName, "Data source lookup by id"),
				ConfigStateChecks: append(
					frameworkDataSourceComparisons(),
					// filter is input-only, so it stays null on an ID lookup.
					statecheck.ExpectKnownValue(
						frameworkDataSourceName, tfjsonpath.New("filter"),
						knownvalue.Null(),
					),
				),
			},
		},
	})
}

func TestAccCloudComplianceFrameworkDataSource_ByFilter(t *testing.T) {
	// The name carries an uppercase word so the second step can prove that
	// compliance_framework_name equality is case sensitive.
	rName := acctest.RandomResourceName() + "-Alpha"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:            testAccFrameworkDataSourceConfigByFilter(rName, "Data source lookup by filter"),
				ConfigStateChecks: frameworkDataSourceComparisons(),
			},
			{
				Config:      testAccFrameworkDataSourceConfigByFilterWrongCase(rName, "Data source lookup by filter"),
				ExpectError: regexp.MustCompile("Resource Not Found"),
			},
		},
	})
}

// TestAccCloudComplianceFrameworkDataSource_MultipleMatches covers a filter
// that resolves to more than one framework. Custom framework names are unique, so
// the ambiguity has to come from a wildcard pattern covering two names.
func TestAccCloudComplianceFrameworkDataSource_MultipleMatches(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccFrameworkDataSourceConfigDuplicatePrefix(rName),
			},
			{
				Config: testAccFrameworkDataSourceConfigDuplicatePrefixLookup(rName),
				// Terraform wraps diagnostic detail, so match the summary only.
				ExpectError: regexp.MustCompile("Multiple compliance frameworks matched"),
			},
		},
	})
}

func TestAccCloudComplianceFrameworkDataSource_NotFound(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + `
data "crowdstrike_cloud_compliance_framework" "test" {
  filter = "compliance_framework_name:'tf-acc-nonexistent-custom-framework-that-should-never-exist'"
}
`,
				ExpectError: regexp.MustCompile("Resource Not Found"),
			},
		},
	})
}

func TestAccCloudComplianceFrameworkDataSource_ValidationErrors(t *testing.T) {
	validationTests := map[string]struct {
		config      string
		expectError *regexp.Regexp
	}{
		"neither_id_nor_filter": {
			config: `
data "crowdstrike_cloud_compliance_framework" "test" {}
`,
			expectError: regexp.MustCompile(`No attribute specified when one \(and only one\) of \[filter,id\] is required`),
		},
		"both_id_and_filter": {
			config: `
data "crowdstrike_cloud_compliance_framework" "test" {
  id     = "00000000-0000-0000-0000-000000000000"
  filter = "compliance_framework_name:'some-framework'"
}
`,
			expectError: regexp.MustCompile(`2 attributes specified when one \(and only one\) of \[filter,id\] is required`),
		},
	}

	for name, tc := range validationTests {
		t.Run(name, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { acctest.PreCheck(t) },
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config:      acctest.ProviderConfig + tc.config,
						ExpectError: tc.expectError,
					},
				},
			})
		})
	}
}

// testAccFrameworkDataSourceConfigDuplicatePrefix creates two frameworks
// whose names share a prefix.
func testAccFrameworkDataSourceConfigDuplicatePrefix(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_compliance_custom_framework" "first" {
  name        = "%[1]s-first"
  description = "First framework sharing a name prefix"
  sections = {
    "section-1" = {
      name = "Section 1"
      controls = {
        "control-1" = {
          name        = "Control 1"
          description = "The first control"
          rules       = []
        }
      }
    }
  }
}

resource "crowdstrike_cloud_compliance_custom_framework" "second" {
  name        = "%[1]s-second"
  description = "Second framework sharing a name prefix"
  sections = {
    "section-1" = {
      name = "Section 1"
      controls = {
        "control-1" = {
          name        = "Control 1"
          description = "The first control"
          rules       = []
        }
      }
    }
  }
}
`, rName)
}

func testAccFrameworkDataSourceConfigDuplicatePrefixLookup(rName string) string {
	return testAccFrameworkDataSourceConfigDuplicatePrefix(rName) + fmt.Sprintf(`
data "crowdstrike_cloud_compliance_framework" "test" {
  filter = "compliance_framework_name:*'%[1]s*'"
}
`, rName)
}
