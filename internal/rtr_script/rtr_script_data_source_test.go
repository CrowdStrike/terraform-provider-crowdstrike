package rtrscript_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccRTRScriptDataSource_ByName(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_rtr_script.test"
	dataSourceName := "data.crowdstrike_rtr_script.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:            testAccRTRScriptDataSourceConfig_byName(rName),
				ConfigStateChecks: rtrScriptDataSourceStateChecks(resourceName, dataSourceName),
			},
		},
	})
}

func TestAccRTRScriptDataSource_ByID(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_rtr_script.test"
	dataSourceName := "data.crowdstrike_rtr_script.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:            testAccRTRScriptDataSourceConfig_byID(rName),
				ConfigStateChecks: rtrScriptDataSourceStateChecks(resourceName, dataSourceName),
			},
		},
	})
}

func TestAccRTRScriptDataSource_ValidationErrors(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		config      string
		expectError *regexp.Regexp
	}{
		"neither_id_nor_name": {
			config:      testAccRTRScriptDataSourceConfig_neither(),
			expectError: regexp.MustCompile(`No attribute specified when one \(and only one\) of \[name,id\] is required`),
		},
		"both_id_and_name": {
			config:      testAccRTRScriptDataSourceConfig_both(),
			expectError: regexp.MustCompile(`2 attributes specified when one \(and only one\) of \[name,id\] is required`),
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

func TestAccRTRScriptDataSource_NotFound(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccRTRScriptDataSourceConfig_notFoundName(),
				ExpectError: regexp.MustCompile("Resource Not Found"),
			},
		},
	})
}

func rtrScriptDataSourceStateChecks(resourceName, dataSourceName string) []statecheck.StateCheck {
	attrs := []string{
		"id",
		"name",
		"description",
		"content",
		"platform_name",
		"permission_type",
		"sha256",
		"size",
		"created_by",
		"created_timestamp",
		"modified_by",
		"modified_timestamp",
	}

	checks := make([]statecheck.StateCheck, 0, len(attrs))
	for _, a := range attrs {
		checks = append(checks, statecheck.CompareValuePairs(
			resourceName, tfjsonpath.New(a),
			dataSourceName, tfjsonpath.New(a),
			compare.ValuesSame(),
		))
	}
	return checks
}

func testAccRTRScriptDataSourceConfig_byName(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_rtr_script" "test" {
  name            = %[1]q
  description     = "Test RTR script for singular data source"
  content         = "echo 'hello world'"
  platform_name   = "Linux"
  permission_type = "private"
}

data "crowdstrike_rtr_script" "test" {
  name = crowdstrike_rtr_script.test.name

  depends_on = [crowdstrike_rtr_script.test]
}
`, rName)
}

func testAccRTRScriptDataSourceConfig_byID(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_rtr_script" "test" {
  name            = %[1]q
  description     = "Test RTR script for singular data source"
  content         = "echo 'hello world'"
  platform_name   = "Linux"
  permission_type = "private"
}

data "crowdstrike_rtr_script" "test" {
  id = crowdstrike_rtr_script.test.id

  depends_on = [crowdstrike_rtr_script.test]
}
`, rName)
}

func testAccRTRScriptDataSourceConfig_neither() string {
	return acctest.ProviderConfig + `
data "crowdstrike_rtr_script" "test" {
}
`
}

func testAccRTRScriptDataSourceConfig_both() string {
	return acctest.ProviderConfig + `
data "crowdstrike_rtr_script" "test" {
  id   = "00000000000000000000000000000001"
  name = "test"
}
`
}

func testAccRTRScriptDataSourceConfig_notFoundName() string {
	return acctest.ProviderConfig + `
data "crowdstrike_rtr_script" "test" {
  name = "tf-acc-nonexistent-rtr-script-name-that-should-never-exist"
}
`
}
