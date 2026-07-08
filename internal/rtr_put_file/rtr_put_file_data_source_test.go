package rtrputfile_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func testAccRtrPutFileDataSourceWriteTempFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "testfile")
	if err := os.WriteFile(path, []byte("echo hello world"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func rtrPutFileDataSourceStateChecks(resourceName, dataSourceName string) []statecheck.StateCheck {
	attrs := []string{
		"id",
		"name",
		"description",
		"comments_for_audit_log",
		"sha256",
		"file_type",
		"size",
		"platform",
		"permission_type",
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

func TestAccRtrPutFileDataSource_ByName(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_rtr_put_file.test"
	dataSourceName := "data.crowdstrike_rtr_put_file.test"
	sourcePath := testAccRtrPutFileDataSourceWriteTempFile(t)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:            testAccRtrPutFileDataSourceConfigByName(rName, sourcePath),
				ConfigStateChecks: rtrPutFileDataSourceStateChecks(resourceName, dataSourceName),
			},
		},
	})
}

func TestAccRtrPutFileDataSource_ByID(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_rtr_put_file.test"
	dataSourceName := "data.crowdstrike_rtr_put_file.test"
	sourcePath := testAccRtrPutFileDataSourceWriteTempFile(t)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:            testAccRtrPutFileDataSourceConfigByID(rName, sourcePath),
				ConfigStateChecks: rtrPutFileDataSourceStateChecks(resourceName, dataSourceName),
			},
		},
	})
}

func TestAccRtrPutFileDataSource_ValidationErrors(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		configFunc  func() string
		expectError *regexp.Regexp
	}{
		"neither_id_nor_name": {
			configFunc:  testAccRtrPutFileDataSourceConfigNeither,
			expectError: regexp.MustCompile(`No attribute specified when one \(and only one\) of \[name,id\] is required`),
		},
		"both_id_and_name": {
			configFunc:  testAccRtrPutFileDataSourceConfigBoth,
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
						Config:      tc.configFunc(),
						ExpectError: tc.expectError,
					},
				},
			})
		})
	}
}

func TestAccRtrPutFileDataSource_NotFound(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccRtrPutFileDataSourceConfigNotFoundName(),
				ExpectError: regexp.MustCompile("Resource Not Found"),
			},
		},
	})
}

func testAccRtrPutFileDataSourceConfigByName(rName, source string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_rtr_put_file" "test" {
  name                   = %[1]q
  source                 = %[2]q
  description            = "test description"
  comments_for_audit_log = "audit comment"
}

data "crowdstrike_rtr_put_file" "test" {
  name = crowdstrike_rtr_put_file.test.name

  depends_on = [crowdstrike_rtr_put_file.test]
}
`, rName, source)
}

func testAccRtrPutFileDataSourceConfigByID(rName, source string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_rtr_put_file" "test" {
  name                   = %[1]q
  source                 = %[2]q
  description            = "test description"
  comments_for_audit_log = "audit comment"
}

data "crowdstrike_rtr_put_file" "test" {
  id = crowdstrike_rtr_put_file.test.id

  depends_on = [crowdstrike_rtr_put_file.test]
}
`, rName, source)
}

func testAccRtrPutFileDataSourceConfigNeither() string {
	return acctest.ProviderConfig + `
data "crowdstrike_rtr_put_file" "test" {
}
`
}

func testAccRtrPutFileDataSourceConfigBoth() string {
	return acctest.ProviderConfig + `
data "crowdstrike_rtr_put_file" "test" {
  id   = "00000000000000000000000000000001"
  name = "test"
}
`
}

func testAccRtrPutFileDataSourceConfigNotFoundName() string {
	return acctest.ProviderConfig + `
data "crowdstrike_rtr_put_file" "test" {
  name = "tf-acc-nonexistent-rtr-put-file-name-that-should-never-exist"
}
`
}
