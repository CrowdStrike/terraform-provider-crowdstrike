package hostgroups_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccHostGroupDataSource_ByName(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_host_group.test"
	dataSourceName := "data.crowdstrike_host_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccHostGroupDataSourceConfigByName(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(resourceName, "id", dataSourceName, "id"),
					resource.TestCheckResourceAttrPair(resourceName, "name", dataSourceName, "name"),
					resource.TestCheckResourceAttrSet(dataSourceName, "description"),
					resource.TestCheckResourceAttrSet(dataSourceName, "group_type"),
					resource.TestCheckResourceAttrSet(dataSourceName, "created_by"),
					resource.TestCheckResourceAttrSet(dataSourceName, "created_timestamp"),
					resource.TestCheckResourceAttrSet(dataSourceName, "modified_by"),
					resource.TestCheckResourceAttrSet(dataSourceName, "modified_timestamp"),
				),
			},
		},
	})
}

func TestAccHostGroupDataSource_ByID(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_host_group.test"
	dataSourceName := "data.crowdstrike_host_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccHostGroupDataSourceConfigByID(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(resourceName, "id", dataSourceName, "id"),
					resource.TestCheckResourceAttrPair(resourceName, "name", dataSourceName, "name"),
					resource.TestCheckResourceAttrSet(dataSourceName, "description"),
					resource.TestCheckResourceAttrSet(dataSourceName, "group_type"),
				),
			},
		},
	})
}

func TestAccHostGroupDataSource_ValidationErrors(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		configFunc  func() string
		expectError *regexp.Regexp
	}{
		"neither_id_nor_name": {
			configFunc:  testAccHostGroupDataSourceConfigNeither,
			expectError: regexp.MustCompile(`(?i)exactly one of these must be configured`),
		},
		"both_id_and_name": {
			configFunc:  testAccHostGroupDataSourceConfigBoth,
			expectError: regexp.MustCompile(`(?i)these attributes cannot be configured together`),
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

func TestAccHostGroupDataSource_NotFound(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccHostGroupDataSourceConfigNotFoundName(),
				ExpectError: regexp.MustCompile("Host group not found"),
			},
		},
	})
}

// Test config helpers.

func testAccHostGroupDataSourceConfigByName(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name        = %[1]q
  description = "Test host group for singular data source"
  type        = "dynamic"
  assignment_rule = "tags:'FalconGroupingTags/tf-acc-test'+os_version:*'*'"
}

data "crowdstrike_host_group" "test" {
  name = crowdstrike_host_group.test.name

  depends_on = [crowdstrike_host_group.test]
}
`, rName)
}

func testAccHostGroupDataSourceConfigByID(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name        = %[1]q
  description = "Test host group for singular data source"
  type        = "dynamic"
  assignment_rule = "tags:'FalconGroupingTags/tf-acc-test'+os_version:*'*'"
}

data "crowdstrike_host_group" "test" {
  id = crowdstrike_host_group.test.id

  depends_on = [crowdstrike_host_group.test]
}
`, rName)
}

func testAccHostGroupDataSourceConfigNeither() string {
	return acctest.ProviderConfig + `
data "crowdstrike_host_group" "test" {
}
`
}

func testAccHostGroupDataSourceConfigBoth() string {
	return acctest.ProviderConfig + `
data "crowdstrike_host_group" "test" {
  id   = "00000000000000000000000000000001"
  name = "test"
}
`
}

func testAccHostGroupDataSourceConfigNotFoundName() string {
	return acctest.ProviderConfig + `
data "crowdstrike_host_group" "test" {
  name = "tf-acc-nonexistent-host-group-name-that-should-never-exist"
}
`
}
