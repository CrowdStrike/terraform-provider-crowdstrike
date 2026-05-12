package cidgroup_test

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccCIDGroupDataSource_ByID(t *testing.T) {
	rName := acctest.RandomResourceName()
	dataSourceName := "data.crowdstrike_cid_group.test"
	resourceName := "crowdstrike_cid_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCIDGroupDataSourceConfigByID(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(resourceName, "id", dataSourceName, "id"),
					resource.TestCheckResourceAttrPair(resourceName, "name", dataSourceName, "name"),
					resource.TestCheckResourceAttrPair(resourceName, "description", dataSourceName, "description"),
					resource.TestCheckResourceAttrPair(resourceName, "cid", dataSourceName, "cid"),
					resource.TestCheckResourceAttrSet(dataSourceName, "is_default"),
				),
			},
		},
	})
}

func TestAccCIDGroupDataSource_ByName(t *testing.T) {
	rName := acctest.RandomResourceName()
	dataSourceName := "data.crowdstrike_cid_group.test"
	resourceName := "crowdstrike_cid_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCIDGroupDataSourceConfigByName(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(resourceName, "id", dataSourceName, "id"),
					resource.TestCheckResourceAttrPair(resourceName, "name", dataSourceName, "name"),
					resource.TestCheckResourceAttrPair(resourceName, "description", dataSourceName, "description"),
					resource.TestCheckResourceAttrPair(resourceName, "cid", dataSourceName, "cid"),
					resource.TestCheckResourceAttrSet(dataSourceName, "is_default"),
				),
			},
		},
	})
}

func TestAccCIDGroupDataSource_WithMembers(t *testing.T) {
	childCIDs := os.Getenv("TF_ACC_CID_GROUP_CHILD_CIDS")
	if childCIDs == "" {
		t.Skip("Skipping test that requires real child CIDs. Set TF_ACC_CID_GROUP_CHILD_CIDS environment variable with comma-separated CID values to run this test.")
	}

	cids := strings.Split(childCIDs, ",")
	if len(cids) < 1 {
		t.Skip("TF_ACC_CID_GROUP_CHILD_CIDS must contain at least 1 CID value")
	}
	cid1 := strings.TrimSpace(cids[0])

	rName := acctest.RandomResourceName()
	dataSourceName := "data.crowdstrike_cid_group.test"
	resourceName := "crowdstrike_cid_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCIDGroupDataSourceConfigWithMembers(rName, cid1),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(resourceName, "id", dataSourceName, "id"),
					resource.TestCheckResourceAttr(dataSourceName, "cids.#", "1"),
					resource.TestCheckTypeSetElemAttr(dataSourceName, "cids.*", cid1),
				),
			},
		},
	})
}

func TestAccCIDGroupDataSource_ValidationErrors(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		configFunc  func() string
		expectError *regexp.Regexp
	}{
		"neither_id_nor_name": {
			configFunc:  testAccCIDGroupDataSourceConfigNeither,
			expectError: regexp.MustCompile(`No attribute specified when one \(and only one\) of \[name,id\] is required`),
		},
		"both_id_and_name": {
			configFunc:  testAccCIDGroupDataSourceConfigBoth,
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

func TestAccCIDGroupDataSource_NotFound(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccCIDGroupDataSourceConfigNotFoundName(),
				ExpectError: regexp.MustCompile("Resource Not Found"),
			},
		},
	})
}

func testAccCIDGroupDataSourceConfigByID(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cid_group" "test" {
  name        = %[1]q
  description = "Test CID group for data source"
}

data "crowdstrike_cid_group" "test" {
  id = crowdstrike_cid_group.test.id
}
`, rName)
}

func testAccCIDGroupDataSourceConfigByName(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cid_group" "test" {
  name        = %[1]q
  description = "Test CID group for data source"
}

data "crowdstrike_cid_group" "test" {
  name = crowdstrike_cid_group.test.name

  depends_on = [crowdstrike_cid_group.test]
}
`, rName)
}

func testAccCIDGroupDataSourceConfigWithMembers(rName, cid string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cid_group" "test" {
  name        = %[1]q
  description = "Test CID group with members"
  cids        = [%[2]q]
}

data "crowdstrike_cid_group" "test" {
  id = crowdstrike_cid_group.test.id
}
`, rName, cid)
}

func testAccCIDGroupDataSourceConfigNeither() string {
	return acctest.ProviderConfig + `
data "crowdstrike_cid_group" "test" {
}
`
}

func testAccCIDGroupDataSourceConfigBoth() string {
	return acctest.ProviderConfig + `
data "crowdstrike_cid_group" "test" {
  id   = "00000000000000000000000000000001"
  name = "test"
}
`
}

func testAccCIDGroupDataSourceConfigNotFoundName() string {
	return acctest.ProviderConfig + `
data "crowdstrike_cid_group" "test" {
  name = "tf-acc-nonexistent-cid-group-name-that-should-never-exist"
}
`
}
