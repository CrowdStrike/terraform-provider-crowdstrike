package cidgroup_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccCIDGroupResource_Basic(t *testing.T) {
	rName := acctest.RandomResourceName()
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCIDGroupConfig(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_cid_group.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_cid_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_cid_group.test",
						"cid",
					),
					resource.TestCheckNoResourceAttr(
						"crowdstrike_cid_group.test",
						"description",
					),
					resource.TestCheckNoResourceAttr(
						"crowdstrike_cid_group.test",
						"cids",
					),
				),
			},
			{
				ResourceName:      "crowdstrike_cid_group.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccCIDGroupConfigDescription(rName + "-updated"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_cid_group.test",
						"name",
						rName+"-updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_cid_group.test",
						"description",
						"Test CID group created by Terraform",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_cid_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_cid_group.test",
						"cid",
					),
					resource.TestCheckNoResourceAttr(
						"crowdstrike_cid_group.test",
						"cids",
					),
				),
			},
			{
				Config: testAccCIDGroupConfig(rName + "-updated"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_cid_group.test",
						"name",
						rName+"-updated",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_cid_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_cid_group.test",
						"cid",
					),
					resource.TestCheckNoResourceAttr(
						"crowdstrike_cid_group.test",
						"description",
					),
					resource.TestCheckNoResourceAttr(
						"crowdstrike_cid_group.test",
						"cids",
					),
				),
			},
		},
	})
}

func TestAccCIDGroupResource_Members(t *testing.T) {
	childCIDs := os.Getenv("TF_ACC_CID_GROUP_CHILD_CIDS")
	if childCIDs == "" {
		t.Skip("Skipping test that requires real child CIDs. Set TF_ACC_CID_GROUP_CHILD_CIDS environment variable with comma-separated CID values to run this test.")
	}

	cids := strings.Split(childCIDs, ",")
	if len(cids) < 2 {
		t.Skip("TF_ACC_CID_GROUP_CHILD_CIDS must contain at least 2 comma-separated CID values")
	}

	cid1 := strings.TrimSpace(cids[0])
	cid2 := strings.TrimSpace(cids[1])

	rName := acctest.RandomResourceName()
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCIDGroupConfigMembers(rName, []string{cid1, cid2}),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_cid_group.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_cid_group.test",
						"description",
						"Test CID group with members",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_cid_group.test",
						"cids.#",
						"2",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_cid_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_cid_group.test",
						"cid",
					),
				),
			},
			{
				Config: testAccCIDGroupConfigMembers(rName, []string{cid1}),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_cid_group.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_cid_group.test",
						"description",
						"Test CID group with members",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_cid_group.test",
						"cids.#",
						"1",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_cid_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_cid_group.test",
						"cid",
					),
				),
			},
			{
				Config: testAccCIDGroupConfig(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_cid_group.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_cid_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_cid_group.test",
						"cid",
					),
					resource.TestCheckNoResourceAttr(
						"crowdstrike_cid_group.test",
						"description",
					),
					resource.TestCheckNoResourceAttr(
						"crowdstrike_cid_group.test",
						"cids",
					),
				),
			},
		},
	})
}

func testAccCIDGroupConfig(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cid_group" "test" {
  name = %[1]q
}
`, rName)
}

func testAccCIDGroupConfigDescription(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cid_group" "test" {
  name        = %[1]q
  description = "Test CID group created by Terraform"
}
`, rName)
}

func testAccCIDGroupConfigMembers(rName string, cids []string) string {
	cidList := ""
	for i, cid := range cids {
		if i > 0 {
			cidList += ",\n    "
		}
		cidList += fmt.Sprintf(`"%s"`, cid)
	}

	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cid_group" "test" {
  name        = %[1]q
  description = "Test CID group with members"
  cids = [
    %[2]s
  ]
}
`, rName, cidList)
}
