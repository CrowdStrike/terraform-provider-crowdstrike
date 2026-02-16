package usergroup_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccUserGroupResource_Basic(t *testing.T) {
	rName := acctest.RandomResourceName()
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccUserGroupConfig(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_user_group.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_user_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_user_group.test",
						"cid",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_user_group.test",
						"last_updated",
					),
					resource.TestCheckNoResourceAttr(
						"crowdstrike_user_group.test",
						"description",
					),
					resource.TestCheckNoResourceAttr(
						"crowdstrike_user_group.test",
						"user_uuids",
					),
				),
			},
			{
				ResourceName:      "crowdstrike_user_group.test",
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"last_updated",
				},
			},
			{
				Config: testAccUserGroupConfigDescription(rName + "-updated"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_user_group.test",
						"name",
						rName+"-updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_user_group.test",
						"description",
						"Test user group created by Terraform",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_user_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_user_group.test",
						"cid",
					),
					resource.TestCheckNoResourceAttr(
						"crowdstrike_user_group.test",
						"user_uuids",
					),
				),
			},
			{
				Config: testAccUserGroupConfig(rName + "-updated"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_user_group.test",
						"name",
						rName+"-updated",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_user_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_user_group.test",
						"cid",
					),
					resource.TestCheckNoResourceAttr(
						"crowdstrike_user_group.test",
						"description",
					),
					resource.TestCheckNoResourceAttr(
						"crowdstrike_user_group.test",
						"user_uuids",
					),
				),
			},
		},
	})
}

func TestAccUserGroupResource_Members(t *testing.T) {
	userUUIDs := os.Getenv("TF_ACC_USER_GROUP_USER_UUIDS")
	if userUUIDs == "" {
		t.Skip("Skipping test that requires real user UUIDs. Set TF_ACC_USER_GROUP_USER_UUIDS environment variable with comma-separated UUID values to run this test.")
	}

	uuids := strings.Split(userUUIDs, ",")
	if len(uuids) < 2 {
		t.Skip("TF_ACC_USER_GROUP_USER_UUIDS must contain at least 2 comma-separated UUID values")
	}

	uuid1 := strings.TrimSpace(uuids[0])
	uuid2 := strings.TrimSpace(uuids[1])

	rName := acctest.RandomResourceName()
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccUserGroupConfigMembers(rName, []string{uuid1, uuid2}),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_user_group.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_user_group.test",
						"description",
						"Test user group with members",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_user_group.test",
						"user_uuids.#",
						"2",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_user_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_user_group.test",
						"cid",
					),
				),
			},
			{
				Config: testAccUserGroupConfigMembers(rName, []string{uuid1}),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_user_group.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_user_group.test",
						"description",
						"Test user group with members",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_user_group.test",
						"user_uuids.#",
						"1",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_user_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_user_group.test",
						"cid",
					),
				),
			},
			{
				Config: testAccUserGroupConfig(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_user_group.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_user_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_user_group.test",
						"cid",
					),
					resource.TestCheckNoResourceAttr(
						"crowdstrike_user_group.test",
						"description",
					),
					resource.TestCheckNoResourceAttr(
						"crowdstrike_user_group.test",
						"user_uuids",
					),
				),
			},
		},
	})
}

func testAccUserGroupConfig(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_user_group" "test" {
  name = %[1]q
}
`, rName)
}

func testAccUserGroupConfigDescription(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_user_group" "test" {
  name        = %[1]q
  description = "Test user group created by Terraform"
}
`, rName)
}

func testAccUserGroupConfigMembers(rName string, userUUIDs []string) string {
	uuidList := ""
	for i, uuid := range userUUIDs {
		if i > 0 {
			uuidList += ",\n    "
		}
		uuidList += fmt.Sprintf(`"%s"`, uuid)
	}

	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_user_group" "test" {
  name        = %[1]q
  description = "Test user group with members"
  user_uuids = [
    %[2]s
  ]
}
`, rName, uuidList)
}
