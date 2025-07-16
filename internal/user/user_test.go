package user_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestUserResource(t *testing.T) {
	resourceNameNoCID := "crowdstrike_user.testNoCID"
	resourceNameWithCID := "crowdstrike_user.testWithCID"
	uidNoCID := "terraform_test_user_2@crowdstrike.com"
	uidWithCID := "terraform_test_user_3@crowdstrike.com"
	firstName := "firstName"
	lastName := "lastName"
	cid := strings.ToUpper(os.Getenv("FALCON_CID"))
	if len(cid) > 32 {
		cid = cid[:32]
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Testing user without passing the CID. This defaults to the CID attached to the API credentials.
			{
				Config: testUserConfig_noCID(uidNoCID, firstName, lastName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameNoCID, "cid", cid),
					resource.TestCheckResourceAttr(resourceNameNoCID, "first_name", firstName),
					resource.TestCheckResourceAttr(resourceNameNoCID, "last_name", lastName),
					resource.TestCheckResourceAttr(resourceNameNoCID, "uid", uidNoCID),
					resource.TestCheckResourceAttrSet(resourceNameNoCID, "uuid"),
				),
			},
			// Import testing
			{
				ResourceName:                         resourceNameNoCID,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "uuid",
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					rs, ok := s.RootModule().Resources[resourceNameNoCID]
					if !ok {
						return "", fmt.Errorf("Resource not found: %s", resourceNameNoCID)
					}
					return rs.Primary.Attributes["uuid"], nil
				},
			},
			// Testing user with the CID.
			{
				Config: testUserConfig_withCID(uidWithCID, firstName, lastName, cid),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameWithCID, "cid", cid),
					resource.TestCheckResourceAttr(resourceNameWithCID, "first_name", firstName),
					resource.TestCheckResourceAttr(resourceNameWithCID, "last_name", lastName),
					resource.TestCheckResourceAttr(resourceNameWithCID, "uid", uidWithCID),
					resource.TestCheckResourceAttrSet(resourceNameWithCID, "uuid"),
				),
			},
			// Testing user update
			{
				Config: testUserConfig_withCID(uidWithCID, "updatedFirstName", "updatedLastName", cid),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameWithCID, "cid", cid),
					resource.TestCheckResourceAttr(resourceNameWithCID, "first_name", "updatedFirstName"),
					resource.TestCheckResourceAttr(resourceNameWithCID, "last_name", "updatedLastName"),
					resource.TestCheckResourceAttr(resourceNameWithCID, "uid", uidWithCID),
					resource.TestCheckResourceAttrSet(resourceNameWithCID, "uuid"),
				),
			},
		},
	})
}

func testUserConfig_noCID(uid string, firstName string, lastName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_user" "testNoCID" {
  uid = "%s"
  first_name = "%s"
  last_name = "%s"
}
`, uid, firstName, lastName)
}

func testUserConfig_withCID(uid string, firstName string, lastName string, cid string) string {
	return fmt.Sprintf(`
resource "crowdstrike_user" "testWithCID" {
  uid = "%s"
  first_name = "%s"
  last_name = "%s"
  cid = "%s"
}
`, uid, firstName, lastName, cid)
}
