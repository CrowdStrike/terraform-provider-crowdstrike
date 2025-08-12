package user_test

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/user_management"
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
				ImportStateVerifyIgnore:              []string{"cid", "first_name", "last_name", "uid"},
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
			// Manually corrupt the CID and UID
			{
				Config: testUserConfig_withCID(uidWithCID, "updatedFirstName", "updatedLastName", cid),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Corrupt the state manually
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[resourceNameWithCID]
						if !ok {
							return fmt.Errorf("resource not found: %s", resourceNameWithCID)
						}

						// Corrupt specific attributes
						rs.Primary.Attributes["cid"] = "ASDF"
						rs.Primary.Attributes["uid"] = "ASDF"
						return nil
					},
				),
			},
			// Ensure read fixes the non-UUID drift
			{
				Config: testUserConfig_withCID(uidWithCID, "updatedFirstName", "updatedLastName", cid),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verify state was corrected
					resource.TestCheckResourceAttr(resourceNameWithCID, "cid", cid),
					resource.TestCheckResourceAttr(resourceNameWithCID, "uid", uidWithCID),
				),
			},
			// Manually corrupt the UUID in the state file
			{
				Config: testUserConfig_withCID(uidWithCID, "updatedFirstName", "updatedLastName", cid),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Corrupt the state manually
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[resourceNameWithCID]
						if !ok {
							return fmt.Errorf("resource not found: %s", resourceNameWithCID)
						}

						// Corrupt specific attributes
						rs.Primary.Attributes["uuid"] = "ASDF"
						return nil
					},
				),
			},
			// Ensure read fixes the UUID drift
			{
				Config: testUserConfig_withCID(uidWithCID, "updatedFirstName", "updatedLastName", cid),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verify state was corrected
					resource.TestMatchResourceAttr(resourceNameWithCID, "uuid", regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)),
				),
			},
			// Trigger a destroy and see if the User was actually removed from Falcon
			{
				Config: " ", // Empty string with a space
				Check: resource.ComposeTestCheckFunc(
					testUserDoesNotExist(t, resourceNameWithCID, cid, uidWithCID),
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

// nolint:unparam
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

func TestUserResource_Validation(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
                resource "crowdstrike_user" "test" {
                    uid = "asdf"
					first_name = "firstName"
					last_name = "lastName"
                }
                `,
				ExpectError: regexp.MustCompile(`Attribute uid must be a valid email address in lowercase`),
			},
			{
				Config: `
			    resource "crowdstrike_user" "test" {
			        uid = "user@crowdstrike"
					first_name = "firstName"
					last_name = "lastName"
			    }
			    `,
				ExpectError: regexp.MustCompile(`Attribute uid must be a valid email address in lowercase`),
			},
			{
				Config: `
			    resource "crowdstrike_user" "test" {
					uid = "user@crowdstrike.com"
			        cid = "asdfasdfasdfasdfasdfasdfasdfasdf"
					first_name = "firstName"
					last_name = "lastName"
			    }
			    `,
				ExpectError: regexp.MustCompile(`must be a 32-character hexadecimal string in uppercase`),
			},
			{
				Config: `
			    resource "crowdstrike_user" "test" {
					uid = "user@crowdstrike.com"
			        cid = "ASDF"
					first_name = "firstName"
					last_name = "lastName"
			    }
			    `,
				ExpectError: regexp.MustCompile(`must be a 32-character hexadecimal string in uppercase`),
			},
		},
	})
}

func testUserDoesNotExist(t *testing.T, resource string, cid string, uid string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		// Try to find the resource in state
		_, ok := s.RootModule().Resources[resource]
		if ok {
			return fmt.Errorf("Resource %s still exists in state", resource)
		}

		// Verify resource doesn't exist in backend
		client := acctest.FalconTestClient(t)
		filter := fmt.Sprintf("uid:'%s'+cid:'%s'", uid, strings.ToLower(cid))
		params := &user_management.QueryUserV1Params{
			Context: t.Context(),
			Filter:  &filter,
		}

		resp, err := client.UserManagement.QueryUserV1(params)
		if err != nil {
			return fmt.Errorf("Unable to query user: %s", err)
		}

		if len(resp.GetPayload().Resources) == 0 {
			return nil
		}

		return fmt.Errorf("Resource still exists in backend")
	}
}
