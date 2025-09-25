package user_test

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestUserAssignmentsResource(t *testing.T) {
	resourceName := "crowdstrike_user_role_assignments.test"
	uid := "terraform_test_user_assign1@crowdstrike.com"
	cid := strings.ToUpper(os.Getenv("FALCON_CID"))
	if len(cid) > 32 {
		cid = cid[:32]
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Testing new resource
			{
				Config: testUserRoleAssignmentConfig(uid, []string{"image_viewer", "falcon_console_guest"}),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "cid", cid),
					resource.TestCheckResourceAttr(resourceName, "uid", uid),
					resource.TestCheckTypeSetElemAttr(resourceName, "assigned_role_ids.*", "image_viewer"),
					resource.TestCheckTypeSetElemAttr(resourceName, "assigned_role_ids.*", "falcon_console_guest"),
					resource.TestCheckResourceAttrSet(resourceName, "uuid"),
				),
			},
			// Testing removals to assigned roles for existing user
			{
				Config: testUserRoleAssignmentConfig(uid, []string{"image_viewer"}),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "cid", cid),
					resource.TestCheckResourceAttr(resourceName, "uid", uid),
					resource.TestCheckResourceAttr(resourceName, "assigned_role_ids.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "assigned_role_ids.*", "image_viewer"),
					resource.TestCheckResourceAttrSet(resourceName, "uuid"),
				),
			},
			// Testing additions to assigned roles for existing user
			{
				Config: testUserRoleAssignmentConfig(uid, []string{"image_viewer", "falcon_console_guest", "falconhost_read_only"}),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "cid", cid),
					resource.TestCheckResourceAttr(resourceName, "uid", uid),
					resource.TestCheckResourceAttr(resourceName, "assigned_role_ids.#", "3"),
					resource.TestCheckTypeSetElemAttr(resourceName, "assigned_role_ids.*", "image_viewer"),
					resource.TestCheckTypeSetElemAttr(resourceName, "assigned_role_ids.*", "falcon_console_guest"),
					resource.TestCheckTypeSetElemAttr(resourceName, "assigned_role_ids.*", "falconhost_read_only"),
					resource.TestCheckResourceAttrSet(resourceName, "uuid"),
				),
			},
			// Manually corrupt the UUID in the state file
			{
				Config: testUserRoleAssignmentConfig(uid, []string{"image_viewer"}),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Corrupt the state manually
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[resourceName]
						if !ok {
							return fmt.Errorf("resource not found: %s", resourceName)
						}

						// Corrupt specific attributes
						rs.Primary.Attributes["uuid"] = "ASDF"
						return nil
					},
				),
			},
			// Validating that the UUID recovered
			{
				Config: testUserRoleAssignmentConfig(uid, []string{"image_viewer"}),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "cid", cid),
					resource.TestCheckResourceAttr(resourceName, "uid", uid),
					resource.TestCheckResourceAttr(resourceName, "assigned_role_ids.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "assigned_role_ids.*", "image_viewer"),
					resource.TestMatchResourceAttr(resourceName, "uuid", regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)),
				),
			},
			// Manually corrupt the UID in the state file
			{
				Config: testUserRoleAssignmentConfig(uid, []string{"image_viewer"}),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Corrupt the state manually
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[resourceName]
						if !ok {
							return fmt.Errorf("resource not found: %s", resourceName)
						}

						// Corrupt specific attributes
						rs.Primary.Attributes["uid"] = "ASDF"
						return nil
					},
				),
			},
			// Validating that the UID recovered
			{
				Config: testUserRoleAssignmentConfig(uid, []string{"image_viewer"}),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "cid", cid),
					resource.TestCheckResourceAttr(resourceName, "uid", uid),
					resource.TestCheckResourceAttr(resourceName, "assigned_role_ids.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "assigned_role_ids.*", "image_viewer"),
					resource.TestCheckResourceAttrSet(resourceName, "uuid"),
				),
			},
			// Manually corrupt the CID in the state file
			{
				Config: testUserRoleAssignmentConfig(uid, []string{"image_viewer"}),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Corrupt the state manually
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[resourceName]
						if !ok {
							return fmt.Errorf("resource not found: %s", resourceName)
						}

						// Corrupt specific attributes
						rs.Primary.Attributes["cid"] = "ASDF"
						return nil
					},
				),
			},
			// Validating that the CID recovered
			{
				Config: testUserRoleAssignmentConfig(uid, []string{"image_viewer"}),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "cid", cid),
					resource.TestCheckResourceAttr(resourceName, "uid", uid),
					resource.TestCheckResourceAttr(resourceName, "assigned_role_ids.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "assigned_role_ids.*", "image_viewer"),
					resource.TestCheckResourceAttrSet(resourceName, "uuid"),
				),
			},
			// Testing Imports
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					rs, ok := s.RootModule().Resources[resourceName]
					if !ok {
						return "", fmt.Errorf("Resource not found: %s", resourceName)
					}
					uuid := rs.Primary.Attributes["uuid"]
					roles := rs.Primary.Attributes["assigned_role_ids"]
					return fmt.Sprintf("%s,%s", uuid, roles), nil
				},
				ImportStateVerifyIdentifierAttribute: "uuid",
				ImportStateVerifyIgnore:              []string{"skip_revoke_on_destroy"},
			},
		},
	})
}

// nolint:unparam
func testUserRoleAssignmentConfig(uid string, roleIds []string) string {
	itemsStr := make([]string, len(roleIds))
	for i, item := range roleIds {
		itemsStr[i] = fmt.Sprintf(`"%s"`, item)
	}
	return fmt.Sprintf(`
resource "crowdstrike_user" "test" {
  uid = "%s"
  first_name = "firstName"
  last_name = "lastName"
}
resource "crowdstrike_user_role_assignments" "test" {
  uid = crowdstrike_user.test.uid
  cid = crowdstrike_user.test.cid
  assigned_role_ids = [%s]
  depends_on = [crowdstrike_user.test]
}
`, uid, strings.Join(itemsStr, ", "))
}

func TestUserRoleAssignmentResource_Validation(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
                resource "crowdstrike_user_role_assignments" "test" {
                    uuid = ""
					assigned_role_ids = ["falcon_console_guest"]
                }
                `,
				ExpectError: regexp.MustCompile(`uuid must be in the format of xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`),
			},
			{
				Config: `
                resource "crowdstrike_user_role_assignments" "test" {
                    uid = "asdf"
					assigned_role_ids = ["falcon_console_guest"]
                }
                `,
				ExpectError: regexp.MustCompile(`Attribute uid must be a valid email address in lowercase`),
			},
			{
				Config: `
			    resource "crowdstrike_user_role_assignments" "test" {
			        uid = "user@crowdstrike"
					assigned_role_ids = ["falcon_console_guest"]
			    }
			    `,
				ExpectError: regexp.MustCompile(`Attribute uid must be a valid email address in lowercase`),
			},
			{
				Config: `
			    resource "crowdstrike_user_role_assignments" "test" {
					uid = "user@crowdstrike.com"
			        cid = "asdfasdfasdfasdfasdfasdfasdfasdf"
					assigned_role_ids = ["falcon_console_guest"]

			    }
			    `,
				ExpectError: regexp.MustCompile(`must be a 32-character hexadecimal string in uppercase`),
			},
			{
				Config: `
			    resource "crowdstrike_user_role_assignments" "test" {
					uid = "user@crowdstrike.com"
			        cid = "ABCD"
					assigned_role_ids = ["falcon_console_guest"]
			    }
			    `,
				ExpectError: regexp.MustCompile(`must be a 32-character hexadecimal string in uppercase`),
			},
			{
				Config: `
			    resource "crowdstrike_user_role_assignments" "test" {
					uid = "user@crowdstrike.com"
			        cid = "ABCDABCDABCDABCDABCDABCDABCDABCD"
					assigned_role_ids = []
			    }
			    `,
				ExpectError: regexp.MustCompile(`set must contain at least 1 elements`),
			},
		},
	})
}
