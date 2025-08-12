package user_test

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestUserDataSource(t *testing.T) {
	dataSourceUidWithCID := "data.crowdstrike_user.uidWithCID"
	dataSourceUidWithoutCID := "data.crowdstrike_user.uidWithoutCID"
	dataSourceWithUUID := "data.crowdstrike_user.withUUID"
	dataSourcewithUUIDandUID := "data.crowdstrike_user.withUUIDandUID"

	uidWithUUID := "terraform_test_user_uidwithuuid@crowdstrike.com"
	uidWithoutCID := "terraform_test_user_uidwithoutcid@crowdstrike.com"
	uidWithCID := "terraform_test_user_uidwithcid@crowdstrike.com"
	withUUIDandUID := "terraform_test_user_withuuidanduid@crowdstrike.com"
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
			// Only UUID is passed to the data source
			{
				Config: testUserDataSource_withUUID(uidWithUUID, firstName, lastName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceWithUUID, "cid", cid),
					resource.TestCheckResourceAttr(dataSourceWithUUID, "first_name", firstName),
					resource.TestCheckResourceAttr(dataSourceWithUUID, "last_name", lastName),
					resource.TestCheckResourceAttr(dataSourceWithUUID, "uid", uidWithUUID),
					resource.TestCheckResourceAttrSet(dataSourceWithUUID, "uuid"),
				),
			},
			// UID and CID are passed to the data source to validate child CID permissions
			{
				Config: testUserDataSource_uidWithCID(uidWithCID, firstName, lastName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceUidWithCID, "cid", cid),
					resource.TestCheckResourceAttr(dataSourceUidWithCID, "first_name", firstName),
					resource.TestCheckResourceAttr(dataSourceUidWithCID, "last_name", lastName),
					resource.TestCheckResourceAttr(dataSourceUidWithCID, "uid", uidWithCID),
					resource.TestCheckResourceAttrSet(dataSourceUidWithCID, "uuid"),
				),
			},
			// Only UID is passed to the data source
			{
				Config: testUserDataSource_uidWithoutCID(uidWithoutCID, firstName, lastName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceUidWithoutCID, "cid", cid),
					resource.TestCheckResourceAttr(dataSourceUidWithoutCID, "first_name", firstName),
					resource.TestCheckResourceAttr(dataSourceUidWithoutCID, "last_name", lastName),
					resource.TestCheckResourceAttr(dataSourceUidWithoutCID, "uid", uidWithoutCID),
					resource.TestCheckResourceAttrSet(dataSourceUidWithoutCID, "uuid"),
				),
			},
			// Only UID and UUID are passed to the data source
			{
				Config: testUserDataSource_withUUIDandUID(withUUIDandUID, firstName, lastName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourcewithUUIDandUID, "cid", cid),
					resource.TestCheckResourceAttr(dataSourcewithUUIDandUID, "first_name", firstName),
					resource.TestCheckResourceAttr(dataSourcewithUUIDandUID, "last_name", lastName),
					resource.TestCheckResourceAttr(dataSourcewithUUIDandUID, "uid", withUUIDandUID),
					resource.TestCheckResourceAttrSet(dataSourcewithUUIDandUID, "uuid"),
				),
			},
		},
	})
}

func TestUserDataSource_Validation(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
                data "crowdstrike_user" "test" {
                    uid = "asdf"
                }
                `,
				ExpectError: regexp.MustCompile(`Attribute uid must be a valid email address in lowercase`),
			},
			{
				Config: `
			    data "crowdstrike_user" "test" {
			        uid = "user@crowdstrike"
			    }
			    `,
				ExpectError: regexp.MustCompile(`Attribute uid must be a valid email address in lowercase`),
			},
			{
				Config: `
			    data "crowdstrike_user" "test" {
			        cid = "asdfasdfasdfasdfasdfasdfasdfasdf"
			    }
			    `,
				ExpectError: regexp.MustCompile(`must be a 32-character hexadecimal string in uppercase`),
			},
			{
				Config: `
			    data "crowdstrike_user" "test" {
			        cid = "ASDF"
			    }
			    `,
				ExpectError: regexp.MustCompile(`must be a 32-character hexadecimal string in uppercase`),
			},
			{
				Config: `
			    data "crowdstrike_user" "test" {
			        uuid = "asdf"
			    }
			    `,
				ExpectError: regexp.MustCompile(`must be in the format of xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`),
			},
		},
	})
}

func testUserDataSource_uidWithCID(uid string, firstName string, lastName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_user" "uidWithCID" {
  uid = "%s"
  first_name = "%s"
  last_name = "%s"
}

data "crowdstrike_user" "uidWithCID" {
  uid = crowdstrike_user.uidWithCID.uid
  cid = crowdstrike_user.uidWithCID.cid
  depends_on = [
	crowdstrike_user.uidWithCID
  ]
}
`, uid, firstName, lastName)
}

func testUserDataSource_uidWithoutCID(uid string, firstName string, lastName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_user" "uidWithoutCID" {
  uid = "%s"
  first_name = "%s"
  last_name = "%s"
}

data "crowdstrike_user" "uidWithoutCID" {
  uid = crowdstrike_user.uidWithoutCID.uid
  depends_on = [
	crowdstrike_user.uidWithoutCID
  ]
}
`, uid, firstName, lastName)
}

func testUserDataSource_withUUID(uid string, firstName string, lastName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_user" "withUUID" {
  uid = "%s"
  first_name = "%s"
  last_name = "%s"
}

data "crowdstrike_user" "withUUID" {
  uuid = crowdstrike_user.withUUID.uuid
  depends_on = [
	crowdstrike_user.withUUID
  ]
}
`, uid, firstName, lastName)
}

func testUserDataSource_withUUIDandUID(uid string, firstName string, lastName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_user" "withUUIDandUID" {
  uid = "%s"
  first_name = "%s"
  last_name = "%s"
}

data "crowdstrike_user" "withUUIDandUID" {
  uuid = crowdstrike_user.withUUIDandUID.uuid
  uid = crowdstrike_user.withUUIDandUID.uid
  depends_on = [
	crowdstrike_user.withUUIDandUID
  ]
}
`, uid, firstName, lastName)
}
