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

func TestUserRolesDataSource(t *testing.T) {
	dataSourceWithCID := "data.crowdstrike_user_roles.withCID"
	dataSourceWithoutCID := "data.crowdstrike_user_roles.withoutCID"

	cid := strings.ToUpper(os.Getenv("FALCON_CID"))
	if len(cid) > 32 {
		cid = cid[:32]
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testUserRolesDataSource_withCID(cid),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceWithCID, "cid", cid),
					resource.TestCheckResourceAttrSet(dataSourceWithCID, "role_ids.#"),
				),
			},
			{
				Config: testUserRolesDataSource_withoutCID(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceWithoutCID, "cid", cid),
					resource.TestCheckResourceAttrSet(dataSourceWithoutCID, "role_ids.#"),
				),
			},
			{
				Config: testUserRolesDataSource_filter(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckOutput("filtered_roles_count", "2"),
					resource.TestCheckOutput("has_falcon_console_guest", "true"),
					resource.TestCheckOutput("has_falconhost_read_only", "true"),
				),
			},
		},
	})
}

func TestUserRolesDataSource_Validation(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
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
		},
	})
}

func testUserRolesDataSource_withCID(cid string) string {
	return fmt.Sprintf(`
data "crowdstrike_user_roles" "withCID" {
  cid = "%s"
}
`, cid)
}

func testUserRolesDataSource_withoutCID() string {
	return `data "crowdstrike_user_roles" "withoutCID" {}`
}

func testUserRolesDataSource_filter() string {
	return `
data "crowdstrike_user_roles" "filter" {}

locals {
  filtered_roles = [for role in data.crowdstrike_user_roles.filter.role_ids : role if can(regex("(read|guest)", role))]
}

output "filtered_roles_count" {
  value = length(local.filtered_roles)
}

output "has_falcon_console_guest" {
  value = contains(local.filtered_roles, "falcon_console_guest")
}

output "has_falconhost_read_only" {
  value = contains(local.filtered_roles, "falconhost_read_only")
}
`
}
