package userroles_test

import (
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const userRolesDataSourceName = "data.crowdstrike_user_roles.test"

func TestAccUserRolesDataSource_basic(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + `
data "crowdstrike_user_roles" "test" {}
`,
				ConfigStateChecks: []statecheck.StateCheck{
					// The roles list must be present and non-empty, and its
					// first element must carry the hydrated role fields. The
					// ListPartial check fails if index 0 is absent.
					statecheck.ExpectKnownValue(
						userRolesDataSourceName,
						tfjsonpath.New("roles"),
						knownvalue.ListPartial(map[int]knownvalue.Check{
							0: knownvalue.ObjectPartial(map[string]knownvalue.Check{
								"id":           knownvalue.NotNull(),
								"display_name": knownvalue.NotNull(),
								"is_global":    knownvalue.NotNull(),
								"type":         knownvalue.NotNull(),
							}),
						}),
					),
				},
			},
		},
	})
}

func TestAccUserRolesDataSource_cid(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + `
data "crowdstrike_cid" "test" {}

data "crowdstrike_user_roles" "test" {
  cid = data.crowdstrike_cid.test.cid
}
`,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						userRolesDataSourceName,
						tfjsonpath.New("roles"),
						knownvalue.ListPartial(map[int]knownvalue.Check{
							0: knownvalue.ObjectPartial(map[string]knownvalue.Check{
								"id": knownvalue.NotNull(),
							}),
						}),
					),
				},
			},
		},
	})
}

func TestAccUserRolesDataSource_invalidCID(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + `
data "crowdstrike_user_roles" "test" {
  cid = "ABCDEF1234567890ABCDEF1234567890-0F"
}
`,
				ExpectError: regexp.MustCompile("must be a 32-character lowercase hexadecimal CID"),
			},
		},
	})
}
