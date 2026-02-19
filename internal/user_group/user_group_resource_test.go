package usergroup_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccUserGroupResource_basic(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_user_group.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccUserGroupConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cid"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_uuids"), knownvalue.Null()),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
		},
	})
}

func TestAccUserGroupResource_update(t *testing.T) {
	rName := acctest.RandomResourceName()
	rNameUpdated := rName + "-updated"
	resourceName := "crowdstrike_user_group.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccUserGroupConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_uuids"), knownvalue.Null()),
				},
			},
			{
				Config: testAccUserGroupConfig_description(rNameUpdated),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rNameUpdated)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Test user group created by Terraform")),
				},
			},
			{
				Config: testAccUserGroupConfig_basic(rNameUpdated),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rNameUpdated)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.Null()),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
		},
	})
}

func TestAccUserGroupResource_members(t *testing.T) {
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
	resourceName := "crowdstrike_user_group.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccUserGroupConfig_members(rName, []string{uuid1, uuid2}),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Test user group with members")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_uuids"), knownvalue.SetSizeExact(2)),
				},
			},
			{
				Config: testAccUserGroupConfig_members(rName, []string{uuid1}),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_uuids"), knownvalue.SetSizeExact(1)),
				},
			},
			{
				Config: testAccUserGroupConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_uuids"), knownvalue.Null()),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
		},
	})
}

func testAccUserGroupConfig_basic(name string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_user_group" "test" {
  name = %[1]q
}
`, name)
}

func testAccUserGroupConfig_description(name string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_user_group" "test" {
  name        = %[1]q
  description = "Test user group created by Terraform"
}
`, name)
}

func testAccUserGroupConfig_members(name string, userUUIDs []string) string {
	var uuidList strings.Builder
	for i, uuid := range userUUIDs {
		if i > 0 {
			uuidList.WriteString(",\n    ")
		}
		fmt.Fprintf(&uuidList, `"%s"`, uuid)
	}

	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_user_group" "test" {
  name        = %[1]q
  description = "Test user group with members"
  user_uuids = [
    %[2]s
  ]
}
`, name, uuidList.String())
}
