package user_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// testUserEmail returns a unique email in the tenant's allowlisted domain. The
// Falcon tenant only accepts users whose domain is allowlisted, so the domain is
// configurable via TF_ACC_USER_EMAIL_DOMAIN and defaults to crowdstrike.com.
func testUserEmail() string {
	domain := os.Getenv("TF_ACC_USER_EMAIL_DOMAIN")
	if domain == "" {
		domain = "crowdstrike.com"
	}
	return fmt.Sprintf("%s@%s", acctest.RandomResourceName(), domain)
}

func TestAccUserResource_basic(t *testing.T) {
	email := testUserEmail()
	resourceName := "crowdstrike_user.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccUserConfig_basic(email, "John", "Doe"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("email"), knownvalue.StringExact(email)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("first_name"), knownvalue.StringExact("John")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_name"), knownvalue.StringExact("Doe")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cid"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("status"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_at"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password_wo", "password_wo_version"},
			},
		},
	})
}

func TestAccUserResource_update(t *testing.T) {
	email := testUserEmail()
	resourceName := "crowdstrike_user.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccUserConfig_basic(email, "John", "Doe"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("first_name"), knownvalue.StringExact("John")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_name"), knownvalue.StringExact("Doe")),
				},
			},
			{
				Config: testAccUserConfig_basic(email, "Jane", "Smith"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("email"), knownvalue.StringExact(email)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("first_name"), knownvalue.StringExact("Jane")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_name"), knownvalue.StringExact("Smith")),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password_wo", "password_wo_version"},
			},
		},
	})
}

// TestAccUserResource_passwordVersionReplace verifies that bumping
// password_wo_version replaces the user (a new UUID is minted), since the
// Falcon API has no in-place password-change endpoint.
func TestAccUserResource_passwordVersionReplace(t *testing.T) {
	email := testUserEmail()
	resourceName := "crowdstrike_user.test"

	idsDiffer := statecheck.CompareValue(compare.ValuesDiffer())

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccUserConfig_password(email, "TfAccPassw0rd!123", 1),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("email"), knownvalue.StringExact(email)),
					idsDiffer.AddStateValue(resourceName, tfjsonpath.New("id")),
				},
			},
			{
				Config: testAccUserConfig_password(email, "TfAccPassw0rd!456", 2),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionReplace),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					idsDiffer.AddStateValue(resourceName, tfjsonpath.New("id")),
				},
			},
		},
	})
}

func testAccUserConfig_basic(email, firstName, lastName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
data "crowdstrike_cid" "current" {}

resource "crowdstrike_user" "test" {
  email      = %[1]q
  first_name = %[2]q
  last_name  = %[3]q
  cid        = data.crowdstrike_cid.current.cid
}
`, email, firstName, lastName)
}

func testAccUserConfig_password(email, password string, version int) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
data "crowdstrike_cid" "current" {}

resource "crowdstrike_user" "test" {
  email               = %[1]q
  first_name          = "John"
  last_name           = "Doe"
  cid                 = data.crowdstrike_cid.current.cid
  password_wo         = %[2]q
  password_wo_version = %[3]d
}
`, email, password, version)
}
