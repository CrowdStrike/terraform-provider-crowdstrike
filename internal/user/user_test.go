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

// testUserEmailDomain is the email domain used to build test user emails. The
// Falcon tenant only accepts users whose domain is allowlisted, so it is
// configurable via TF_ACC_USER_EMAIL_DOMAIN and defaults to crowdstrike.com.
func testUserEmailDomain() string {
	if d := os.Getenv("TF_ACC_USER_EMAIL_DOMAIN"); d != "" {
		return d
	}
	return "crowdstrike.com"
}

func TestAccUserResource_basic(t *testing.T) {
	rName := acctest.RandomResourceName()
	email := fmt.Sprintf("%s@%s", rName, testUserEmailDomain())
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
	rName := acctest.RandomResourceName()
	email := fmt.Sprintf("%s@%s", rName, testUserEmailDomain())
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
	rName := acctest.RandomResourceName()
	email := fmt.Sprintf("%s@%s", rName, testUserEmailDomain())
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
resource "crowdstrike_user" "test" {
  email      = %[1]q
  first_name = %[2]q
  last_name  = %[3]q
}
`, email, firstName, lastName)
}

func testAccUserConfig_password(email, password string, version int) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_user" "test" {
  email               = %[1]q
  first_name          = "John"
  last_name           = "Doe"
  password_wo         = %[2]q
  password_wo_version = %[3]d
}
`, email, password, version)
}
