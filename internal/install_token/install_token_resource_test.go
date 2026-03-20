package installtoken_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

var futureTimestamp = time.Now().AddDate(1, 0, 0).UTC().Format(time.RFC3339)

func TestAccInstallTokenResource_basic(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_install_token.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccInstallTokenConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("value"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("status"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_timestamp"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_used_timestamp"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("revoked_timestamp"), knownvalue.Null()),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccInstallTokenResource_update(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_install_token.test"

	valueSame := statecheck.CompareValue(compare.ValuesSame())

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccInstallTokenConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("value"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("status"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_timestamp"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("expires_timestamp"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("revoked"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("revoked_timestamp"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_used_timestamp"), knownvalue.Null()),
					valueSame.AddStateValue(resourceName, tfjsonpath.New("value")),
				},
			},
			{
				Config: testAccInstallTokenConfig_updated(fmt.Sprintf("%s-updated", rName), futureTimestamp),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(fmt.Sprintf("%s-updated", rName))),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("expires_timestamp"), knownvalue.StringExact(futureTimestamp)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("revoked"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("status"), knownvalue.StringExact("revoked")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("revoked_timestamp"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("value"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_timestamp"), knownvalue.NotNull()),
					valueSame.AddStateValue(resourceName, tfjsonpath.New("value")),
				},
			},
			{
				Config: testAccInstallTokenConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("expires_timestamp"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("revoked"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("revoked_timestamp"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("value"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_timestamp"), knownvalue.NotNull()),
					valueSame.AddStateValue(resourceName, tfjsonpath.New("value")),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccInstallTokenResource_revoked(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_install_token.test"

	valueSame := statecheck.CompareValue(compare.ValuesSame())

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccInstallTokenConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("revoked"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("revoked_timestamp"), knownvalue.Null()),
					valueSame.AddStateValue(resourceName, tfjsonpath.New("value")),
				},
			},
			{
				Config: testAccInstallTokenConfig_revoked(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("revoked"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("status"), knownvalue.StringExact("revoked")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("revoked_timestamp"), knownvalue.NotNull()),
					valueSame.AddStateValue(resourceName, tfjsonpath.New("value")),
				},
			},
			{
				Config: testAccInstallTokenConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("revoked"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("revoked_timestamp"), knownvalue.Null()),
					valueSame.AddStateValue(resourceName, tfjsonpath.New("value")),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccInstallTokenResource_expiresTimestamp(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_install_token.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccInstallTokenConfig_withExpiration(rName, futureTimestamp),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("expires_timestamp"), knownvalue.StringExact(futureTimestamp)),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccInstallTokenConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("expires_timestamp"), knownvalue.Null()),
				},
			},
		},
	})
}

func testAccInstallTokenConfig_basic(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_install_token" "test" {
  name = %[1]q
}`, name)
}

func testAccInstallTokenConfig_withExpiration(name, expires string) string {
	return fmt.Sprintf(`
resource "crowdstrike_install_token" "test" {
  name              = %[1]q
  expires_timestamp = %[2]q
}`, name, expires)
}

func testAccInstallTokenConfig_updated(name, expires string) string {
	return fmt.Sprintf(`
resource "crowdstrike_install_token" "test" {
  name              = %[1]q
  expires_timestamp = %[2]q
  revoked           = true
}`, name, expires)
}

func testAccInstallTokenConfig_revoked(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_install_token" "test" {
  name    = %[1]q
  revoked = true
}`, name)
}
