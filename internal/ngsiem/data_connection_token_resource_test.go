package ngsiem_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const dataConnectionTokenResourceName = "crowdstrike_ngsiem_data_connection_token.test"

// TestAccNGSIEMDataConnectionTokenResource_basic generates a token for a push
// connection and asserts the computed attributes are populated. The token value
// itself cannot be read back, so it is only asserted non-null. Import is not
// supported for this resource.
func TestAccNGSIEMDataConnectionTokenResource_basic(t *testing.T) {
	connectorID := requirePushConnectorID(t)
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckDataConnectionDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccNGSIEMDataConnectionTokenConfig(connectorID, rName, "v1"),
				ConfigStateChecks: []statecheck.StateCheck{
					stateCheckDataConnectionExists(dataConnectionResourceName),
					statecheck.ExpectKnownValue(dataConnectionTokenResourceName, tfjsonpath.New("token"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(dataConnectionTokenResourceName, tfjsonpath.New("ingest_url"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(dataConnectionTokenResourceName, tfjsonpath.New("created_at"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(dataConnectionTokenResourceName, tfjsonpath.New("expires_at"), knownvalue.NotNull()),
				},
			},
		},
	})
}

// TestAccNGSIEMDataConnectionTokenResource_rotate asserts that changing
// triggers forces the resource to be replaced (regenerating the token).
func TestAccNGSIEMDataConnectionTokenResource_rotate(t *testing.T) {
	connectorID := requirePushConnectorID(t)
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckDataConnectionDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccNGSIEMDataConnectionTokenConfig(connectorID, rName, "v1"),
				ConfigStateChecks: []statecheck.StateCheck{
					stateCheckDataConnectionExists(dataConnectionResourceName),
					statecheck.ExpectKnownValue(dataConnectionTokenResourceName, tfjsonpath.New("token"), knownvalue.NotNull()),
				},
			},
			{
				Config: testAccNGSIEMDataConnectionTokenConfig(connectorID, rName, "v2"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(dataConnectionTokenResourceName, plancheck.ResourceActionReplace),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					stateCheckDataConnectionExists(dataConnectionResourceName),
					statecheck.ExpectKnownValue(dataConnectionTokenResourceName, tfjsonpath.New("token"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(dataConnectionTokenResourceName, tfjsonpath.New("triggers").AtMapKey("version"), knownvalue.StringExact("v2")),
				},
			},
		},
	})
}

// TestAccNGSIEMDataConnectionTokenResource_disappears deletes the underlying
// connection out-of-band; the token resource's Read must then drop it from
// state, producing a non-empty plan.
func TestAccNGSIEMDataConnectionTokenResource_disappears(t *testing.T) {
	connectorID := requirePushConnectorID(t)
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckDataConnectionDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccNGSIEMDataConnectionTokenConfig(connectorID, rName, "v1"),
				ConfigStateChecks: []statecheck.StateCheck{
					stateCheckDataConnectionExists(dataConnectionResourceName),
					stateCheckDataConnectionDisappears(dataConnectionResourceName),
				},
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// testAccNGSIEMDataConnectionTokenConfig builds a push data connection and a
// token resource for it. rotateVersion sets a triggers value used to
// exercise rotation.
func testAccNGSIEMDataConnectionTokenConfig(connectorID, name, rotateVersion string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ngsiem_data_connection" "test" {
  name                   = %[1]q
  connector_id           = %[2]q
  parser                 = "aws-elb"
  enable_host_enrichment = false
  enable_user_enrichment = false
}

resource "crowdstrike_ngsiem_data_connection_token" "test" {
  connection_id = crowdstrike_ngsiem_data_connection.test.id

  triggers = {
    version = %[3]q
  }
}
`, name, connectorID, rotateVersion)
}
