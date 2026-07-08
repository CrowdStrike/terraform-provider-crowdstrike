package ngsiem_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/ngsiem"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/testconfig"
	"github.com/go-openapi/runtime"
	tfjson "github.com/hashicorp/terraform-json"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const dataConnectionResourceName = "crowdstrike_ngsiem_data_connection.test"

// dataConnectionImportIgnore lists attributes the read API does not echo back.
// They are tracked only from prior state, so a fresh import cannot repopulate
// them and they must be skipped during ImportStateVerify.
var dataConnectionImportIgnore = []string{
	"connector_id",
	"enable_host_enrichment",
	"enable_user_enrichment",
	"description",
	"config_id",
	"log_sources",
	"custom",
}

// requirePushConnectorID returns the PUSH connector catalog ID to test against,
// read from TF_ACC_NGSIEM_PUSH_CONNECTOR_ID (e.g. the HEC / HTTP Event
// Connector). The test is skipped when unset since the ID is tenant/catalog
// specific.
func requirePushConnectorID(t *testing.T) string {
	t.Helper()
	id := os.Getenv("TF_ACC_NGSIEM_PUSH_CONNECTOR_ID")
	if id == "" {
		t.Skip("Set TF_ACC_NGSIEM_PUSH_CONNECTOR_ID to a PUSH connector catalog ID to run NG-SIEM data connection PUSH tests")
	}
	return id
}

// TestAccNGSIEMDataConnectionResource_Pull covers the PULL lifecycle: create a
// connection backed by an inline connector config, then update it. It verifies
// config_id links to the config resource, that a PULL reads back
// connector_type=Pull with no ingest_url, and that the connection round-trips
// through import at each state.
func TestAccNGSIEMDataConnectionResource_Pull(t *testing.T) {
	connectorID := requireConnectorID(t)
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckDataConnectionDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccNGSIEMDataConnectionConfig_pull(connectorID, rName, ""),
				ConfigStateChecks: []statecheck.StateCheck{
					stateCheckDataConnectionExists(dataConnectionResourceName),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("connector_id"), knownvalue.StringExact(connectorID)),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("parser"), knownvalue.StringExact("aws-s3serveraccess")),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("enable_host_enrichment"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("enable_user_enrichment"), knownvalue.Bool(false)),
					// config_id is stored from the referenced config resource id.
					statecheck.CompareValuePairs(
						dataConnectionResourceName, tfjsonpath.New("config_id"),
						"crowdstrike_ngsiem_data_connector_config.test", tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
					// Optional inputs left unset.
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("description"), knownvalue.Null()),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("log_sources"), knownvalue.Null()),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("custom"), knownvalue.Null()),
					// Computed values derived from the catalog / runtime.
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("connector_type"), knownvalue.StringExact("Pull")),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("status"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("vendor_name"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("vendor_product_name"), knownvalue.NotNull()),
					// A PULL connection has no HEC ingest URL.
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("ingest_url"), knownvalue.Null()),
				},
			},
			{
				ResourceName:            dataConnectionResourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: dataConnectionImportIgnore,
			},
			{
				// Update: set an optional description on a PULL connection.
				Config: testAccNGSIEMDataConnectionConfig_pull(connectorID, rName, "pull description"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("description"), knownvalue.StringExact("pull description")),
					statecheck.CompareValuePairs(
						dataConnectionResourceName, tfjsonpath.New("config_id"),
						"crowdstrike_ngsiem_data_connector_config.test", tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("connector_type"), knownvalue.StringExact("Pull")),
				},
			},
			{
				ResourceName:            dataConnectionResourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: dataConnectionImportIgnore,
			},
		},
	})
}

// TestAccNGSIEMDataConnectionResource_Push covers the full PUSH lifecycle:
// create with required attributes only, update to set every optional attribute
// and flip the enrichment flags, then drop the optionals and flip the flags
// back. Because the read API echoes none of these inputs, the drift-back step
// proves clearing settles without a perpetual diff. The false→true→false
// enrichment path also exercises the client override that forces a false value
// onto the wire. The connection round-trips through import at each state.
func TestAccNGSIEMDataConnectionResource_Push(t *testing.T) {
	connectorID := requirePushConnectorID(t)
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckDataConnectionDestroy,
		Steps: []resource.TestStep{
			{
				// Step 1: required attributes only.
				Config: testAccNGSIEMDataConnectionConfig_push(connectorID, rName, false),
				ConfigStateChecks: []statecheck.StateCheck{
					stateCheckDataConnectionExists(dataConnectionResourceName),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("connector_id"), knownvalue.StringExact(connectorID)),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("parser"), knownvalue.StringExact("aws-elb")),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("enable_host_enrichment"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("enable_user_enrichment"), knownvalue.Bool(false)),
					// Optional inputs left unset.
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("description"), knownvalue.Null()),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("config_id"), knownvalue.Null()),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("log_sources"), knownvalue.Null()),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("custom"), knownvalue.Null()),
					// Computed values.
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("connector_type"), knownvalue.StringExact("Push")),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("status"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("vendor_name"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("vendor_product_name"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("ingest_url"), knownvalue.Null()),
				},
			},
			{
				ResourceName:            dataConnectionResourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: dataConnectionImportIgnore,
			},
			{
				// Step 2: set all optionals and flip enrichment to true.
				Config: testAccNGSIEMDataConnectionConfig_push(connectorID, rName, true),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("enable_host_enrichment"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("enable_user_enrichment"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("description"), knownvalue.StringExact("updated hec description")),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("log_sources"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact("src-a"),
						knownvalue.StringExact("src-b"),
					})),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("connector_type"), knownvalue.StringExact("Push")),
				},
			},
			{
				ResourceName:            dataConnectionResourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: dataConnectionImportIgnore,
			},
			{
				// Step 3: drop all optionals and flip enrichment back to false.
				Config: testAccNGSIEMDataConnectionConfig_push(connectorID, rName, false),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("enable_host_enrichment"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("enable_user_enrichment"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("description"), knownvalue.Null()),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("log_sources"), knownvalue.Null()),
					statecheck.ExpectKnownValue(dataConnectionResourceName, tfjsonpath.New("custom"), knownvalue.Null()),
				},
			},
			{
				ResourceName:            dataConnectionResourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: dataConnectionImportIgnore,
			},
		},
	})
}

// TestAccNGSIEMDataConnectionResource_disappears verifies that when a
// connection is deleted out-of-band, the next plan proposes recreation rather
// than erroring. This exercises the Read not-found path that removes the
// resource from state.
func TestAccNGSIEMDataConnectionResource_disappears(t *testing.T) {
	connectorID := requirePushConnectorID(t)
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckDataConnectionDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccNGSIEMDataConnectionConfig_push(connectorID, rName, false),
				ConfigStateChecks: []statecheck.StateCheck{
					stateCheckDataConnectionExists(dataConnectionResourceName),
					stateCheckDataConnectionDisappears(dataConnectionResourceName),
				},
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func testAccNGSIEMDataConnectionConfig_pull(connectorID, name, description string) string {
	desc := ""
	if description != "" {
		desc = fmt.Sprintf("\n  description            = %q", description)
	}
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ngsiem_data_connector_config" "test" {
  connector_id = %[2]q
  name         = %[1]q

  params = jsonencode({
    account_id            = "123456789012"
    bucket                = "my-access-log-bucket"
    prefix                = "logs/"
    region                = "us-east-1"
    sqs_name              = "my-s3-notification-queue"
    authentication_method = "iam_assume_role"
    iam_assume_role       = "arn:aws:iam::123456789012:role/crowdstrike-s3-ingest"
  })
}

resource "crowdstrike_ngsiem_data_connection" "test" {
  name                   = %[1]q
  connector_id           = %[2]q
  parser                 = "aws-s3serveraccess"
  enable_host_enrichment = true
  enable_user_enrichment = false
  config_id              = crowdstrike_ngsiem_data_connector_config.test.id%[3]s
}
`, name, connectorID, desc)
}

func testAccNGSIEMDataConnectionConfig_push(connectorID, name string, withOptionals bool) string {
	host, user := "false", "false"
	optionals := ""
	if withOptionals {
		host, user = "true", "true"
		optionals = `
  description = "updated hec description"
  log_sources = ["src-a", "src-b"]`
	}
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ngsiem_data_connection" "test" {
  name                   = %[1]q
  connector_id           = %[2]q
  parser                 = "aws-elb"
  enable_host_enrichment = %[3]s
  enable_user_enrichment = %[4]s%[5]s
}
`, name, connectorID, host, user, optionals)
}

// stateResourceAtAddress returns the parsed state resource at the given
// address, or an error if the state is empty or the address is absent.
func stateResourceAtAddress(state *tfjson.State, address string) (*tfjson.StateResource, error) {
	if state == nil || state.Values == nil || state.Values.RootModule == nil {
		return nil, fmt.Errorf("no state available")
	}
	for _, r := range state.Values.RootModule.Resources {
		if r.Address == address {
			return r, nil
		}
	}
	return nil, fmt.Errorf("not found in state: %s", address)
}

// getDataConnectionByID reads a single data connection from the API and reports
// whether it exists. A nil error with found=false means the API returned no
// matching resource.
func getDataConnectionByID(ctx context.Context, id string) (found bool, err error) {
	conn := testconfig.GetTestClient()
	params := ngsiem.NewExternalGetDataConnectionByIDParams().
		WithContext(ctx).
		WithIds([]string{id})

	res, err := conn.Ngsiem.ExternalGetDataConnectionByID(params)
	if err != nil {
		if statusErr, ok := err.(runtime.ClientResponseStatus); ok && statusErr.IsCode(404) {
			return false, nil
		}
		return false, err
	}
	if res == nil || res.Payload == nil {
		return false, nil
	}
	for _, r := range res.Payload.Resources {
		if r != nil && r.ID != nil && *r.ID == id {
			return true, nil
		}
	}
	return false, nil
}

// dataConnectionExistsCheck verifies the connection at the given address exists
// via a live API read.
type dataConnectionExistsCheck struct {
	resourceAddress string
}

func (c dataConnectionExistsCheck) CheckState(ctx context.Context, req statecheck.CheckStateRequest, resp *statecheck.CheckStateResponse) {
	r, err := stateResourceAtAddress(req.State, c.resourceAddress)
	if err != nil {
		resp.Error = err
		return
	}
	id, ok := r.AttributeValues["id"].(string)
	if !ok || id == "" {
		resp.Error = fmt.Errorf("no id found for %s", c.resourceAddress)
		return
	}
	found, err := getDataConnectionByID(ctx, id)
	if err != nil {
		resp.Error = fmt.Errorf("reading data connection %s: %w", id, err)
		return
	}
	if !found {
		resp.Error = fmt.Errorf("data connection %s not found via API", id)
	}
}

// stateCheckDataConnectionExists asserts the connection at the given address
// exists in the API.
func stateCheckDataConnectionExists(name string) statecheck.StateCheck {
	return dataConnectionExistsCheck{resourceAddress: name}
}

// dataConnectionDisappearsCheck deletes the connection at the given address via
// the API to simulate out-of-band deletion.
type dataConnectionDisappearsCheck struct {
	resourceAddress string
}

func (c dataConnectionDisappearsCheck) CheckState(ctx context.Context, req statecheck.CheckStateRequest, resp *statecheck.CheckStateResponse) {
	r, err := stateResourceAtAddress(req.State, c.resourceAddress)
	if err != nil {
		resp.Error = err
		return
	}
	id, ok := r.AttributeValues["id"].(string)
	if !ok || id == "" {
		resp.Error = fmt.Errorf("no id found for %s", c.resourceAddress)
		return
	}
	conn := testconfig.GetTestClient()
	params := ngsiem.NewExternalDeleteDataConnectionParams().
		WithContext(ctx).
		WithIds(id)
	if _, err := conn.Ngsiem.ExternalDeleteDataConnection(params); err != nil {
		resp.Error = fmt.Errorf("deleting data connection %s: %w", id, err)
	}
}

// stateCheckDataConnectionDisappears deletes the connection at the given
// address out-of-band.
func stateCheckDataConnectionDisappears(name string) statecheck.StateCheck {
	return dataConnectionDisappearsCheck{resourceAddress: name}
}

// testAccCheckDataConnectionDestroy verifies every data connection tracked in
// state has been removed from the API after the test tears down.
func testAccCheckDataConnectionDestroy(s *terraform.State) error {
	ctx := context.Background()
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "crowdstrike_ngsiem_data_connection" {
			continue
		}
		found, err := getDataConnectionByID(ctx, rs.Primary.ID)
		if err != nil {
			return err
		}
		if found {
			return fmt.Errorf("data connection %s still exists", rs.Primary.ID)
		}
	}
	return nil
}
