package ngsiem_test

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/ngsiem"
	"github.com/hashicorp/terraform-plugin-framework-jsontypes/jsontypes"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// requireConnectorID returns the connector catalog ID to test against, read
// from TF_ACC_NGSIEM_CONNECTOR_ID. It expects a PULL connector that carries
// credentials inside params (no top-level auth) and does not validate them at
// config-create time, e.g. the AWS S3 Access Log connector. The test is skipped
// when the variable is unset since the ID is tenant/catalog specific.
func requireConnectorID(t *testing.T) string {
	t.Helper()
	id := os.Getenv("TF_ACC_NGSIEM_CONNECTOR_ID")
	if id == "" {
		t.Skip("Set TF_ACC_NGSIEM_CONNECTOR_ID to a PULL connector catalog ID to run NG-SIEM connector config tests")
	}
	return id
}

func TestAccNgsiemDataConnectorConfig_basic(t *testing.T) {
	connectorID := requireConnectorID(t)
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_ngsiem_data_connector_config.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccNgsiemDataConnectorConfig(connectorID, rName, "my-access-log-bucket"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("connector_id"), knownvalue.StringExact(connectorID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("params"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("auth"), knownvalue.Null()),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: testAccNgsiemDataConnectorConfigImportID(),
			},
		},
	})
}

func TestAccNgsiemDataConnectorConfig_update(t *testing.T) {
	connectorID := requireConnectorID(t)
	rName := acctest.RandomResourceName()
	updatedName := fmt.Sprintf("%s-updated", rName)
	resourceName := "crowdstrike_ngsiem_data_connector_config.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccNgsiemDataConnectorConfig(connectorID, rName, "my-access-log-bucket"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("params"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("auth"), knownvalue.Null()),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: testAccNgsiemDataConnectorConfigImportID(),
			},
			{
				Config: testAccNgsiemDataConnectorConfig(connectorID, updatedName, "my-updated-bucket"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(updatedName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("params"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("auth"), knownvalue.Null()),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: testAccNgsiemDataConnectorConfigImportID(),
			},
			{
				Config: testAccNgsiemDataConnectorConfig(connectorID, rName, "my-access-log-bucket"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("params"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("auth"), knownvalue.Null()),
				},
			},
		},
	})
}

// TestAccNgsiemDataConnectorConfig_pathWrapperRejected verifies that supplying
// params already wrapped in a top-level "path" key is rejected at plan time. The
// resource adds the wrapper itself and expects flat params.
func TestAccNgsiemDataConnectorConfig_pathWrapperRejected(t *testing.T) {
	connectorID := requireConnectorID(t)
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccNgsiemDataConnectorConfigPathWrapped(connectorID, rName, "my-access-log-bucket"),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Unexpected "path" Wrapper in params`),
			},
		},
	})
}

// testAccNgsiemDataConnectorConfigImportID builds the composite import id
// ("<connector_id>,<config_id>") from state.
func testAccNgsiemDataConnectorConfigImportID() resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources["crowdstrike_ngsiem_data_connector_config.test"]
		if !ok {
			return "", fmt.Errorf("resource not found in state: crowdstrike_ngsiem_data_connector_config.test")
		}
		return fmt.Sprintf("%s,%s", rs.Primary.Attributes["connector_id"], rs.Primary.Attributes["id"]), nil
	}
}

func testAccNgsiemDataConnectorConfig(connectorID, name, bucket string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ngsiem_data_connector_config" "test" {
  connector_id = %[1]q
  name         = %[2]q

  params = jsonencode({
    account_id            = "123456789012"
    bucket                = %[3]q
    prefix                = "logs/"
    region                = "us-east-1"
    sqs_name              = "tf-acc-test-queue"
    authentication_method = "iam_assume_role"
    iam_assume_role       = "arn:aws:iam::123456789012:role/tf-acc-test-ingest"
  })
}
`, connectorID, name, bucket)
}

func testAccNgsiemDataConnectorConfigPathWrapped(connectorID, name, bucket string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ngsiem_data_connector_config" "test" {
  connector_id = %[1]q
  name         = %[2]q

  params = jsonencode({
    path = {
      account_id            = "123456789012"
      bucket                = %[3]q
      prefix                = "logs/"
      region                = "us-east-1"
      sqs_name              = "tf-acc-test-queue"
      authentication_method = "iam_assume_role"
      iam_assume_role       = "arn:aws:iam::123456789012:role/tf-acc-test-ingest"
    }
  })
}
`, connectorID, name, bucket)
}

// TestNormalizeParams covers the read-side transform: the API returns params
// flat and they are stored flat, matching the shape users supply. Any key the
// API redacts as "[SECRET]" is restored from the prior params so
// secret-in-params connectors do not drift. This is unit-tested (rather than via
// a live secret-bearing connector) because the behavior is deterministic and
// does not depend on the remote API.
func TestNormalizeParams(t *testing.T) {
	tests := map[string]struct {
		apiParams  interface{}
		prior      jsontypes.Normalized
		wantFields map[string]interface{}
		wantNull   bool
	}{
		"flat params stored flat": {
			apiParams: map[string]interface{}{
				"account_id": "123456789012",
				"region":     "us-east-1",
			},
			prior: jsontypes.NewNormalizedValue(`{"account_id":"123456789012","region":"us-east-1"}`),
			wantFields: map[string]interface{}{
				"account_id": "123456789012",
				"region":     "us-east-1",
			},
		},
		"null prior stored flat": {
			apiParams: map[string]interface{}{
				"account_id": "123456789012",
			},
			prior: jsontypes.NewNormalizedNull(),
			wantFields: map[string]interface{}{
				"account_id": "123456789012",
			},
		},
		"redacted secret restored from prior": {
			apiParams: map[string]interface{}{
				"project_id":       "my-project",
				"credentials_json": "[SECRET]",
			},
			prior: jsontypes.NewNormalizedValue(`{"project_id":"my-project","credentials_json":"real-secret"}`),
			wantFields: map[string]interface{}{
				"project_id":       "my-project",
				"credentials_json": "real-secret",
			},
		},
		"redacted secret with no prior left as-is": {
			apiParams: map[string]interface{}{
				"project_id":       "my-project",
				"credentials_json": "[SECRET]",
			},
			prior: jsontypes.NewNormalizedNull(),
			wantFields: map[string]interface{}{
				"project_id":       "my-project",
				"credentials_json": "[SECRET]",
			},
		},
		"redacted secret missing from prior left as-is": {
			apiParams: map[string]interface{}{
				"credentials_json": "[SECRET]",
			},
			prior: jsontypes.NewNormalizedValue(`{"project_id":"my-project"}`),
			wantFields: map[string]interface{}{
				"credentials_json": "[SECRET]",
			},
		},
		"nil params yields null": {
			apiParams: nil,
			prior:     jsontypes.NewNormalizedNull(),
			wantNull:  true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, diags := ngsiem.NormalizeParams(tc.apiParams, tc.prior)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags)
			}

			if tc.wantNull {
				if !got.IsNull() {
					t.Fatalf("expected null result, got %q", got.ValueString())
				}
				return
			}

			var fields map[string]interface{}
			if err := json.Unmarshal([]byte(got.ValueString()), &fields); err != nil {
				t.Fatalf("result is not valid JSON: %v (value: %q)", err, got.ValueString())
			}

			if len(fields) != len(tc.wantFields) {
				t.Fatalf("field count = %d, want %d (value: %q)", len(fields), len(tc.wantFields), got.ValueString())
			}
			for k, want := range tc.wantFields {
				if fields[k] != want {
					t.Errorf("field[%q] = %v, want %v", k, fields[k], want)
				}
			}
		})
	}
}
