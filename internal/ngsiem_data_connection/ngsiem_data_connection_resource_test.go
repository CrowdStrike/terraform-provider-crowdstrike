package ngsiemdataconnection_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const hecConnectorName = "HEC / HTTP Event Connector"

const criblConnectorName = "Cribl Data Connector"

const resourceName = "crowdstrike_ngsiem_data_connection.test"

// importStateIDFunc builds the composite import ID `connector_id:connection_id` from prior state.
func importStateIDFunc(s *terraform.State) (string, error) {
	rs, ok := s.RootModule().Resources[resourceName]
	if !ok {
		return "", fmt.Errorf("resource not found: %s", resourceName)
	}
	return rs.Primary.Attributes["connector_id"] + ":" + rs.Primary.ID, nil
}

// importIgnore lists the attributes that legitimately do not round-trip on import: the write-once
// token/url/expiry (unrecoverable), and the config-only fields the read API never returns (parser is
// returned as a possibly-normalized parser_name and so is deliberately not refreshed).
var importIgnore = []string{
	"ingest_token", "ingest_url", "token_expires_at",
	"parser", "description",
	"enable_host_enrichment", "enable_user_enrichment", "log_sources",
}

func TestAccNgsiemDataConnectionResource_basic(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConnectionConfig(rName, "initial"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("connector_id"), knownvalue.NotNull()),
					// Non-empty, not just non-null: NotNull() would pass for "", which wouldn't be a usable token.
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("ingest_token"), knownvalue.StringRegexp(regexp.MustCompile(`.+`))),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("ingest_url"), knownvalue.StringRegexp(regexp.MustCompile(`^https://`))),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("status"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateIdFunc:       importStateIDFunc,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importIgnore,
			},
		},
	})
}

// In-place updates (name, parser, description) must preserve the connection id and its write-once
// ingest token.
func TestAccNgsiemDataConnectionResource_updateInPlacePreservesToken(t *testing.T) {
	rName := acctest.RandomResourceName()

	idSame := statecheck.CompareValue(compare.ValuesSame())
	tokenSame := statecheck.CompareValue(compare.ValuesSame())

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConnectionConfig(rName, "before"),
				ConfigStateChecks: []statecheck.StateCheck{
					idSame.AddStateValue(resourceName, tfjsonpath.New("id")),
					tokenSame.AddStateValue(resourceName, tfjsonpath.New("ingest_token")),
				},
			},
			{
				Config: testAccConnectionConfig(rName, "after"),
				ConfigStateChecks: []statecheck.StateCheck{
					idSame.AddStateValue(resourceName, tfjsonpath.New("id")),
					tokenSame.AddStateValue(resourceName, tfjsonpath.New("ingest_token")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("after")),
				},
			},
		},
	})
}

// Toggling enrichment is an in-place update: the connection id and its write-once ingest token are
// preserved (no recreate, no token rotation).
func TestAccNgsiemDataConnectionResource_updateEnrichmentInPlace(t *testing.T) {
	rName := acctest.RandomResourceName()

	idSame := statecheck.CompareValue(compare.ValuesSame())
	tokenSame := statecheck.CompareValue(compare.ValuesSame())

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConnectionConfigEnrichment(rName, false),
				ConfigStateChecks: []statecheck.StateCheck{
					idSame.AddStateValue(resourceName, tfjsonpath.New("id")),
					tokenSame.AddStateValue(resourceName, tfjsonpath.New("ingest_token")),
				},
			},
			{
				Config: testAccConnectionConfigEnrichment(rName, true),
				ConfigStateChecks: []statecheck.StateCheck{
					idSame.AddStateValue(resourceName, tfjsonpath.New("id")),
					tokenSame.AddStateValue(resourceName, tfjsonpath.New("ingest_token")),
				},
			},
		},
	})
}

// Clearing a previously-set description is an in-place update (the empty value is sent explicitly),
// so it must NOT recreate the connection: the id and the write-once ingest token are preserved.
func TestAccNgsiemDataConnectionResource_clearDescriptionInPlace(t *testing.T) {
	rName := acctest.RandomResourceName()

	idSame := statecheck.CompareValue(compare.ValuesSame())
	tokenSame := statecheck.CompareValue(compare.ValuesSame())

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConnectionConfig(rName, "has-a-description"),
				ConfigStateChecks: []statecheck.StateCheck{
					idSame.AddStateValue(resourceName, tfjsonpath.New("id")),
					tokenSame.AddStateValue(resourceName, tfjsonpath.New("ingest_token")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("has-a-description")),
				},
			},
			{
				Config: testAccConnectionConfigNoDescription(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					idSame.AddStateValue(resourceName, tfjsonpath.New("id")),
					tokenSame.AddStateValue(resourceName, tfjsonpath.New("ingest_token")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.Null()),
				},
			},
		},
	})
}

func testAccConnectionConfigNoDescription(name string) string {
	return fmt.Sprintf(`
data "crowdstrike_ngsiem_data_connectors" "hec" {
  by_name = %[1]q
}

resource "crowdstrike_ngsiem_data_connection" "test" {
  name         = %[2]q
  connector_id = data.crowdstrike_ngsiem_data_connectors.hec.id
  parser       = "aws-cloudtrail"
}
`, hecConnectorName, name)
}

func testAccConnectionConfig(name, description string) string {
	return fmt.Sprintf(`
data "crowdstrike_ngsiem_data_connectors" "hec" {
  by_name = %[1]q
}

resource "crowdstrike_ngsiem_data_connection" "test" {
  name         = %[2]q
  connector_id = data.crowdstrike_ngsiem_data_connectors.hec.id
  parser       = "aws-cloudtrail"
  description  = %[3]q
}
`, hecConnectorName, name, description)
}

func testAccConnectionConfigEnrichment(name string, hostEnrichment bool) string {
	return fmt.Sprintf(`
data "crowdstrike_ngsiem_data_connectors" "hec" {
  by_name = %[1]q
}

resource "crowdstrike_ngsiem_data_connection" "test" {
  name                   = %[2]q
  connector_id           = data.crowdstrike_ngsiem_data_connectors.hec.id
  parser                 = "aws-cloudtrail"
  enable_host_enrichment = %[3]t
}
`, hecConnectorName, name, hostEnrichment)
}

// Changing connector_id is a force-replace: the connection is recreated, so a new id is assigned and a
// fresh ingest token is minted. This guards the documented "issues a new token" behavior that the
// in-place update tests deliberately assert is NOT triggered. connector_id is the only force-replace
// attribute; swapping HEC -> Cribl (both push connectors that issue tokens) exercises it.
func TestAccNgsiemDataConnectionResource_replaceRotatesToken(t *testing.T) {
	rName := acctest.RandomResourceName()

	idDiffer := statecheck.CompareValue(compare.ValuesDiffer())
	tokenDiffer := statecheck.CompareValue(compare.ValuesDiffer())

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConnectionConfigConnector(rName, hecConnectorName),
				ConfigStateChecks: []statecheck.StateCheck{
					idDiffer.AddStateValue(resourceName, tfjsonpath.New("id")),
					tokenDiffer.AddStateValue(resourceName, tfjsonpath.New("ingest_token")),
				},
			},
			{
				Config: testAccConnectionConfigConnector(rName, criblConnectorName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionReplace),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					idDiffer.AddStateValue(resourceName, tfjsonpath.New("id")),
					tokenDiffer.AddStateValue(resourceName, tfjsonpath.New("ingest_token")),
				},
			},
		},
	})
}

// Changing log_sources is an in-place update (not a replace): the connection id and its write-once
// ingest token are preserved.
func TestAccNgsiemDataConnectionResource_updateLogSourcesInPlace(t *testing.T) {
	rName := acctest.RandomResourceName()

	idSame := statecheck.CompareValue(compare.ValuesSame())
	tokenSame := statecheck.CompareValue(compare.ValuesSame())

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConnectionConfigLogSources(rName, `["source-a"]`),
				ConfigStateChecks: []statecheck.StateCheck{
					idSame.AddStateValue(resourceName, tfjsonpath.New("id")),
					tokenSame.AddStateValue(resourceName, tfjsonpath.New("ingest_token")),
				},
			},
			{
				Config: testAccConnectionConfigLogSources(rName, `["source-a", "source-b"]`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					idSame.AddStateValue(resourceName, tfjsonpath.New("id")),
					tokenSame.AddStateValue(resourceName, tfjsonpath.New("ingest_token")),
				},
			},
		},
	})
}

func testAccConnectionConfigConnector(name, connectorName string) string {
	return fmt.Sprintf(`
data "crowdstrike_ngsiem_data_connectors" "c" {
  by_name = %[2]q
}

resource "crowdstrike_ngsiem_data_connection" "test" {
  name         = %[1]q
  connector_id = data.crowdstrike_ngsiem_data_connectors.c.id
  parser       = "aws-cloudtrail"
}
`, name, connectorName)
}

func testAccConnectionConfigLogSources(name, logSources string) string {
	return fmt.Sprintf(`
data "crowdstrike_ngsiem_data_connectors" "hec" {
  by_name = %[1]q
}

resource "crowdstrike_ngsiem_data_connection" "test" {
  name         = %[2]q
  connector_id = data.crowdstrike_ngsiem_data_connectors.hec.id
  parser       = "aws-cloudtrail"
  log_sources  = %[3]s
}
`, hecConnectorName, name, logSources)
}

// Schema validators reject bad config at plan time (no API call, no resource created). A literal
// connector_id keeps these offline — there's no data source read to resolve.
func TestAccNgsiemDataConnectionResource_validation(t *testing.T) {
	notWhitespace := regexp.MustCompile(`must not be empty or contain only`)
	atLeastOne := regexp.MustCompile(`(?s)list must contain at least 1 element`)

	for _, tc := range []struct {
		name        string
		attrs       string
		expectError *regexp.Regexp
	}{
		{
			name:        "name_whitespace_only",
			attrs:       "  name   = \"   \"\n  parser = \"aws-cloudtrail\"",
			expectError: notWhitespace,
		},
		{
			name:        "parser_whitespace_only",
			attrs:       "  name   = \"valid-name\"\n  parser = \"   \"",
			expectError: notWhitespace,
		},
		{
			name:        "description_whitespace_only",
			attrs:       "  name        = \"valid-name\"\n  parser      = \"aws-cloudtrail\"\n  description = \"   \"",
			expectError: notWhitespace,
		},
		{
			name:        "log_sources_empty",
			attrs:       "  name        = \"valid-name\"\n  parser      = \"aws-cloudtrail\"\n  log_sources = []",
			expectError: atLeastOne,
		},
		{
			name:        "log_sources_whitespace_element",
			attrs:       "  name        = \"valid-name\"\n  parser      = \"aws-cloudtrail\"\n  log_sources = [\"   \"]",
			expectError: notWhitespace,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { acctest.PreCheck(t) },
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config:      testAccConnectionConfigValidation(tc.attrs),
						PlanOnly:    true,
						ExpectError: tc.expectError,
					},
				},
			})
		})
	}
}

func testAccConnectionConfigValidation(attrs string) string {
	return fmt.Sprintf(`
resource "crowdstrike_ngsiem_data_connection" "test" {
  connector_id = "placeholder-connector-id"
%s
}
`, attrs)
}

// A non-installed parser name (e.g. "json") is rejected by the API at create time with a 400, so the
// connection is never created and no token is ever requested. This pins that documented rejection end to
// end (verified live: the create call returns 400, not the token endpoint).
func TestAccNgsiemDataConnectionResource_invalidParser(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccConnectionConfigParser(rName, "json"),
				ExpectError: regexp.MustCompile(`Failed to create: 400`),
			},
		},
	})
}

func testAccConnectionConfigParser(name, parser string) string {
	return fmt.Sprintf(`
data "crowdstrike_ngsiem_data_connectors" "hec" {
  by_name = %[1]q
}

resource "crowdstrike_ngsiem_data_connection" "test" {
  name         = %[2]q
  connector_id = data.crowdstrike_ngsiem_data_connectors.hec.id
  parser       = %[3]q
}
`, hecConnectorName, name, parser)
}
