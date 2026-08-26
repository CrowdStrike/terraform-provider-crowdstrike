package fcs_test

import (
	"fmt"
	"regexp"
	"slices"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/fcs"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/stretchr/testify/assert"
)

const (
	cloudAzureTenantDataSourceName                 = "data.crowdstrike_cloud_azure_tenant.test"
	cloudAzureTenantByRegistrationIDDataSourceName = "data.crowdstrike_cloud_azure_tenant.by_registration_id"
)

// TestAccCloudAzureTenantDataSource_byID drives one tenant registration through
// every shape the data source has to report: minimal, every collection populated,
// and event hubs attached. The steps share a single registration, so the whole
// matrix costs one create and one destroy.
func TestAccCloudAzureTenantDataSource_byID(t *testing.T) {
	tenantID := acctest.RandomUUID()
	mgID1, mgID2 := acctest.RandomUUID(), acctest.RandomUUID()
	subID1, subID2 := acctest.RandomUUID(), acctest.RandomUUID()
	agentlessID1, agentlessID2 := acctest.RandomUUID(), acctest.RandomUUID()

	// Attributes both read paths expose without normalizing differently. Every one
	// is compared rather than pinned to a literal, so the test keeps working when
	// the API changes a value it was not given and still fails if the two read
	// paths disagree.
	comparedAttrs := []string{
		"tenant_id",
		"account_type",
		"cs_azure_client_id",
		"cs_infra_location",
		"cs_infra_subscription_id",
		"environment",
		"resource_name_prefix",
		"resource_name_suffix",
		"realtime_visibility",
		"dspm",
		"vulnerability_scanning",
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// 1. Minimal registration: nothing optional set.
			{
				Config: testAccCloudAzureTenantDataSourceConfig_minimal(tenantID),
				ConfigStateChecks: slices.Concat(
					compareTenantAttrs(comparedAttrs),
					[]statecheck.StateCheck{
						statecheck.ExpectKnownValue(cloudAzureTenantDataSourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
						statecheck.ExpectKnownValue(cloudAzureTenantDataSourceName, tfjsonpath.New("registration_id"), knownvalue.NotNull()),
						statecheck.ExpectKnownValue(cloudAzureTenantDataSourceName, tfjsonpath.New("account_type"), knownvalue.StringExact("commercial")),
						statecheck.ExpectKnownValue(cloudAzureTenantDataSourceName, tfjsonpath.New("cs_azure_client_id"), knownvalue.NotNull()),
						statecheck.ExpectKnownValue(cloudAzureTenantDataSourceName, tfjsonpath.New("realtime_visibility").AtMapKey("enabled"), knownvalue.Bool(false)),
						statecheck.ExpectKnownValue(cloudAzureTenantDataSourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(false)),
						statecheck.ExpectKnownValue(cloudAzureTenantDataSourceName, tfjsonpath.New("vulnerability_scanning").AtMapKey("enabled"), knownvalue.Bool(false)),
						statecheck.ExpectKnownValue(cloudAzureTenantDataSourceName, tfjsonpath.New("microsoft_graph_permission_ids"),
							knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(userReadAllPermissionID)})),
						statecheck.ExpectKnownValue(cloudAzureTenantDataSourceName, tfjsonpath.New("subscription_ids"), knownvalue.ListSizeExact(0)),
						statecheck.ExpectKnownValue(cloudAzureTenantDataSourceName, tfjsonpath.New("management_group_ids"), knownvalue.ListSizeExact(0)),
						statecheck.ExpectKnownValue(cloudAzureTenantDataSourceName, tfjsonpath.New("agentless_scanning_subscription_ids"), knownvalue.ListSizeExact(0)),
						statecheck.ExpectKnownValue(cloudAzureTenantDataSourceName, tfjsonpath.New("tags"), knownvalue.MapSizeExact(0)),
						statecheck.ExpectKnownValue(cloudAzureTenantDataSourceName, tfjsonpath.New("eventhub_settings"), knownvalue.ListSizeExact(0)),
					},
				),
			},
			// 2. Every collection populated with more than one element, so a
			//    flatten that drops or reorders elements cannot pass.
			{
				Config: testAccCloudAzureTenantDataSourceConfig_populated(
					tenantID, mgID1, mgID2, subID1, subID2, agentlessID1, agentlessID2,
				),
				ConfigStateChecks: slices.Concat(
					compareTenantAttrs(append(comparedAttrs, "tags")),
					[]statecheck.StateCheck{
						// The API is not documented to preserve the order these were
						// submitted in, so the elements are asserted without it.
						// knownvalue.SetExact is order independent and accepts the
						// data source's list, since both containers serialize to a
						// JSON array.
						statecheck.ExpectKnownValue(cloudAzureTenantDataSourceName, tfjsonpath.New("microsoft_graph_permission_ids"),
							knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(userReadAllPermissionID)})),
						statecheck.ExpectKnownValue(cloudAzureTenantDataSourceName, tfjsonpath.New("subscription_ids"),
							knownvalue.SetExact([]knownvalue.Check{
								knownvalue.StringExact(subID1),
								knownvalue.StringExact(subID2),
							})),
						statecheck.ExpectKnownValue(cloudAzureTenantDataSourceName, tfjsonpath.New("management_group_ids"),
							knownvalue.SetExact([]knownvalue.Check{
								knownvalue.StringExact(mgID1),
								knownvalue.StringExact(mgID2),
							})),
						statecheck.ExpectKnownValue(cloudAzureTenantDataSourceName, tfjsonpath.New("agentless_scanning_subscription_ids"),
							knownvalue.SetExact([]knownvalue.Check{
								knownvalue.StringExact(agentlessID1),
								knownvalue.StringExact(agentlessID2),
							})),
						statecheck.ExpectKnownValue(cloudAzureTenantDataSourceName, tfjsonpath.New("tags"), knownvalue.MapExact(map[string]knownvalue.Check{
							"env":  knownvalue.StringExact("test"),
							"team": knownvalue.StringExact("security"),
						})),
						statecheck.ExpectKnownValue(cloudAzureTenantDataSourceName, tfjsonpath.New("environment"), knownvalue.StringExact("prod")),
						statecheck.ExpectKnownValue(cloudAzureTenantDataSourceName, tfjsonpath.New("resource_name_prefix"), knownvalue.StringExact("cs")),
						statecheck.ExpectKnownValue(cloudAzureTenantDataSourceName, tfjsonpath.New("resource_name_suffix"), knownvalue.StringExact("dev")),
						statecheck.ExpectKnownValue(cloudAzureTenantDataSourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(true)),
					},
				),
			},
			// 3. Event hubs attached. Two hubs of different types, since
			//    eventhub_settings is a collection of objects and that is where a
			//    flatten bug hides. The settings resource's own state is covered by
			//    its own test, so only the data source is asserted here.
			{
				Config: testAccCloudAzureTenantDataSourceConfig_eventhubs(
					tenantID, mgID1, mgID2, subID1, subID2, agentlessID1, agentlessID2,
				),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantDataSourceName, tfjsonpath.New("eventhub_settings"),
						knownvalue.SetExact([]knownvalue.Check{
							knownvalue.ObjectExact(map[string]knownvalue.Check{
								"id":             knownvalue.StringExact(testAccEventhubID(subID1, "activity")),
								"type":           knownvalue.StringExact("activity_logs"),
								"consumer_group": knownvalue.StringExact("cs-activity-logs"),
							}),
							knownvalue.ObjectExact(map[string]knownvalue.Check{
								"id":             knownvalue.StringExact(testAccEventhubID(subID1, "entra")),
								"type":           knownvalue.StringExact("entra_logs"),
								"consumer_group": knownvalue.StringExact("cs-entra-logs"),
							}),
						})),
				},
			},
			// 4. The same tenant looked up by registration_id instead of
			//    tenant_id. Both keys must resolve to the same registration.
			{
				Config: testAccCloudAzureTenantDataSourceConfig_byRegistrationID(
					tenantID, mgID1, mgID2, subID1, subID2, agentlessID1, agentlessID2,
				),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.CompareValuePairs(
						cloudAzureTenantDataSourceName, tfjsonpath.New("registration_id"),
						cloudAzureTenantByRegistrationIDDataSourceName, tfjsonpath.New("registration_id"),
						compare.ValuesSame(),
					),
					statecheck.ExpectKnownValue(
						cloudAzureTenantByRegistrationIDDataSourceName,
						tfjsonpath.New("tenant_id"),
						knownvalue.StringExact(tenantID),
					),
					statecheck.ExpectKnownValue(
						cloudAzureTenantByRegistrationIDDataSourceName,
						tfjsonpath.New("registration_id"),
						knownvalue.NotNull(),
					),
				},
			},
		},
	})
}

func TestAccCloudAzureTenantDataSource_notFound(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccCloudAzureTenantDataSourceConfig_lookup(acctest.RandomUUID()),
				ExpectError: regexp.MustCompile(tferrors.NotFoundErrorSummary),
			},
		},
	})
}

// TestAccCloudAzureTenantDataSource_lookupKeys pins the lookup key validation:
// tenant_id rejects an empty string, and exactly one of the two keys is required.
func TestAccCloudAzureTenantDataSource_lookupKeys(t *testing.T) {
	testCases := map[string]struct {
		config      string
		expectError *regexp.Regexp
	}{
		"empty tenant_id": {
			config:      testAccCloudAzureTenantDataSourceConfig_lookup(""),
			expectError: regexp.MustCompile(`Attribute tenant_id must not be empty or contain only whitespace`),
		},
		// Terraform hard-wraps diagnostic detail, so these match the part of the
		// message that fits on one line.
		"neither key set": {
			config: `data "crowdstrike_cloud_azure_tenant" "test" {}`,
			expectError: regexp.MustCompile(
				`No attribute specified when one \(and only one\) of`,
			),
		},
		"both keys set": {
			config: `
data "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id       = "00000000-0000-0000-0000-000000000000"
  registration_id = "00000000-0000-0000-0000-000000000000"
}`,
			expectError: regexp.MustCompile(
				`2 attributes specified when one \(and only one\) of`,
			),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			resource.ParallelTest(t, resource.TestCase{
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				PreCheck:                 func() { acctest.PreCheck(t) },
				Steps: []resource.TestStep{
					{
						Config:      tc.config,
						ExpectError: tc.expectError,
					},
				},
			})
		})
	}
}

// TestFlattenAzureTenantFeatures covers the feature derivation. A feature is
// enabled either by appearing under the cspm product or by having an additional
// features entry, and the API models every level of that structure as a pointer.
func TestFlattenAzureTenantFeatures(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		registration        models.AzureTenantRegistration
		wantRealtime        bool
		wantDSPM            bool
		wantVulnScanning    bool
		wantAgentlessSubIDs []string
	}{
		"empty registration disables everything": {
			registration: models.AzureTenantRegistration{},
		},
		"cspm ioa feature enables realtime visibility": {
			registration: models.AzureTenantRegistration{
				Products: []*models.DomainProductFeatures{
					{Product: utils.Addr("cspm"), Features: []string{"ioa"}},
				},
			},
			wantRealtime: true,
		},
		"cspm enables every feature it lists": {
			registration: models.AzureTenantRegistration{
				Products: []*models.DomainProductFeatures{
					{
						Product:  utils.Addr("cspm"),
						Features: []string{"ioa", "dspm", "vulnerability_scanning"},
					},
				},
			},
			wantRealtime:     true,
			wantDSPM:         true,
			wantVulnScanning: true,
		},
		// Features are only read off the cspm product, so another product
		// listing the same feature name must not enable it.
		"features on another product are ignored": {
			registration: models.AzureTenantRegistration{
				Products: []*models.DomainProductFeatures{
					{Product: utils.Addr("cwpp"), Features: []string{"ioa", "dspm"}},
				},
			},
		},
		"unknown cspm feature is ignored": {
			registration: models.AzureTenantRegistration{
				Products: []*models.DomainProductFeatures{
					{Product: utils.Addr("cspm"), Features: []string{"something_new"}},
				},
			},
		},
		// A nil product entry, or one with no name, is representable.
		"nil product entry is skipped": {
			registration: models.AzureTenantRegistration{
				Products: []*models.DomainProductFeatures{
					nil,
					{Product: utils.Addr("cspm"), Features: []string{"ioa"}},
				},
			},
			wantRealtime: true,
		},
		"product with nil name is skipped": {
			registration: models.AzureTenantRegistration{
				Products: []*models.DomainProductFeatures{
					{Product: nil, Features: []string{"ioa"}},
					{Product: utils.Addr("cspm"), Features: []string{"dspm"}},
				},
			},
			wantDSPM: true,
		},
		// An additional features entry enables its feature on its own, without a
		// matching cspm feature, and carries the agentless subscription IDs.
		"dspm additional feature enables dspm and reports subscriptions": {
			registration: models.AzureTenantRegistration{
				AdditionalFeatures: []*models.AzureAdditionalFeature{
					{
						Feature:         utils.Addr("dspm"),
						SubscriptionIds: []string{"sub-1", "sub-2"},
					},
				},
			},
			wantDSPM:            true,
			wantAgentlessSubIDs: []string{"sub-1", "sub-2"},
		},
		"vulnerability scanning additional feature enables vulnerability scanning": {
			registration: models.AzureTenantRegistration{
				AdditionalFeatures: []*models.AzureAdditionalFeature{
					{
						Feature:         utils.Addr("vulnerability_scanning"),
						SubscriptionIds: []string{"sub-1"},
					},
				},
			},
			wantVulnScanning:    true,
			wantAgentlessSubIDs: []string{"sub-1"},
		},
		"nil additional feature entry is skipped": {
			registration: models.AzureTenantRegistration{
				AdditionalFeatures: []*models.AzureAdditionalFeature{
					nil,
					{Feature: nil, SubscriptionIds: []string{"ignored"}},
					{Feature: utils.Addr("dspm"), SubscriptionIds: []string{"sub-1"}},
				},
			},
			wantDSPM:            true,
			wantAgentlessSubIDs: []string{"sub-1"},
		},
		"unknown additional feature is ignored": {
			registration: models.AzureTenantRegistration{
				AdditionalFeatures: []*models.AzureAdditionalFeature{
					{Feature: utils.Addr("something_new"), SubscriptionIds: []string{"ignored"}},
				},
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, diags := fcs.FlattenAzureTenantFeatures(t.Context(), tc.registration)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags)
			}

			want := fcs.AzureTenantFeatures{
				RealtimeVisibility:             featureObject(t, tc.wantRealtime),
				DSPM:                           featureObject(t, tc.wantDSPM),
				VulnerabilityScanning:          featureObject(t, tc.wantVulnScanning),
				AgentlessScanningSubscriptions: tc.wantAgentlessSubIDs,
			}

			assert.Equal(t, want, got)
		})
	}
}

// featureObject builds the expected object for a feature's enabled state.
func featureObject(t *testing.T, enabled bool) types.Object {
	t.Helper()

	object, diags := types.ObjectValue(
		map[string]attr.Type{"enabled": types.BoolType},
		map[string]attr.Value{"enabled": types.BoolValue(enabled)},
	)
	if diags.HasError() {
		t.Fatalf("building expected object: %v", diags)
	}

	return object
}

// compareTenantAttrs asserts the data source reports the same value as the managed
// resource for each attribute. The resource is the fixture that created the tenant,
// so its state is the expected value; the data source is what is under test. A
// mismatch means the data source's read path diverged from the resource's.
func compareTenantAttrs(attrs []string) []statecheck.StateCheck {
	checks := make([]statecheck.StateCheck, 0, len(attrs))

	for _, attr := range attrs {
		checks = append(checks, statecheck.CompareValuePairs(
			cloudAzureTenantResourceName, tfjsonpath.New(attr),
			cloudAzureTenantDataSourceName, tfjsonpath.New(attr),
			compare.ValuesSame(),
		))
	}

	return checks
}

// testAccEventhubID builds an Azure Event Hub resource ID. The test asserts the
// exact value the data source returns, so the config and the expectation must
// derive it the same way.
func testAccEventhubID(subscriptionID, name string) string {
	return fmt.Sprintf(
		"/subscriptions/%s/resourceGroups/cs-test-rg/providers/Microsoft.EventHub/namespaces/cs-test-ns/eventhubs/cs-%s-logs",
		subscriptionID,
		name,
	)
}

func testAccCloudAzureTenantDataSourceConfig_minimal(tenantID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                      = %[1]q
  microsoft_graph_permission_ids = [%[2]q]
}

data "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id = crowdstrike_cloud_azure_tenant.test.tenant_id
}`, tenantID, userReadAllPermissionID)
}

// testAccCloudAzureTenantTenantResource_populated is the tenant registration with
// every collection populated. Shared by the populated and eventhub steps so the
// registration is not mutated out from under the event hubs.
func testAccCloudAzureTenantTenantResource_populated(
	tenantID, mgID1, mgID2, subID1, subID2, agentlessID1, agentlessID2 string,
) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                           = %[1]q
  microsoft_graph_permission_ids      = [%[2]q]
  management_group_ids                = [%[3]q, %[4]q]
  subscription_ids                    = [%[5]q, %[6]q]
  agentless_scanning_subscription_ids = [%[7]q, %[8]q]
  resource_name_prefix                = "cs"
  resource_name_suffix                = "dev"
  environment                         = "prod"

  # agentless_scanning_subscription_ids requires DSPM or vulnerability scanning.
  dspm = {
    enabled = true
  }

  tags = {
    env  = "test"
    team = "security"
  }
}`, tenantID, userReadAllPermissionID, mgID1, mgID2, subID1, subID2, agentlessID1, agentlessID2)
}

func testAccCloudAzureTenantDataSourceConfig_populated(
	tenantID, mgID1, mgID2, subID1, subID2, agentlessID1, agentlessID2 string,
) string {
	return testAccCloudAzureTenantTenantResource_populated(
		tenantID, mgID1, mgID2, subID1, subID2, agentlessID1, agentlessID2,
	) + `

data "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id = crowdstrike_cloud_azure_tenant.test.tenant_id
}`
}

func testAccCloudAzureTenantDataSourceConfig_eventhubs(
	tenantID, mgID1, mgID2, subID1, subID2, agentlessID1, agentlessID2 string,
) string {
	return testAccCloudAzureTenantTenantResource_populated(
		tenantID, mgID1, mgID2, subID1, subID2, agentlessID1, agentlessID2,
	) + fmt.Sprintf(`

resource "crowdstrike_cloud_azure_tenant_eventhub_settings" "test" {
  tenant_id = crowdstrike_cloud_azure_tenant.test.tenant_id

  settings = [
    {
      type           = "activity_logs"
      id             = %[1]q
      consumer_group = "cs-activity-logs"
    },
    {
      type           = "entra_logs"
      id             = %[2]q
      consumer_group = "cs-entra-logs"
    },
  ]
}

# Depends on the settings resource so the read happens after the event hubs are
# attached, otherwise eventhub_settings would be read as empty.
data "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id = crowdstrike_cloud_azure_tenant_eventhub_settings.test.tenant_id
}`, testAccEventhubID(subID1, "activity"), testAccEventhubID(subID1, "entra"))
}

// testAccCloudAzureTenantDataSourceConfig_byRegistrationID looks the same tenant up
// twice, by tenant_id and by the registration_id that lookup reported. The resource
// does not expose registration_id, so the second lookup has to chain off the first.
func testAccCloudAzureTenantDataSourceConfig_byRegistrationID(
	tenantID, mgID1, mgID2, subID1, subID2, agentlessID1, agentlessID2 string,
) string {
	return testAccCloudAzureTenantDataSourceConfig_populated(
		tenantID, mgID1, mgID2, subID1, subID2, agentlessID1, agentlessID2,
	) + `

data "crowdstrike_cloud_azure_tenant" "by_registration_id" {
  registration_id = data.crowdstrike_cloud_azure_tenant.test.registration_id
}`
}

func testAccCloudAzureTenantDataSourceConfig_lookup(tenantID string) string {
	return fmt.Sprintf(`
data "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id = %[1]q
}`, tenantID)
}
