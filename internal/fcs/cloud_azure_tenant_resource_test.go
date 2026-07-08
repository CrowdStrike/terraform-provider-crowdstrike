package fcs_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const (
	cloudAzureTenantResourceName = "crowdstrike_cloud_azure_tenant.test"
	userReadAllPermissionID      = "df021288-bdef-4463-88db-98f22de89214"
)

func TestAccCloudAzureTenant_basic(t *testing.T) {
	tenantID := acctest.RandomUUID()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAzureTenantConfig_basic(tenantID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("microsoft_graph_permission_ids"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(userReadAllPermissionID)})),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("cs_azure_client_id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("account_type"), knownvalue.StringExact("commercial")),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("realtime_visibility").AtMapKey("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("resource_name_prefix"), knownvalue.StringExact("")),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("resource_name_suffix"), knownvalue.StringExact("")),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("environment"), knownvalue.StringExact("")),
				},
			},
			{
				ResourceName:                         cloudAzureTenantResourceName,
				ImportState:                          true,
				ImportStateId:                        tenantID,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "tenant_id",
			},
		},
	})
}

func TestAccCloudAzureTenant_update(t *testing.T) {
	tenantID := acctest.RandomUUID()
	subID1 := acctest.RandomUUID()
	subID2 := acctest.RandomUUID()
	subID3 := acctest.RandomUUID()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAzureTenantConfig_withSubscription(tenantID, subID1),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("microsoft_graph_permission_ids"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(userReadAllPermissionID)})),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("subscription_ids"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(subID1)})),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("cs_azure_client_id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("account_type"), knownvalue.StringExact("commercial")),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("realtime_visibility").AtMapKey("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tags"), knownvalue.Null()),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("management_group_ids"), knownvalue.Null()),
				},
			},
			{
				Config: testAccCloudAzureTenantConfig_updated(tenantID, subID2),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("microsoft_graph_permission_ids"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(userReadAllPermissionID)})),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("subscription_ids"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(subID2)})),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("realtime_visibility").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("resource_name_prefix"), knownvalue.StringExact("cs")),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("resource_name_suffix"), knownvalue.StringExact("dev")),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("environment"), knownvalue.StringExact("prod")),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tags"), knownvalue.MapExact(map[string]knownvalue.Check{
						"env":  knownvalue.StringExact("test"),
						"team": knownvalue.StringExact("security"),
					})),
				},
			},
			{
				Config: testAccCloudAzureTenantConfig_withSubscription(tenantID, subID3),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("subscription_ids"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(subID3)})),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("realtime_visibility").AtMapKey("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("resource_name_prefix"), knownvalue.StringExact("")),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("resource_name_suffix"), knownvalue.StringExact("")),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("environment"), knownvalue.StringExact("")),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tags"), knownvalue.Null()),
				},
			},
			{
				ResourceName:                         cloudAzureTenantResourceName,
				ImportState:                          true,
				ImportStateId:                        tenantID,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "tenant_id",
			},
		},
	})
}

func TestAccCloudAzureTenant_managementGroups(t *testing.T) {
	tenantID := acctest.RandomUUID()
	mgID := acctest.RandomUUID()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAzureTenantConfig_withManagementGroup(tenantID, mgID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("management_group_ids"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(mgID)})),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("subscription_ids"), knownvalue.Null()),
				},
			},
		},
	})
}

func TestAccCloudAzureTenant_emptyIdLists(t *testing.T) {
	tenantID := acctest.RandomUUID()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAzureTenantConfig_basic(tenantID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("subscription_ids"), knownvalue.Null()),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("management_group_ids"), knownvalue.Null()),
				},
			},
			{
				Config: testAccCloudAzureTenantConfig_emptyIdLists(tenantID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("subscription_ids"), knownvalue.SetSizeExact(0)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("management_group_ids"), knownvalue.SetSizeExact(0)),
				},
			},
			{
				Config: testAccCloudAzureTenantConfig_basic(tenantID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("subscription_ids"), knownvalue.Null()),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("management_group_ids"), knownvalue.Null()),
				},
			},
		},
	})
}

func TestAccCloudAzureTenant_tags(t *testing.T) {
	tenantID := acctest.RandomUUID()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAzureTenantConfig_withTags(tenantID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tags"), knownvalue.MapExact(map[string]knownvalue.Check{
						"env":  knownvalue.StringExact("test"),
						"team": knownvalue.StringExact("security"),
					})),
				},
			},
		},
	})
}

func TestAccCloudAzureTenant_affixes(t *testing.T) {
	tenantID := acctest.RandomUUID()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccCloudAzureTenantConfig_withAffixes(tenantID, "prefix", "suffix"),
				ExpectError: regexp.MustCompile("Invalid affixes"),
			},
			{
				Config: testAccCloudAzureTenantConfig_withAffixes(tenantID, "cs", "dev"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("resource_name_prefix"), knownvalue.StringExact("cs")),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("resource_name_suffix"), knownvalue.StringExact("dev")),
				},
			},
		},
	})
}

func TestAccCloudAzureTenant_environment(t *testing.T) {
	tenantID := acctest.RandomUUID()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccCloudAzureTenantConfig_withEnvironment(tenantID, "toolong"),
				ExpectError: regexp.MustCompile("length must be at most 4"),
			},
			{
				Config: testAccCloudAzureTenantConfig_withEnvironment(tenantID, "prod"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("environment"), knownvalue.StringExact("prod")),
				},
			},
		},
	})
}

func TestAccCloudAzureTenant_csInfra(t *testing.T) {
	tenantID := acctest.RandomUUID()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAzureTenantConfig_csInfra(tenantID, "", ""),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("cs_infra_subscription_id"), knownvalue.StringExact("")),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("cs_infra_location"), knownvalue.StringExact("")),
				},
			},
			{
				Config: testAccCloudAzureTenantConfig_csInfra(tenantID, tenantID, "westus"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("cs_infra_subscription_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("cs_infra_location"), knownvalue.StringExact("westus")),
				},
			},
			// TODO: API silently ignores empty-string clears for cs_infra_subscription_id
			// and cs_infra_location, so unsetting after set is not currently supported.
			// {
			// 	Config: testAccCloudAzureTenantConfig_basic(tenantID),
			// 	ConfigStateChecks: []statecheck.StateCheck{
			// 		statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
			// 		statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("cs_infra_subscription_id"), knownvalue.Null()),
			// 		statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("cs_infra_location"), knownvalue.Null()),
			// 	},
			// },
		},
	})
}

func TestAccCloudAzureTenant_realtimeVisibility(t *testing.T) {
	tenantID := acctest.RandomUUID()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAzureTenantConfig_basic(tenantID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("realtime_visibility").AtMapKey("enabled"), knownvalue.Bool(false)),
				},
			},
			{
				Config: testAccCloudAzureTenantConfig_rtvEnabled(tenantID, true),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("realtime_visibility").AtMapKey("enabled"), knownvalue.Bool(true)),
				},
			},
			{
				Config: testAccCloudAzureTenantConfig_rtvEnabled(tenantID, false),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("realtime_visibility").AtMapKey("enabled"), knownvalue.Bool(false)),
				},
			},
		},
	})
}

func TestAccCloudAzureTenant_dspm(t *testing.T) {
	tenantID := acctest.RandomUUID()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAzureTenantConfig_basic(tenantID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(false)),
				},
			},
			{
				Config: testAccCloudAzureTenantConfig_dspmEnabled(tenantID, true),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(true)),
				},
			},
			{
				Config: testAccCloudAzureTenantConfig_dspmEnabled(tenantID, false),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(false)),
				},
			},
		},
	})
}

func TestAccCloudAzureTenant_emptyGraphPermissions(t *testing.T) {
	tenantID := acctest.RandomUUID()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAzureTenantConfig_emptyGraphPermissions(tenantID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("microsoft_graph_permission_ids"), knownvalue.SetSizeExact(0)),
				},
			},
		},
	})
}

func TestAccCloudAzureTenant_agentlessScanningSubscriptionIds(t *testing.T) {
	tenantID := acctest.RandomUUID()
	mgID := acctest.RandomUUID()
	subID1 := acctest.RandomUUID()
	subID2 := acctest.RandomUUID()
	subID3 := acctest.RandomUUID()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAzureTenantConfig_withManagementGroup(tenantID, mgID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("management_group_ids"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(mgID)})),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("agentless_scanning_subscription_ids"), knownvalue.Null()),
				},
			},
			{
				Config: testAccCloudAzureTenantConfig_withAgentlessSubIds(tenantID, mgID, subID1, subID2),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("management_group_ids"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(mgID)})),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("agentless_scanning_subscription_ids"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact(subID1),
						knownvalue.StringExact(subID2),
					})),
				},
			},
			{
				Config: testAccCloudAzureTenantConfig_withAgentlessSubIds(tenantID, mgID, subID2, subID3),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("agentless_scanning_subscription_ids"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact(subID2),
						knownvalue.StringExact(subID3),
					})),
				},
			},
			{
				ResourceName:                         cloudAzureTenantResourceName,
				ImportState:                          true,
				ImportStateId:                        tenantID,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "tenant_id",
			},
			{
				Config: testAccCloudAzureTenantConfig_withManagementGroup(tenantID, mgID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("agentless_scanning_subscription_ids"), knownvalue.Null()),
				},
			},
		},
	})
}

func TestAccCloudAzureTenant_agentlessScanningSubscriptionIdsTenantWide(t *testing.T) {
	tenantID := acctest.RandomUUID()
	subID1 := acctest.RandomUUID()
	subID2 := acctest.RandomUUID()
	subID3 := acctest.RandomUUID()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAzureTenantConfig_basic(tenantID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("agentless_scanning_subscription_ids"), knownvalue.Null()),
				},
			},
			{
				Config: testAccCloudAzureTenantConfig_tenantWideWithAgentlessSubIds(tenantID, subID1, subID2),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("agentless_scanning_subscription_ids"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact(subID1),
						knownvalue.StringExact(subID2),
					})),
				},
			},
			{
				Config: testAccCloudAzureTenantConfig_tenantWideWithAgentlessSubIds(tenantID, subID2, subID3),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("agentless_scanning_subscription_ids"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact(subID2),
						knownvalue.StringExact(subID3),
					})),
				},
			},
			{
				ResourceName:                         cloudAzureTenantResourceName,
				ImportState:                          true,
				ImportStateId:                        tenantID,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "tenant_id",
			},
			{
				Config: testAccCloudAzureTenantConfig_basic(tenantID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("agentless_scanning_subscription_ids"), knownvalue.Null()),
				},
			},
		},
	})
}

func TestAccCloudAzureTenant_agentlessSubIdsRequiresDSPMOrVulnScanning(t *testing.T) {
	tenantID := acctest.RandomUUID()
	subID1 := acctest.RandomUUID()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccCloudAzureTenantConfig_agentlessSubIdsNoDSPM(tenantID, subID1),
				ExpectError: regexp.MustCompile(`agentless_scanning_subscription_ids requires dspm or vulnerability_scanning\s+to be enabled`),
			},
		},
	})
}

func TestAccCloudAzureTenant_agentless_UnknownDSPMEnabled(t *testing.T) {
	tenantID := acctest.RandomUUID()
	subID1 := acctest.RandomUUID()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAzureTenantConfig_agentlessSubIdsUnknownDSPM(tenantID, subID1, true),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("agentless_scanning_subscription_ids"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact(subID1),
					})),
				},
			},
			{
				Config:      testAccCloudAzureTenantConfig_agentlessSubIdsUnknownDSPM(tenantID, subID1, false),
				ExpectError: regexp.MustCompile(`agentless_scanning_subscription_ids requires dspm or vulnerability_scanning\s+to be enabled`),
			},
			{
				Config:      testAccCloudAzureTenantConfig_agentlessSubIdsNoDSPM(tenantID, subID1),
				ExpectError: regexp.MustCompile(`agentless_scanning_subscription_ids requires dspm or vulnerability_scanning\s+to be enabled`),
			},
		},
	})
}

func TestAccCloudAzureTenant_agentless_UnknownSubIds(t *testing.T) {
	tenantID := acctest.RandomUUID()
	subID1 := acctest.RandomUUID()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAzureTenantConfig_unknownAgentlessSubIds(tenantID, subID1, true),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("agentless_scanning_subscription_ids"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact(subID1),
					})),
				},
			},
			{
				Config:      testAccCloudAzureTenantConfig_unknownAgentlessSubIds(tenantID, subID1, false),
				ExpectError: regexp.MustCompile(`agentless_scanning_subscription_ids requires dspm or vulnerability_scanning\s+to be enabled`),
			},
		},
	})
}

func TestAccCloudAzureTenant_agentless_UnknownDSPMObject(t *testing.T) {
	tenantID := acctest.RandomUUID()
	subID1 := acctest.RandomUUID()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAzureTenantConfig_unknownDSPMObject(tenantID, subID1, true),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("agentless_scanning_subscription_ids"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact(subID1),
					})),
				},
			},
			{
				Config:      testAccCloudAzureTenantConfig_unknownDSPMObject(tenantID, subID1, false),
				ExpectError: regexp.MustCompile(`agentless_scanning_subscription_ids requires dspm or vulnerability_scanning\s+to be enabled`),
			},
		},
	})
}

func TestAccCloudAzureTenant_agentless_UnknownVulnerabilityScanningEnabled(t *testing.T) {
	tenantID := acctest.RandomUUID()
	subID1 := acctest.RandomUUID()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAzureTenantConfig_agentlessSubIdsUnknownVulnScanning(tenantID, subID1, true),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("vulnerability_scanning").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("agentless_scanning_subscription_ids"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact(subID1),
					})),
				},
			},
			{
				Config:      testAccCloudAzureTenantConfig_agentlessSubIdsUnknownVulnScanning(tenantID, subID1, false),
				ExpectError: regexp.MustCompile(`agentless_scanning_subscription_ids requires dspm or vulnerability_scanning\s+to be enabled`),
			},
		},
	})
}

func TestAccCloudAzureTenant_agentlessSubIdsShapeTransitions(t *testing.T) {
	tenantID := acctest.RandomUUID()
	subID1 := acctest.RandomUUID()
	subID2 := acctest.RandomUUID()

	importStep := resource.TestStep{
		ResourceName:                         cloudAzureTenantResourceName,
		ImportState:                          true,
		ImportStateId:                        tenantID,
		ImportStateVerify:                    true,
		ImportStateVerifyIdentifierAttribute: "tenant_id",
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAzureTenantConfig_basic(tenantID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("tenant_id"), knownvalue.StringExact(tenantID)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("agentless_scanning_subscription_ids"), knownvalue.Null()),
				},
			},
			{
				Config: testAccCloudAzureTenantConfig_dspmEnabled(tenantID, true),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("agentless_scanning_subscription_ids"), knownvalue.Null()),
				},
			},
			importStep,
			{
				Config: testAccCloudAzureTenantConfig_tenantWideWithAgentlessSubIds(tenantID, subID1, subID2),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("agentless_scanning_subscription_ids"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact(subID1),
						knownvalue.StringExact(subID2),
					})),
				},
			},
			importStep,
			{
				Config: testAccCloudAzureTenantConfig_dspmEnabled(tenantID, true),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("agentless_scanning_subscription_ids"), knownvalue.Null()),
				},
			},
			importStep,
			{
				Config: testAccCloudAzureTenantConfig_basic(tenantID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("agentless_scanning_subscription_ids"), knownvalue.Null()),
				},
			},
		},
	})
}

// Config helpers

func testAccCloudAzureTenantConfig_basic(tenantID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                      = %[1]q
  microsoft_graph_permission_ids = [%[2]q]
}`, tenantID, userReadAllPermissionID)
}

func testAccCloudAzureTenantConfig_withSubscription(tenantID, subscriptionID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                      = %[1]q
  microsoft_graph_permission_ids = [%[2]q]
  subscription_ids               = [%[3]q]
}`, tenantID, userReadAllPermissionID, subscriptionID)
}

func testAccCloudAzureTenantConfig_updated(tenantID, subscriptionID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                      = %[1]q
  microsoft_graph_permission_ids = [%[2]q]
  subscription_ids               = [%[3]q]
  realtime_visibility = {
    enabled = true
  }
  dspm = {
    enabled = true
  }
  resource_name_prefix = "cs"
  resource_name_suffix = "dev"
  environment          = "prod"
  tags = {
    env  = "test"
    team = "security"
  }
}`, tenantID, userReadAllPermissionID, subscriptionID)
}

func testAccCloudAzureTenantConfig_withManagementGroup(tenantID, managementGroupID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                      = %[1]q
  microsoft_graph_permission_ids = [%[2]q]
  management_group_ids           = [%[3]q]
}`, tenantID, userReadAllPermissionID, managementGroupID)
}

func testAccCloudAzureTenantConfig_emptyIdLists(tenantID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                      = %[1]q
  microsoft_graph_permission_ids = [%[2]q]
  subscription_ids               = []
  management_group_ids           = []
}`, tenantID, userReadAllPermissionID)
}

func testAccCloudAzureTenantConfig_withTags(tenantID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                      = %[1]q
  microsoft_graph_permission_ids = [%[2]q]
  tags = {
    env  = "test"
    team = "security"
  }
}`, tenantID, userReadAllPermissionID)
}

func testAccCloudAzureTenantConfig_withAffixes(tenantID, prefix, suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                      = %[1]q
  microsoft_graph_permission_ids = [%[2]q]
  resource_name_prefix           = %[3]q
  resource_name_suffix           = %[4]q
}`, tenantID, userReadAllPermissionID, prefix, suffix)
}

func testAccCloudAzureTenantConfig_withEnvironment(tenantID, env string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                      = %[1]q
  microsoft_graph_permission_ids = [%[2]q]
  environment                    = %[3]q
}`, tenantID, userReadAllPermissionID, env)
}

func testAccCloudAzureTenantConfig_csInfra(tenantID, csInfraSubscriptionID, csInfraLocation string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                      = %[1]q
  microsoft_graph_permission_ids = [%[2]q]
  cs_infra_subscription_id       = %[3]q
  cs_infra_location              = %[4]q
}`, tenantID, userReadAllPermissionID, csInfraSubscriptionID, csInfraLocation)
}

func testAccCloudAzureTenantConfig_rtvEnabled(tenantID string, enabled bool) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                      = %[1]q
  microsoft_graph_permission_ids = [%[2]q]
  realtime_visibility = {
    enabled = %[3]t
  }
}`, tenantID, userReadAllPermissionID, enabled)
}

func testAccCloudAzureTenantConfig_dspmEnabled(tenantID string, enabled bool) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                      = %[1]q
  microsoft_graph_permission_ids = [%[2]q]
  dspm = {
    enabled = %[3]t
  }
}`, tenantID, userReadAllPermissionID, enabled)
}

func testAccCloudAzureTenantConfig_emptyGraphPermissions(tenantID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                      = %[1]q
  microsoft_graph_permission_ids = []
}`, tenantID)
}

func testAccCloudAzureTenantConfig_withAgentlessSubIds(tenantID, mgID, subID1, subID2 string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                              = %[1]q
  microsoft_graph_permission_ids         = [%[2]q]
  management_group_ids                   = [%[3]q]
  agentless_scanning_subscription_ids    = [%[4]q, %[5]q]
  dspm = {
    enabled = true
  }
}`, tenantID, userReadAllPermissionID, mgID, subID1, subID2)
}

func testAccCloudAzureTenantConfig_tenantWideWithAgentlessSubIds(tenantID, subID1, subID2 string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                              = %[1]q
  microsoft_graph_permission_ids         = [%[2]q]
  agentless_scanning_subscription_ids    = [%[3]q, %[4]q]
  dspm = {
    enabled = true
  }
}`, tenantID, userReadAllPermissionID, subID1, subID2)
}

func testAccCloudAzureTenantConfig_agentlessSubIdsNoDSPM(tenantID, subID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                              = %[1]q
  microsoft_graph_permission_ids         = [%[2]q]
  agentless_scanning_subscription_ids    = [%[3]q]
}`, tenantID, userReadAllPermissionID, subID)
}

func testAccCloudAzureTenantConfig_agentlessSubIdsUnknownDSPM(tenantID, subID string, enabled bool) string {
	return fmt.Sprintf(`
resource "terraform_data" "dspm_flag" {
  input = %[4]t
}

resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                           = %[1]q
  microsoft_graph_permission_ids      = [%[2]q]
  agentless_scanning_subscription_ids = [%[3]q]
  dspm = {
    enabled = tobool(terraform_data.dspm_flag.output)
  }
}`, tenantID, userReadAllPermissionID, subID, enabled)
}

func testAccCloudAzureTenantConfig_unknownAgentlessSubIds(tenantID, subID string, dspmEnabled bool) string {
	return fmt.Sprintf(`
resource "terraform_data" "sub_id" {
  input = %[3]q
}

resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                           = %[1]q
  microsoft_graph_permission_ids      = [%[2]q]
  agentless_scanning_subscription_ids = [tostring(terraform_data.sub_id.output)]
  dspm = {
    enabled = %[4]t
  }
}`, tenantID, userReadAllPermissionID, subID, dspmEnabled)
}

func testAccCloudAzureTenantConfig_unknownDSPMObject(tenantID, subID string, enabled bool) string {
	return fmt.Sprintf(`
resource "terraform_data" "dspm_obj" {
  input = {
    enabled = %[4]t
  }
}

resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                           = %[1]q
  microsoft_graph_permission_ids      = [%[2]q]
  agentless_scanning_subscription_ids = [%[3]q]
  dspm                                = terraform_data.dspm_obj.output
}`, tenantID, userReadAllPermissionID, subID, enabled)
}

func testAccCloudAzureTenantConfig_agentlessSubIdsUnknownVulnScanning(tenantID, subID string, enabled bool) string {
	return fmt.Sprintf(`
resource "terraform_data" "vuln_scanning_flag" {
  input = %[4]t
}

resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                           = %[1]q
  microsoft_graph_permission_ids      = [%[2]q]
  agentless_scanning_subscription_ids = [%[3]q]
  vulnerability_scanning = {
    enabled = tobool(terraform_data.vuln_scanning_flag.output)
  }
}`, tenantID, userReadAllPermissionID, subID, enabled)
}

func TestAccCloudAzureTenant_vulnerabilityScanning(t *testing.T) {
	tenantID := acctest.RandomUUID()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAzureTenantConfig_basic(tenantID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("vulnerability_scanning").AtMapKey("enabled"), knownvalue.Bool(false)),
				},
			},
			{
				Config: testAccCloudAzureTenantConfig_vulnScanningEnabled(tenantID, true),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("vulnerability_scanning").AtMapKey("enabled"), knownvalue.Bool(true)),
				},
			},
			{
				Config: testAccCloudAzureTenantConfig_vulnScanningEnabled(tenantID, false),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("vulnerability_scanning").AtMapKey("enabled"), knownvalue.Bool(false)),
				},
			},
		},
	})
}

func TestAccCloudAzureTenant_vulnScanningWithSubscriptionIds(t *testing.T) {
	tenantID := acctest.RandomUUID()
	subID1 := acctest.RandomUUID()
	subID2 := acctest.RandomUUID()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAzureTenantConfig_vulnScanningWithSubIds(tenantID, subID1, subID2),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("vulnerability_scanning").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("agentless_scanning_subscription_ids"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact(subID1),
						knownvalue.StringExact(subID2),
					})),
				},
			},
			{
				ResourceName:                         cloudAzureTenantResourceName,
				ImportState:                          true,
				ImportStateId:                        tenantID,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "tenant_id",
			},
		},
	})
}

func TestAccCloudAzureTenant_vulnScanningAndDSPM(t *testing.T) {
	tenantID := acctest.RandomUUID()
	subID1 := acctest.RandomUUID()
	subID2 := acctest.RandomUUID()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAzureTenantConfig_vulnScanningAndDSPM(tenantID, subID1, subID2),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("vulnerability_scanning").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("agentless_scanning_subscription_ids"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact(subID1),
						knownvalue.StringExact(subID2),
					})),
				},
			},
			{
				ResourceName:                         cloudAzureTenantResourceName,
				ImportState:                          true,
				ImportStateId:                        tenantID,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "tenant_id",
			},
			{
				Config: testAccCloudAzureTenantConfig_vulnScanningEnabled(tenantID, true),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("vulnerability_scanning").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("agentless_scanning_subscription_ids"), knownvalue.Null()),
				},
			},
		},
	})
}

func testAccCloudAzureTenantConfig_vulnScanningEnabled(tenantID string, enabled bool) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                      = %[1]q
  microsoft_graph_permission_ids = [%[2]q]
  vulnerability_scanning = {
    enabled = %[3]t
  }
}`, tenantID, userReadAllPermissionID, enabled)
}

func testAccCloudAzureTenantConfig_vulnScanningWithSubIds(tenantID, subID1, subID2 string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                           = %[1]q
  microsoft_graph_permission_ids      = [%[2]q]
  agentless_scanning_subscription_ids = [%[3]q, %[4]q]
  vulnerability_scanning = {
    enabled = true
  }
}`, tenantID, userReadAllPermissionID, subID1, subID2)
}

func testAccCloudAzureTenantConfig_vulnScanningAndDSPM(tenantID, subID1, subID2 string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                           = %[1]q
  microsoft_graph_permission_ids      = [%[2]q]
  agentless_scanning_subscription_ids = [%[3]q, %[4]q]
  vulnerability_scanning = {
    enabled = true
  }
  dspm = {
    enabled = true
  }
}`, tenantID, userReadAllPermissionID, subID1, subID2)
}
