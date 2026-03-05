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
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("microsoft_graph_permission_ids"), knownvalue.ListSizeExact(1)),
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
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("microsoft_graph_permission_ids"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("subscription_ids"), knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact(subID1)})),
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
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("microsoft_graph_permission_ids"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("subscription_ids"), knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact(subID2)})),
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
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("subscription_ids"), knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact(subID3)})),
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
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("management_group_ids"), knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact(mgID)})),
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("subscription_ids"), knownvalue.Null()),
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
					statecheck.ExpectKnownValue(cloudAzureTenantResourceName, tfjsonpath.New("microsoft_graph_permission_ids"), knownvalue.ListSizeExact(0)),
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
