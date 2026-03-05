package fcs_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

const (
	// terraform resource name
	resourceName = "crowdstrike_cloud_azure_tenant.test"
	// User.Read.All Microsoft Graph permission ID
	userReadAllPermissionID = "df021288-bdef-4463-88db-98f22de89214"
)

func testAccCloudAzureTenantConfig_withSubscription(tenantID, subscriptionID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                      = "%s"
  microsoft_graph_permission_ids = ["%s"]
  subscription_ids               = ["%s"]
}
`, tenantID, userReadAllPermissionID, subscriptionID)
}

func testAccCloudAzureTenantConfig_featuresEnabled(tenantID, subscriptionID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                      = "%s"
  microsoft_graph_permission_ids = ["%s"]
  subscription_ids               = ["%s"]
  realtime_visibility = {
    enabled = true
  }
  dspm = {
    enabled = true
  }
}
`, tenantID, userReadAllPermissionID, subscriptionID)
}

func TestAccCloudAzureTenantResource_Sanity(t *testing.T) {
	tenantID := uuid.NewString()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccCloudAzureTenantConfig_withSubscription(tenantID, uuid.NewString()),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tenant_id", tenantID),
					resource.TestCheckResourceAttr(resourceName, "account_type", "commercial"),
					resource.TestCheckResourceAttr(resourceName, "microsoft_graph_permission_ids.#", "1"),
					resource.TestCheckResourceAttrSet(resourceName, "cs_azure_client_id"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "dspm.enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "resource_name_prefix", ""),
					resource.TestCheckResourceAttr(resourceName, "resource_name_suffix", ""),
					resource.TestCheckResourceAttr(resourceName, "environment", ""),
				),
			},
			// Import testing
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateId:                        tenantID,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "tenant_id",
			},
			// Update testing - enable features
			{
				Config: testAccCloudAzureTenantConfig_featuresEnabled(tenantID, uuid.NewString()),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tenant_id", tenantID),
					resource.TestCheckResourceAttr(resourceName, "microsoft_graph_permission_ids.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "subscription_ids.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "dspm.enabled", "true"),
					resource.TestCheckResourceAttrSet(resourceName, "cs_azure_client_id"),
				),
			},
			// Update testing - back to default
			{
				Config: testAccCloudAzureTenantConfig_withSubscription(tenantID, uuid.NewString()),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tenant_id", tenantID),
					resource.TestCheckResourceAttr(resourceName, "account_type", "commercial"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "dspm.enabled", "false"),
				),
			},
		},
	})
}

func testAccCloudAzureTenantConfig_withManagementGroup(tenantID, managementGroupID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                      = "%s"
  microsoft_graph_permission_ids = ["%s"]
  management_group_ids           = ["%s"]
}
`, tenantID, userReadAllPermissionID, managementGroupID)
}

func TestAccCloudAzureTenantResource_ManagementGroups(t *testing.T) {
	tenantID := uuid.NewString()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAzureTenantConfig_withManagementGroup(tenantID, uuid.NewString()),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tenant_id", tenantID),
					resource.TestCheckResourceAttr(resourceName, "management_group_ids.#", "1"),
				),
			},
		},
	})
}

func testAccCloudAzureTenantConfig_withTags(tenantID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                      = "%s"
  microsoft_graph_permission_ids = ["%s"]
  tags = {
    env  = "test"
    team = "security"
  }
}
`, tenantID, userReadAllPermissionID)
}

func TestAccCloudAzureTenantResource_Tags(t *testing.T) {
	tenantID := uuid.NewString()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAzureTenantConfig_withTags(tenantID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tenant_id", tenantID),
					resource.TestCheckResourceAttr(resourceName, "tags.env", "test"),
					resource.TestCheckResourceAttr(resourceName, "tags.team", "security"),
				),
			},
		},
	})
}

func testAccCloudAzureTenantConfig_withAffixes(tenantID, prefix, suffix string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                      = "%s"
  microsoft_graph_permission_ids = ["%s"]
  resource_name_prefix           = "%s"
  resource_name_suffix           = "%s"
}
`, tenantID, userReadAllPermissionID, prefix, suffix)
}

func TestAccCloudAzureTenantResource_Affixes(t *testing.T) {
	tenantID := uuid.NewString()

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
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tenant_id", tenantID),
					resource.TestCheckResourceAttr(resourceName, "resource_name_prefix", "cs"),
					resource.TestCheckResourceAttr(resourceName, "resource_name_suffix", "dev"),
				),
			},
		},
	})
}

func testAccCloudAzureTenantConfig_withEnvironment(tenantID, env string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                      = "%s"
  microsoft_graph_permission_ids = ["%s"]
  environment                    = "%s"
}
`, tenantID, userReadAllPermissionID, env)
}

func TestAccCloudAzureTenantResource_Environment(t *testing.T) {
	tenantID := uuid.NewString()

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
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tenant_id", tenantID),
					resource.TestCheckResourceAttr(resourceName, "environment", "prod"),
				),
			},
		},
	})
}

func testAccCloudAzureTenantConfig_rtvEnabled(tenantID string, rtvEnabled bool) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                      = "%s"
  microsoft_graph_permission_ids = ["%s"]
  realtime_visibility = {
    enabled = %t
  }
}
`, tenantID, userReadAllPermissionID, rtvEnabled)
}

func TestAccCloudAzureTenantResource_RealtimeVisibility(t *testing.T) {
	tenantID := uuid.NewString()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create with RTV&D disabled (default)
			{
				Config: testAccCloudAzureTenantConfig_withSubscription(tenantID, uuid.NewString()),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tenant_id", tenantID),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "false"),
				),
			},
			// Enable RTV&D
			{
				Config: testAccCloudAzureTenantConfig_rtvEnabled(tenantID, true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tenant_id", tenantID),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "true"),
				),
			},
			// Disable RTV&D
			{
				Config: testAccCloudAzureTenantConfig_rtvEnabled(tenantID, false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tenant_id", tenantID),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "false"),
				),
			},
		},
	})
}

func testAccCloudAzureTenantConfig_dspmEnabled(tenantID string, dspmEnabled bool) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                      = "%s"
  microsoft_graph_permission_ids = ["%s"]
  dspm = {
    enabled = %t
  }
}
`, tenantID, userReadAllPermissionID, dspmEnabled)
}

func TestAccCloudAzureTenantResource_DSPM(t *testing.T) {
	tenantID := uuid.NewString()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create with DSPM disabled (default)
			{
				Config: testAccCloudAzureTenantConfig_withSubscription(tenantID, uuid.NewString()),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tenant_id", tenantID),
					resource.TestCheckResourceAttr(resourceName, "dspm.enabled", "false"),
				),
			},
			// Enable DSPM
			{
				Config: testAccCloudAzureTenantConfig_dspmEnabled(tenantID, true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tenant_id", tenantID),
					resource.TestCheckResourceAttr(resourceName, "dspm.enabled", "true"),
				),
			},
			// Disable DSPM
			{
				Config: testAccCloudAzureTenantConfig_dspmEnabled(tenantID, false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tenant_id", tenantID),
					resource.TestCheckResourceAttr(resourceName, "dspm.enabled", "false"),
				),
			},
		},
	})
}

func testAccCloudAzureTenantConfig_emptyGraphPermissions(tenantID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_azure_tenant" "test" {
  tenant_id                      = "%s"
  microsoft_graph_permission_ids = []
}
`, tenantID)
}

func TestAccCloudAzureTenantResource_EmptyGraphPermissions(t *testing.T) {
	tenantID := uuid.NewString()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAzureTenantConfig_emptyGraphPermissions(tenantID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tenant_id", tenantID),
					resource.TestCheckResourceAttr(resourceName, "microsoft_graph_permission_ids.#", "0"),
				),
			},
		},
	})
}
