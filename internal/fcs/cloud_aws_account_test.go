package fcs_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
)

const (
	testDSPMRoleName                  = "dspm-role"
	testVulnRoleName                  = "vuln-role"
	testAgentlessScanningRole         = "agentless-scanning-shared-role"
	crowdstrikeAWSAccountResourceType = "crowdstrike_cloud_aws_account"
)

// Basic configuration.
func testAccCloudAwsAccountConfig_basic(account, organization_id string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
  account_id                         = "%s"
  organization_id                    = "%s"
  target_ous                         = ["ou-abcd-defghijk", "r-abcd"]
  account_type                       = "commercial"
}
`, account, organization_id)
}

// Updated configuration with multiple products.
func testAccCloudAwsAccountConfig_update(account, organization_id string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
  account_id                         = "%s"
  organization_id                    = "%s"
  target_ous                         = ["ou-abcd-defghijk", "r-abcd"]
  account_type                       = "commercial"
  asset_inventory = {
    enabled   = true
  }
  realtime_visibility = {
    enabled           = true
    cloudtrail_region = "us-east-1"
  }
  idp = {
    enabled = true
  }
  sensor_management = {
    enabled = true
  }
  dspm = {
    enabled = true
    role_name = "mydspmrole"
  }
}
`, account, organization_id)
}

// Minimal configuration with only required attributes.
func testAccCloudAwsAccountConfig_minimal(account string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
    account_id                         = "%s"
}
`, account)
}

func testAccCloudAwsAccountConfig_vulnerabilityScanning(account string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
  account_id = "%s"
  vulnerability_scanning = {
    enabled   = true
    role_name = "%s"
  }
}
`, account, testVulnRoleName)
}

func testAccCloudAwsAccountConfig_withRegions(account string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
  account_id = "%s"
  realtime_visibility = {
    enabled           = true
    cloudtrail_region = "us-east-1"
    regions     = ["us-east-1", "us-west-2"]
  }
  dspm = {
    enabled       = true
  }
  vulnerability_scanning = {
    enabled                          = true
  }
}
`, account)
}

func testAccCloudAwsAccountConfig_updateRegions(account string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
  account_id = "%s"
  realtime_visibility = {
    enabled           = true
    cloudtrail_region = "us-east-1"
    regions     = ["us-east-1", "us-west-2", "eu-central-1"]
  }
  dspm = {
    enabled       = true
  }
  vulnerability_scanning = {
    enabled       = true
  }
}
`, account)
}

func testAccCloudAwsAccountConfig_withoutRegions(account string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
  account_id = "%s"
  realtime_visibility = {
    enabled           = true
    cloudtrail_region = "us-east-1"
  }
  dspm = {
    enabled = true
  }
  vulnerability_scanning = {
    enabled = true
  }
}
`, account)
}

func testAccCloudAwsAccountConfig_vulnerabilityScanningNoRoleName(account string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
  account_id = "%s"
  vulnerability_scanning = {
    enabled   = true
  }
}
`, account)
}

func testAccCloudAwsAccountConfig_bothDSPMAndVulnScanning(account, roleName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
  account_id = "%s"
  dspm = {
    enabled   = true
    role_name = "%s"
  }
  vulnerability_scanning = {
    enabled   = true
    role_name = "%s"
  }
}
`, account, roleName, roleName)
}

func testAccCloudAwsAccountConfig_roleMismatch(account string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
  account_id = "%s"
  dspm = {
    enabled   = true
    role_name = "%s"
  }
  vulnerability_scanning = {
    enabled   = true
    role_name = "%s"
  }
}
`, account, testDSPMRoleName, testVulnRoleName)
}

func testAccCloudAwsAccountConfig_dspmOnly(account string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
  account_id = "%s"
  dspm = {
    enabled   = true
    role_name = "%s"
  }
}
`, account, testDSPMRoleName)
}

func testAccCloudAwsAccountConfig_bothDSPMAndVulnEnabledNoRoles(account string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
  account_id = "%s"
  dspm = {
    enabled = true
  }
  vulnerability_scanning = {
    enabled = true
  }
}
`, account)
}

func testAccCloudAwsAccountConfig_withEmptyRegions(account string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
  account_id = "%s"
  realtime_visibility = {
    enabled           = true
    cloudtrail_region = "us-east-1"
    regions     = []
  }
}
`, account)
}

func testAccCloudAwsAccountConfig_withSingleRegion(account string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
  account_id = "%s"
  dspm = {
    enabled = true
  }
}
`, account)
}

func testAccCloudAwsAccountConfig_DSPMCustomRoleVulnDefaultRoleConfig(account string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
  account_id = "%s"
  dspm = {
    enabled   = true
    role_name = "%s"
  }
  vulnerability_scanning = {
    enabled = true
  }
}
`, account, testDSPMRoleName)
}

func TestAccCloudAwsAccountResource(t *testing.T) {
	fullResourceName := fmt.Sprintf("%s.%s", crowdstrikeAWSAccountResourceType, "test")
	accountID := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)
	orgID := fmt.Sprintf("o-%s", sdkacctest.RandStringFromCharSet(10, sdkacctest.CharSetAlpha))

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccCloudAwsAccountConfig_basic(accountID, orgID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fullResourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(fullResourceName, "organization_id", orgID),
					resource.TestCheckResourceAttr(
						fullResourceName,
						"is_organization_management_account",
						"true",
					),
					resource.TestCheckResourceAttr(fullResourceName, "account_type", "commercial"),
					resource.TestCheckResourceAttr(fullResourceName, "target_ous.#", "2"),
					// Computed fields should exist
					resource.TestCheckResourceAttrSet(fullResourceName, "external_id"),
					resource.TestCheckResourceAttrSet(fullResourceName, "intermediate_role_arn"),
					resource.TestCheckResourceAttrSet(fullResourceName, "iam_role_arn"),
					resource.TestCheckResourceAttrSet(fullResourceName, "eventbus_name"),
					resource.TestCheckResourceAttrSet(fullResourceName, "eventbus_arn"),
					// For basic configuration with no DSPM or vulnerability scanning enabled,
					// verify that features default to their expected states
					resource.TestCheckResourceAttr(fullResourceName, "dspm.enabled", "false"),
					resource.TestCheckResourceAttr(fullResourceName, "vulnerability_scanning.enabled", "false"),
					// Note: role fields are computed and may have values based on API defaults
					// We don't assert on their presence/absence in the basic test
				),
			},
			// Import testing
			{
				ResourceName:                         fullResourceName,
				ImportState:                          true,
				ImportStateId:                        accountID,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "account_id",
				ImportStateVerifyIgnore: []string{
					"id",
					"deployment_method",
					"target_ous",
					"asset_inventory",
					"realtime_visibility",
					"idp",
					"sensor_management",
					"dspm",
					"vulnerability_scanning",
				},
			},
			// Update testing
			{
				Config: testAccCloudAwsAccountConfig_update(accountID, orgID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fullResourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(fullResourceName, "organization_id", orgID),
					resource.TestCheckResourceAttr(
						fullResourceName,
						"is_organization_management_account",
						"true",
					),
					resource.TestCheckResourceAttr(fullResourceName, "account_type", "commercial"),
					resource.TestCheckResourceAttr(fullResourceName, "target_ous.#", "2"),
					// Computed fields should exist
					resource.TestCheckResourceAttrSet(fullResourceName, "external_id"),
					resource.TestCheckResourceAttrSet(fullResourceName, "intermediate_role_arn"),
					resource.TestCheckResourceAttrSet(fullResourceName, "iam_role_arn"),
					resource.TestCheckResourceAttrSet(fullResourceName, "eventbus_name"),
					resource.TestCheckResourceAttrSet(fullResourceName, "eventbus_arn"),
					// This configuration enables DSPM with a custom role name, so DSPM role fields should be set
					resource.TestCheckResourceAttr(fullResourceName, "dspm.enabled", "true"),
					resource.TestCheckResourceAttrSet(fullResourceName, "dspm_role_arn"),
					// Vulnerability scanning is not enabled in this config, so these fields may not be set
					resource.TestCheckResourceAttr(fullResourceName, "vulnerability_scanning.enabled", "false"),
					// agentless_scanning_role_name should be set since DSPM is enabled
					resource.TestCheckResourceAttrSet(fullResourceName, "agentless_scanning_role_name"),
				),
			},
			// Test minimal configuration
			{
				Config: testAccCloudAwsAccountConfig_minimal(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fullResourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(
						fullResourceName,
						"is_organization_management_account",
						"false",
					),
					resource.TestCheckResourceAttr(fullResourceName, "account_type", "commercial"),
					// Computed fields should exist
					resource.TestCheckResourceAttrSet(fullResourceName, "external_id"),
					resource.TestCheckResourceAttrSet(fullResourceName, "intermediate_role_arn"),
					resource.TestCheckResourceAttrSet(fullResourceName, "iam_role_arn"),
					resource.TestCheckResourceAttrSet(fullResourceName, "eventbus_name"),
					resource.TestCheckResourceAttrSet(fullResourceName, "eventbus_arn"),
					// For minimal configuration with no explicit feature configuration,
					// verify that features default to their expected states
					resource.TestCheckResourceAttr(fullResourceName, "dspm.enabled", "false"),
					resource.TestCheckResourceAttr(fullResourceName, "vulnerability_scanning.enabled", "false"),
					// Note: role fields are computed and may have values based on API defaults
					// We don't assert on their presence/absence in the minimal test
				),
			},
		},
	})
}

func TestAccCloudAwsAccountResourceMinimal(t *testing.T) {
	fullResourceName := fmt.Sprintf("%s.%s", crowdstrikeAWSAccountResourceType, "test")
	accountID := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Test minimal configuration
			{
				Config: testAccCloudAwsAccountConfig_minimal(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fullResourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(
						fullResourceName,
						"is_organization_management_account",
						"false",
					),
					resource.TestCheckResourceAttr(fullResourceName, "account_type", "commercial"),
					// Computed fields should exist
					resource.TestCheckResourceAttrSet(fullResourceName, "external_id"),
					resource.TestCheckResourceAttrSet(fullResourceName, "intermediate_role_arn"),
					resource.TestCheckResourceAttrSet(fullResourceName, "iam_role_arn"),
					resource.TestCheckResourceAttrSet(fullResourceName, "eventbus_name"),
					resource.TestCheckResourceAttrSet(fullResourceName, "eventbus_arn"),
					// For minimal configuration with no explicit feature configuration,
					// verify that features default to their expected states
					resource.TestCheckResourceAttr(fullResourceName, "dspm.enabled", "false"),
					resource.TestCheckResourceAttr(fullResourceName, "vulnerability_scanning.enabled", "false"),
					// Note: role fields are computed and may have values based on API defaults
					// We don't assert on their presence/absence in the minimal test
				),
			},
		},
	})
}

func TestAccCloudAwsAccountResourceVulnerabilityScanning(t *testing.T) {
	fullResourceName := fmt.Sprintf("%s.%s", crowdstrikeAWSAccountResourceType, "test")
	accountID := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAwsAccountConfig_vulnerabilityScanning(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fullResourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(fullResourceName, "vulnerability_scanning.enabled", "true"),
					resource.TestCheckResourceAttr(fullResourceName, "vulnerability_scanning.role_name", testVulnRoleName),
					resource.TestCheckResourceAttrSet(fullResourceName, "vulnerability_scanning_role_arn"),
					resource.TestCheckResourceAttr(fullResourceName, "vulnerability_scanning_role_name", testVulnRoleName),
					resource.TestCheckResourceAttr(fullResourceName, "agentless_scanning_role_name", testVulnRoleName),
				),
			},
		},
	})
}

func TestAccCloudAwsAccountResourceVulnerabilityScanningNoRoleName(t *testing.T) {
	fullResourceName := fmt.Sprintf("%s.%s", crowdstrikeAWSAccountResourceType, "test")
	accountID := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAwsAccountConfig_vulnerabilityScanningNoRoleName(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fullResourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(fullResourceName, "vulnerability_scanning.enabled", "true"),
					resource.TestCheckResourceAttrSet(fullResourceName, "vulnerability_scanning_role_arn"),
					resource.TestCheckResourceAttrSet(fullResourceName, "vulnerability_scanning_role_name"),
					resource.TestCheckResourceAttrSet(fullResourceName, "agentless_scanning_role_name"),
				),
			},
		},
	})
}

func TestAccCloudAwsAccountResourceBothDSPMAndVulnScanning(t *testing.T) {
	fullResourceName := fmt.Sprintf("%s.%s", crowdstrikeAWSAccountResourceType, "test")
	accountID := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAwsAccountConfig_bothDSPMAndVulnScanning(accountID, testAgentlessScanningRole),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fullResourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(fullResourceName, "dspm.enabled", "true"),
					resource.TestCheckResourceAttr(fullResourceName, "dspm.role_name", testAgentlessScanningRole),
					resource.TestCheckResourceAttr(fullResourceName, "vulnerability_scanning.enabled", "true"),
					resource.TestCheckResourceAttr(fullResourceName, "vulnerability_scanning.role_name", testAgentlessScanningRole),
					resource.TestCheckResourceAttr(fullResourceName, "agentless_scanning_role_name", testAgentlessScanningRole),
				),
			},
		},
	})
}

func TestAccCloudAwsAccountResourceRoleMismatchValidation(t *testing.T) {
	accountID := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccCloudAwsAccountConfig_roleMismatch(accountID),
				ExpectError: regexp.MustCompile("Role Name Mismatch"),
			},
		},
	})
}

func TestAccCloudAwsAccountResourceAgentlessRoleUpdates(t *testing.T) {
	fullResourceName := fmt.Sprintf("%s.%s", crowdstrikeAWSAccountResourceType, "test")
	accountID := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Start with DSPM only
			{
				Config: testAccCloudAwsAccountConfig_dspmOnly(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fullResourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(fullResourceName, "dspm.enabled", "true"),
					resource.TestCheckResourceAttr(fullResourceName, "dspm.role_name", testDSPMRoleName),
					resource.TestCheckResourceAttr(fullResourceName, "vulnerability_scanning.enabled", "false"),
					// Computed fields
					resource.TestCheckResourceAttrSet(fullResourceName, "dspm_role_arn"),
					resource.TestCheckResourceAttr(fullResourceName, "dspm_role_name", testDSPMRoleName),
					resource.TestCheckResourceAttrSet(fullResourceName, "vulnerability_scanning_role_arn"),
					resource.TestCheckResourceAttrSet(fullResourceName, "vulnerability_scanning_role_name"),
					resource.TestCheckResourceAttr(fullResourceName, "agentless_scanning_role_name", testDSPMRoleName),
				),
			},
			// Update to add vulnerability scanning (same role)
			{
				Config: testAccCloudAwsAccountConfig_bothDSPMAndVulnScanning(accountID, testDSPMRoleName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fullResourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(fullResourceName, "dspm.enabled", "true"),
					resource.TestCheckResourceAttr(fullResourceName, "dspm.role_name", testDSPMRoleName),
					resource.TestCheckResourceAttr(fullResourceName, "vulnerability_scanning.enabled", "true"),
					resource.TestCheckResourceAttr(fullResourceName, "vulnerability_scanning.role_name", testDSPMRoleName),
					// Computed fields
					resource.TestCheckResourceAttrSet(fullResourceName, "dspm_role_arn"),
					resource.TestCheckResourceAttr(fullResourceName, "dspm_role_name", testDSPMRoleName),
					resource.TestCheckResourceAttrSet(fullResourceName, "vulnerability_scanning_role_arn"),
					resource.TestCheckResourceAttr(fullResourceName, "vulnerability_scanning_role_name", testDSPMRoleName),
					resource.TestCheckResourceAttr(fullResourceName, "agentless_scanning_role_name", testDSPMRoleName),
				),
			},
			// Update to different roles (should fail validation)
			{
				Config:      testAccCloudAwsAccountConfig_roleMismatch(accountID),
				ExpectError: regexp.MustCompile("Role Name Mismatch"),
			},
			// Update to remove DSPM (vuln scanning takes over)
			{
				Config: testAccCloudAwsAccountConfig_vulnerabilityScanning(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fullResourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(fullResourceName, "dspm.enabled", "false"),
					resource.TestCheckResourceAttr(fullResourceName, "vulnerability_scanning.enabled", "true"),
					resource.TestCheckResourceAttr(fullResourceName, "vulnerability_scanning.role_name", testVulnRoleName),
					// Computed fields
					resource.TestCheckResourceAttrSet(fullResourceName, "dspm_role_arn"),
					resource.TestCheckResourceAttr(fullResourceName, "dspm_role_name", testDSPMRoleName),
					resource.TestCheckResourceAttrSet(fullResourceName, "vulnerability_scanning_role_arn"),
					resource.TestCheckResourceAttr(fullResourceName, "vulnerability_scanning_role_name", testVulnRoleName),
					resource.TestCheckResourceAttr(fullResourceName, "agentless_scanning_role_name", testVulnRoleName),
				),
			},
		},
	})
}

func TestAccCloudAwsAccountResourceBothEnabledDefaultRoles(t *testing.T) {
	fullResourceName := fmt.Sprintf("%s.%s", crowdstrikeAWSAccountResourceType, "test")
	accountID := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAwsAccountConfig_bothDSPMAndVulnEnabledNoRoles(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fullResourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(fullResourceName, "dspm.enabled", "true"),
					resource.TestCheckResourceAttr(fullResourceName, "vulnerability_scanning.enabled", "true"),
					// Both should use default roles - no validation error expected
					resource.TestCheckResourceAttrSet(fullResourceName, "agentless_scanning_role_name"),
				),
			},
		},
	})
}

func TestAccCloudAwsAccountResourceMixedRoleConfiguration(t *testing.T) {
	accountID := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccCloudAwsAccountConfig_DSPMCustomRoleVulnDefaultRoleConfig(accountID),
				ExpectError: regexp.MustCompile("Role Name Mismatch"),
			},
		},
	})
}

// TestAccCloudAWSAccount_RealtimeVisibility tests commercial account realtime_visibility configurations.
func TestAccCloudAWSAccount_RealtimeVisibility(t *testing.T) {
	resourceName := "crowdstrike_cloud_aws_account.test"
	accountID := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAWSAccountConfigRealtimeVisibilityOmitted(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(resourceName, "account_type", "commercial"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.cloudtrail_region", "us-east-1"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.use_existing_cloudtrail", "true"),
					resource.TestCheckResourceAttrSet(resourceName, "cloudtrail_bucket_name"),
				),
			},
			{
				Config: testAccCloudAWSAccountConfigRealtimeVisibility(accountID, false, "us-east-1"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(resourceName, "account_type", "commercial"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "cloudtrail_bucket_name"),
				),
			},
			{
				Config: testAccCloudAWSAccountConfigRealtimeVisibility(accountID, true, "us-east-1"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(resourceName, "account_type", "commercial"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.cloudtrail_region", "us-east-1"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.use_existing_cloudtrail", "true"),
					resource.TestCheckResourceAttrSet(resourceName, "cloudtrail_bucket_name"),
				),
			},
			{
				Config: testAccCloudAWSAccountConfigRealtimeVisibility(accountID, true, "us-west-2"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(resourceName, "account_type", "commercial"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.cloudtrail_region", "us-west-2"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.use_existing_cloudtrail", "true"),
					resource.TestCheckResourceAttrSet(resourceName, "cloudtrail_bucket_name"),
				),
			},
			{
				Config: testAccCloudAWSAccountConfigRealtimeVisibilityOmitted(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(resourceName, "account_type", "commercial"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.cloudtrail_region", "us-east-1"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.use_existing_cloudtrail", "true"),
					resource.TestCheckResourceAttrSet(resourceName, "cloudtrail_bucket_name"),
				),
			},
			{
				Config: testAccCloudAWSAccountConfigRealtimeVisibility(accountID, true, "eu-west-1"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(resourceName, "account_type", "commercial"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.cloudtrail_region", "eu-west-1"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.use_existing_cloudtrail", "true"),
					resource.TestCheckResourceAttrSet(resourceName, "cloudtrail_bucket_name"),
				),
			},
			{
				Config: testAccCloudAWSAccountConfigRealtimeVisibility(accountID, false, "us-east-1"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(resourceName, "account_type", "commercial"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.cloudtrail_region", "us-east-1"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.use_existing_cloudtrail", "true"),
					resource.TestCheckResourceAttrSet(resourceName, "cloudtrail_bucket_name"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateId:                        accountID,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "account_id",
				ImportStateVerifyIgnore: []string{
					"id",
					"deployment_method",
					"target_ous",
					"asset_inventory",
					"idp",
					"sensor_management",
					"dspm",
				},
			},
		},
	})
}

func testAccCloudAWSAccountConfigRealtimeVisibility(accountID string, enabled bool, cloudtrailRegion string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
  account_id   = %[1]q
  realtime_visibility = {
    enabled                 = %[2]t
    cloudtrail_region       = %[3]q
    use_existing_cloudtrail = true
  }
}
`, accountID, enabled, cloudtrailRegion)
}

func testAccCloudAWSAccountConfigRealtimeVisibilityOmitted(accountID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
  account_id = %[1]q
}
`, accountID)
}

// S3 Log Ingestion test configurations.
func testAccCloudAwsAccountConfig_s3LogIngestionRequired(accountID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
  account_id = "%s"
  realtime_visibility = {
    enabled                       = true
    cloudtrail_region            = "us-east-1"
    log_ingestion_method         = "s3"
    log_ingestion_s3_bucket_name = "test-cloudtrail-logs-bucket"
    log_ingestion_sns_topic_arn  = "arn:aws:sns:us-east-1:123456789012:cloudtrail-notifications"
  }
}
`, accountID)
}

func testAccCloudAwsAccountConfig_s3LogIngestionComplete(accountID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
  account_id = "%s"
  realtime_visibility = {
    enabled                         = true
    cloudtrail_region              = "us-east-1"
    log_ingestion_method           = "s3"
    log_ingestion_s3_bucket_name   = "test-cloudtrail-logs-bucket"
    log_ingestion_sns_topic_arn    = "arn:aws:sns:us-east-1:123456789012:cloudtrail-notifications"
    log_ingestion_s3_bucket_prefix = "cloudtrail-logs"
    log_ingestion_kms_key_arn      = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
  }
}
`, accountID)
}

func testAccCloudAwsAccountConfig_s3LogIngestionMissingBucket(accountID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
  account_id = "%s"
  realtime_visibility = {
    enabled                      = true
    cloudtrail_region           = "us-east-1"
    log_ingestion_method        = "s3"
    log_ingestion_sns_topic_arn = "arn:aws:sns:us-east-1:123456789012:cloudtrail-notifications"
  }
}
`, accountID)
}

func testAccCloudAwsAccountConfig_s3LogIngestionMissingSNS(accountID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
  account_id = "%s"
  realtime_visibility = {
    enabled                       = true
    cloudtrail_region            = "us-east-1"
    log_ingestion_method         = "s3"
    log_ingestion_s3_bucket_name = "test-cloudtrail-logs-bucket"
  }
}
`, accountID)
}

func testAccCloudAwsAccountConfig_s3LogIngestionInvalidSNSArn(accountID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
  account_id = "%s"
  realtime_visibility = {
    enabled                       = true
    cloudtrail_region            = "us-east-1"
    log_ingestion_method         = "s3"
    log_ingestion_s3_bucket_name = "test-cloudtrail-logs-bucket"
    log_ingestion_sns_topic_arn  = "invalid-arn"
  }
}
`, accountID)
}

func testAccCloudAwsAccountConfig_s3LogIngestionInvalidBucketName(accountID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
  account_id = "%s"
  realtime_visibility = {
    enabled                       = true
    cloudtrail_region            = "us-east-1"
    log_ingestion_method         = "s3"
    log_ingestion_s3_bucket_name = "Invalid_Bucket_Name_With_Underscores"
    log_ingestion_sns_topic_arn  = "arn:aws:sns:us-east-1:123456789012:cloudtrail-notifications"
  }
}
`, accountID)
}

func testAccCloudAwsAccountConfig_s3LogIngestionInvalidKMSArn(accountID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
  account_id = "%s"
  realtime_visibility = {
    enabled                       = true
    cloudtrail_region            = "us-east-1"
    log_ingestion_method         = "s3"
    log_ingestion_s3_bucket_name = "test-cloudtrail-logs-bucket"
    log_ingestion_sns_topic_arn  = "arn:aws:sns:us-east-1:123456789012:cloudtrail-notifications"
    log_ingestion_kms_key_arn    = "invalid-kms-arn"
  }
}
`, accountID)
}

func testAccCloudAwsAccountConfig_eventBridgeLogIngestion(accountID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
  account_id = "%s"
  realtime_visibility = {
    enabled              = true
    cloudtrail_region   = "us-east-1"
    log_ingestion_method = "eventbridge"
  }
}
`, accountID)
}

func testAccCloudAwsAccountConfig_rtvdDisabled(accountID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
  account_id = "%s"
  realtime_visibility = {
    enabled           = false
    cloudtrail_region = "us-east-1"
  }
}
`, accountID)
}

// TestAccCloudAWSAccount_S3LogIngestion tests S3 log ingestion configurations.
func TestAccCloudAWSAccount_S3LogIngestion(t *testing.T) {
	resourceName := "crowdstrike_cloud_aws_account.test"
	accountID := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAwsAccountConfig_s3LogIngestionRequired(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_method", "s3"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_s3_bucket_name", "test-cloudtrail-logs-bucket"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_sns_topic_arn", "arn:aws:sns:us-east-1:123456789012:cloudtrail-notifications"),
				),
			},
			{
				Config: testAccCloudAwsAccountConfig_s3LogIngestionComplete(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_method", "s3"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_s3_bucket_name", "test-cloudtrail-logs-bucket"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_sns_topic_arn", "arn:aws:sns:us-east-1:123456789012:cloudtrail-notifications"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_s3_bucket_prefix", "cloudtrail-logs"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_kms_key_arn", "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateId:                        accountID,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "account_id",
				ImportStateVerifyIgnore: []string{
					"id",
					"deployment_method",
					"target_ous",
					"asset_inventory",
					"idp",
					"sensor_management",
					"dspm",
					"vulnerability_scanning",
				},
			},
		},
	})
}

// TestAccCloudAWSAccount_S3LogIngestionValidation tests validation for S3 log ingestion.
func TestAccCloudAWSAccount_S3LogIngestionValidation(t *testing.T) {
	accountID := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccCloudAwsAccountConfig_s3LogIngestionMissingBucket(accountID),
				ExpectError: regexp.MustCompile(`Missing required field`),
			},
			{
				Config:      testAccCloudAwsAccountConfig_s3LogIngestionMissingSNS(accountID),
				ExpectError: regexp.MustCompile(`Missing required field`),
			},
			{
				Config:      testAccCloudAwsAccountConfig_s3LogIngestionInvalidSNSArn(accountID),
				ExpectError: regexp.MustCompile(`Invalid Attribute Value Match`),
			},
			{
				Config:      testAccCloudAwsAccountConfig_s3LogIngestionInvalidBucketName(accountID),
				ExpectError: regexp.MustCompile(`Invalid Attribute Value Match`),
			},
			{
				Config:      testAccCloudAwsAccountConfig_s3LogIngestionInvalidKMSArn(accountID),
				ExpectError: regexp.MustCompile(`Invalid Attribute Value Match`),
			},
		},
	})
}

// TestAccCloudAWSAccount_S3LogIngestionBasic tests basic S3 log ingestion functionality.
func TestAccCloudAWSAccount_S3LogIngestionBasic(t *testing.T) {
	resourceName := "crowdstrike_cloud_aws_account.test"
	accountID := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAwsAccountConfig_s3LogIngestionRequired(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_method", "s3"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_s3_bucket_name", "test-cloudtrail-logs-bucket"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_sns_topic_arn", "arn:aws:sns:us-east-1:123456789012:cloudtrail-notifications"),
				),
			},
		},
	})
}

// TestAccCloudAWSAccount_S3LogIngestionCreateWithOptional tests if API returns optional fields when set during CREATE.
func TestAccCloudAWSAccount_S3LogIngestionCreateWithOptional(t *testing.T) {
	resourceName := "crowdstrike_cloud_aws_account.test"
	accountID := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAwsAccountConfig_s3LogIngestionComplete(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_method", "s3"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_s3_bucket_name", "test-cloudtrail-logs-bucket"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_sns_topic_arn", "arn:aws:sns:us-east-1:123456789012:cloudtrail-notifications"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_s3_bucket_prefix", "cloudtrail-logs"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_kms_key_arn", "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"),
				),
			},
		},
	})
}

// TestAccCloudAWSAccount_EventBridgeLogIngestion tests explicit EventBridge log ingestion.
func TestAccCloudAWSAccount_EventBridgeLogIngestion(t *testing.T) {
	resourceName := "crowdstrike_cloud_aws_account.test"
	accountID := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAwsAccountConfig_eventBridgeLogIngestion(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_method", "eventbridge"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.cloudtrail_region", "us-east-1"),
					// S3 fields should not be set when using EventBridge
					resource.TestCheckNoResourceAttr(resourceName, "realtime_visibility.log_ingestion_s3_bucket_name"),
					resource.TestCheckNoResourceAttr(resourceName, "realtime_visibility.log_ingestion_sns_topic_arn"),
				),
			},
		},
	})
}

// TestAccCloudAWSAccount_LogIngestionMethodSwitching tests switching between log ingestion methods.
func TestAccCloudAWSAccount_LogIngestionMethodSwitching(t *testing.T) {
	resourceName := "crowdstrike_cloud_aws_account.test"
	accountID := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Step 1: Create with EventBridge
			{
				Config: testAccCloudAwsAccountConfig_eventBridgeLogIngestion(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_method", "eventbridge"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.cloudtrail_region", "us-east-1"),
				),
			},
			// Step 2: Switch to S3 method
			{
				Config: testAccCloudAwsAccountConfig_s3LogIngestionRequired(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_method", "s3"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_s3_bucket_name", "test-cloudtrail-logs-bucket"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_sns_topic_arn", "arn:aws:sns:us-east-1:123456789012:cloudtrail-notifications"),
				),
			},
			// Step 3: Switch back to EventBridge
			{
				Config: testAccCloudAwsAccountConfig_eventBridgeLogIngestion(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_method", "eventbridge"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.cloudtrail_region", "us-east-1"),
				),
			},
		},
	})
}

// TestAccCloudAWSAccount_S3LogIngestionExpansion tests expanding S3 configuration.
func TestAccCloudAWSAccount_S3LogIngestionExpansion(t *testing.T) {
	resourceName := "crowdstrike_cloud_aws_account.test"
	accountID := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Step 1: Create with S3 (complete configuration)
			{
				Config: testAccCloudAwsAccountConfig_s3LogIngestionComplete(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_method", "s3"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_s3_bucket_name", "test-cloudtrail-logs-bucket"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_sns_topic_arn", "arn:aws:sns:us-east-1:123456789012:cloudtrail-notifications"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_s3_bucket_prefix", "cloudtrail-logs"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_kms_key_arn", "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"),
				),
			},
			// Step 2: Switch to minimal S3 configuration (remove optional fields)
			{
				Config: testAccCloudAwsAccountConfig_s3LogIngestionRequired(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_method", "s3"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_s3_bucket_name", "test-cloudtrail-logs-bucket"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_sns_topic_arn", "arn:aws:sns:us-east-1:123456789012:cloudtrail-notifications"),
					// Optional fields should be absent/null when not specified
					resource.TestCheckNoResourceAttr(resourceName, "realtime_visibility.log_ingestion_s3_bucket_prefix"),
					resource.TestCheckNoResourceAttr(resourceName, "realtime_visibility.log_ingestion_kms_key_arn"),
				),
			},
		},
	})
}

// TestAccCloudAWSAccount_S3LogIngestionDisableRTVD tests S3 → disabled RTVD → re-enabled transitions.
func TestAccCloudAWSAccount_S3LogIngestionDisableRTVD(t *testing.T) {
	resourceName := "crowdstrike_cloud_aws_account.test"
	accountID := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Step 1: Create with S3 log ingestion enabled.
			{
				Config: testAccCloudAwsAccountConfig_s3LogIngestionRequired(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_method", "s3"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_s3_bucket_name", "test-cloudtrail-logs-bucket"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_sns_topic_arn", "arn:aws:sns:us-east-1:123456789012:cloudtrail-notifications"),
				),
			},
			// Step 2: Disable RTVD entirely.
			{
				Config: testAccCloudAwsAccountConfig_rtvdDisabled(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.cloudtrail_region", "us-east-1"),
				),
			},
			// Step 3: Re-enable RTVD with EventBridge method.
			{
				Config: testAccCloudAwsAccountConfig_eventBridgeLogIngestion(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_method", "eventbridge"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.cloudtrail_region", "us-east-1"),
					// S3 fields should not be set when using EventBridge.
					resource.TestCheckNoResourceAttr(resourceName, "realtime_visibility.log_ingestion_s3_bucket_name"),
					resource.TestCheckNoResourceAttr(resourceName, "realtime_visibility.log_ingestion_sns_topic_arn"),
				),
			},
			// Step 4: Switch back to S3 method to test memory of previous settings.
			{
				Config: testAccCloudAwsAccountConfig_s3LogIngestionRequired(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_method", "s3"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_s3_bucket_name", "test-cloudtrail-logs-bucket"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.log_ingestion_sns_topic_arn", "arn:aws:sns:us-east-1:123456789012:cloudtrail-notifications"),
				),
			},
		},
	})
}

func TestAccCloudAwsAccountResourceRegionsValidation(t *testing.T) {
	accountID := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccCloudAwsAccountConfig_withEmptyRegions(accountID),
				ExpectError: regexp.MustCompile("list must contain at least 1 element"),
			},
			{
				Config: testAccCloudAwsAccountConfig_withSingleRegion(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_cloud_aws_account.test",
						"dspm.enabled",
						"true",
					),
				),
			},
		},
	})
}

func TestAccCloudAwsAccountResourceRegions(t *testing.T) {
	fullResourceName := fmt.Sprintf("%s.%s", crowdstrikeAWSAccountResourceType, "test")
	accountID := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAwsAccountConfig_withRegions(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fullResourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(fullResourceName, "realtime_visibility.enabled", "true"),
					resource.TestCheckResourceAttr(fullResourceName, "realtime_visibility.regions.0", "us-east-1"),
					resource.TestCheckResourceAttr(fullResourceName, "realtime_visibility.regions.1", "us-west-2"),
					resource.TestCheckResourceAttr(fullResourceName, "realtime_visibility.regions.#", "2"),
					resource.TestCheckResourceAttr(fullResourceName, "dspm.enabled", "true"),
					resource.TestCheckResourceAttr(fullResourceName, "vulnerability_scanning.enabled", "true"),
				),
			},
			{
				Config: testAccCloudAwsAccountConfig_updateRegions(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fullResourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(fullResourceName, "realtime_visibility.regions.#", "3"),
					resource.TestCheckResourceAttr(fullResourceName, "realtime_visibility.regions.0", "us-east-1"),
					resource.TestCheckResourceAttr(fullResourceName, "realtime_visibility.regions.1", "us-west-2"),
					resource.TestCheckResourceAttr(fullResourceName, "realtime_visibility.regions.2", "eu-central-1"),
				),
			},
			{
				Config: testAccCloudAwsAccountConfig_withoutRegions(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fullResourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(fullResourceName, "realtime_visibility.enabled", "true"),
					resource.TestCheckResourceAttr(fullResourceName, "dspm.enabled", "true"),
					resource.TestCheckResourceAttr(fullResourceName, "vulnerability_scanning.enabled", "true"),
					resource.TestCheckResourceAttr(fullResourceName, "realtime_visibility.regions.#", "0"),
				),
			},
		},
	})
}
