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
	testDSPMRoleName          = "dspm-role"
	testVulnRoleName          = "vuln-role"
	testAgentlessScanningRole = "agentless-scanning-shared-role"
)

// Basic configuration.
func testAccCloudAwsAccountConfig_basic(account string, organization_id string) string {
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
func testAccCloudAwsAccountConfig_update(account string, organization_id string) string {
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

func testAccCloudAwsAccountConfig_bothDSPMAndVulnScanning(account string, roleName string) string {
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

func TestAccCloudAwsAccountResource(t *testing.T) {
	resourceName := "crowdstrike_cloud_aws_account.test"
	account_id := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)
	org_id := fmt.Sprintf("o-%s", sdkacctest.RandStringFromCharSet(10, sdkacctest.CharSetAlpha))

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccCloudAwsAccountConfig_basic(account_id, org_id),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", account_id),
					resource.TestCheckResourceAttr(resourceName, "organization_id", org_id),
					resource.TestCheckResourceAttr(
						resourceName,
						"is_organization_management_account",
						"true",
					),
					resource.TestCheckResourceAttr(resourceName, "account_type", "commercial"),
					resource.TestCheckResourceAttr(resourceName, "target_ous.#", "2"),
					// Computed fields should exist
					resource.TestCheckResourceAttrSet(resourceName, "external_id"),
					resource.TestCheckResourceAttrSet(resourceName, "intermediate_role_arn"),
					resource.TestCheckResourceAttrSet(resourceName, "iam_role_arn"),
					resource.TestCheckResourceAttrSet(resourceName, "eventbus_name"),
					resource.TestCheckResourceAttrSet(resourceName, "eventbus_arn"),
					resource.TestCheckResourceAttrSet(resourceName, "dspm_role_arn"),
					resource.TestCheckResourceAttr(resourceName, "vulnerability_scanning_role_arn", ""), //TODO: consult with max regarding the initial value.
					resource.TestCheckResourceAttr(resourceName, "vulnerability_scanning_role_name", ""),
					resource.TestCheckResourceAttrSet(resourceName, "agentless_scanning_role_name"),
				),
			},
			// Import testing
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateId:                        account_id,
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
				Config: testAccCloudAwsAccountConfig_update(account_id, org_id),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", account_id),
					resource.TestCheckResourceAttr(resourceName, "organization_id", org_id),
					resource.TestCheckResourceAttr(
						resourceName,
						"is_organization_management_account",
						"true",
					),
					resource.TestCheckResourceAttr(resourceName, "account_type", "commercial"),
					resource.TestCheckResourceAttr(resourceName, "target_ous.#", "2"),
					// Computed fields should exist
					resource.TestCheckResourceAttrSet(resourceName, "external_id"),
					resource.TestCheckResourceAttrSet(resourceName, "intermediate_role_arn"),
					resource.TestCheckResourceAttrSet(resourceName, "iam_role_arn"),
					resource.TestCheckResourceAttrSet(resourceName, "eventbus_name"),
					resource.TestCheckResourceAttrSet(resourceName, "eventbus_arn"),
					resource.TestCheckResourceAttrSet(resourceName, "dspm_role_arn"),
					resource.TestCheckResourceAttr(resourceName, "vulnerability_scanning_role_arn", ""), //TODO: consult with max regarding the initial value.
					resource.TestCheckResourceAttr(resourceName, "vulnerability_scanning_role_name", ""),
					resource.TestCheckResourceAttrSet(resourceName, "agentless_scanning_role_name"),
				),
			},
			// Test minimal configuration
			{
				Config: testAccCloudAwsAccountConfig_minimal(account_id),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", account_id),
					resource.TestCheckResourceAttr(
						resourceName,
						"is_organization_management_account",
						"false",
					),
					resource.TestCheckResourceAttr(resourceName, "account_type", "commercial"),
					// Computed fields should exist
					resource.TestCheckResourceAttrSet(resourceName, "external_id"),
					resource.TestCheckResourceAttrSet(resourceName, "intermediate_role_arn"),
					resource.TestCheckResourceAttrSet(resourceName, "iam_role_arn"),
					resource.TestCheckResourceAttrSet(resourceName, "eventbus_name"),
					resource.TestCheckResourceAttrSet(resourceName, "eventbus_arn"),
					resource.TestCheckResourceAttrSet(resourceName, "dspm_role_arn"),
					resource.TestCheckResourceAttr(resourceName, "vulnerability_scanning_role_arn", ""), //TODO: consult with max regarding the initial value.
					resource.TestCheckResourceAttr(resourceName, "vulnerability_scanning_role_name", ""),
					resource.TestCheckResourceAttrSet(resourceName, "agentless_scanning_role_name"),
				),
			},
		},
	})
}

func TestAccCloudAwsAccountResourceMinimal(t *testing.T) {
	resourceName := "crowdstrike_cloud_aws_account.test"
	account_id := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Test minimal configuration
			{
				Config: testAccCloudAwsAccountConfig_minimal(account_id),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", account_id),
					resource.TestCheckResourceAttr(
						resourceName,
						"is_organization_management_account",
						"false",
					),
					resource.TestCheckResourceAttr(resourceName, "account_type", "commercial"),
					// Computed fields should exist
					resource.TestCheckResourceAttrSet(resourceName, "external_id"),
					resource.TestCheckResourceAttrSet(resourceName, "intermediate_role_arn"),
					resource.TestCheckResourceAttrSet(resourceName, "iam_role_arn"),
					resource.TestCheckResourceAttrSet(resourceName, "eventbus_name"),
					resource.TestCheckResourceAttrSet(resourceName, "eventbus_arn"),
					resource.TestCheckResourceAttrSet(resourceName, "dspm_role_arn"),
					resource.TestCheckResourceAttr(resourceName, "vulnerability_scanning_role_arn", ""), //TODO: consult with max regarding the initial value.
					resource.TestCheckResourceAttr(resourceName, "vulnerability_scanning_role_name", ""),
					resource.TestCheckResourceAttrSet(resourceName, "agentless_scanning_role_name"),
				),
			},
		},
	})
}

func TestAccCloudAwsAccountResourceVulnerabilityScanning(t *testing.T) {
	resourceName := "crowdstrike_cloud_aws_account.test"
	account_id := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAwsAccountConfig_vulnerabilityScanning(account_id),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", account_id),
					resource.TestCheckResourceAttr(resourceName, "vulnerability_scanning.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "vulnerability_scanning.role_name", testVulnRoleName),
					resource.TestCheckResourceAttrSet(resourceName, "vulnerability_scanning_role_arn"),
					resource.TestCheckResourceAttr(resourceName, "vulnerability_scanning_role_name", testVulnRoleName),
					resource.TestCheckResourceAttr(resourceName, "agentless_scanning_role_name", testVulnRoleName),
				),
			},
		},
	})
}

func TestAccCloudAwsAccountResourceBothDSPMAndVulnScanning(t *testing.T) {
	resourceName := "crowdstrike_cloud_aws_account.test"
	account_id := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAwsAccountConfig_bothDSPMAndVulnScanning(account_id, testAgentlessScanningRole),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", account_id),
					resource.TestCheckResourceAttr(resourceName, "dspm.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "dspm.role_name", testAgentlessScanningRole),
					resource.TestCheckResourceAttr(resourceName, "vulnerability_scanning.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "vulnerability_scanning.role_name", testAgentlessScanningRole),
					resource.TestCheckResourceAttr(resourceName, "agentless_scanning_role_name", testAgentlessScanningRole),
				),
			},
		},
	})
}

func TestAccCloudAwsAccountResourceRoleMismatchValidation(t *testing.T) {
	account_id := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccCloudAwsAccountConfig_roleMismatch(account_id),
				ExpectError: regexp.MustCompile("Role Name Mismatch"),
			},
		},
	})
}

func TestAccCloudAwsAccountResourceAgentlessRoleUpdates(t *testing.T) {
	resourceName := "crowdstrike_cloud_aws_account.test"
	account_id := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// 1. Start with DSPM only
			{
				Config: testAccCloudAwsAccountConfig_dspmOnly(account_id),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", account_id),
					resource.TestCheckResourceAttr(resourceName, "dspm.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "dspm.role_name", testDSPMRoleName),
					resource.TestCheckResourceAttr(resourceName, "vulnerability_scanning.enabled", "false"),
					// Computed fields
					resource.TestCheckResourceAttrSet(resourceName, "dspm_role_arn"),
					resource.TestCheckResourceAttr(resourceName, "dspm_role_name", testDSPMRoleName),
					resource.TestCheckResourceAttr(resourceName, "vulnerability_scanning_role_arn", ""),
					resource.TestCheckResourceAttr(resourceName, "vulnerability_scanning_role_name", ""),
					resource.TestCheckResourceAttr(resourceName, "agentless_scanning_role_name", testDSPMRoleName),
				),
			},
			// 2. Update to add vulnerability scanning (same role)
			{
				Config: testAccCloudAwsAccountConfig_bothDSPMAndVulnScanning(account_id, testDSPMRoleName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", account_id),
					resource.TestCheckResourceAttr(resourceName, "dspm.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "dspm.role_name", testDSPMRoleName),
					resource.TestCheckResourceAttr(resourceName, "vulnerability_scanning.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "vulnerability_scanning.role_name", testDSPMRoleName),
					// Computed fields
					resource.TestCheckResourceAttrSet(resourceName, "dspm_role_arn"),
					resource.TestCheckResourceAttr(resourceName, "dspm_role_name", testDSPMRoleName),
					resource.TestCheckResourceAttrSet(resourceName, "vulnerability_scanning_role_arn"),
					resource.TestCheckResourceAttr(resourceName, "vulnerability_scanning_role_name", testDSPMRoleName),
					resource.TestCheckResourceAttr(resourceName, "agentless_scanning_role_name", testDSPMRoleName),
				),
			},
			// 3. Update to different roles (should fail validation)
			{
				Config:      testAccCloudAwsAccountConfig_roleMismatch(account_id),
				ExpectError: regexp.MustCompile("Role Name Mismatch"),
			},
			// 4. Update to remove DSPM (vuln scanning takes over)
			{
				Config: testAccCloudAwsAccountConfig_vulnerabilityScanning(account_id),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", account_id),
					resource.TestCheckResourceAttr(resourceName, "dspm.enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "vulnerability_scanning.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "vulnerability_scanning.role_name", testVulnRoleName),
					// Computed fields
					resource.TestCheckResourceAttrSet(resourceName, "dspm_role_arn"),                 // DSPM ARN should still exist from API
					resource.TestCheckResourceAttr(resourceName, "dspm_role_name", testDSPMRoleName), // DSPM role name should still exist
					resource.TestCheckResourceAttrSet(resourceName, "vulnerability_scanning_role_arn"),
					resource.TestCheckResourceAttr(resourceName, "vulnerability_scanning_role_name", testVulnRoleName),
					resource.TestCheckResourceAttr(resourceName, "agentless_scanning_role_name", testVulnRoleName), // Should switch to vuln role
				),
			},
		},
	})
}
