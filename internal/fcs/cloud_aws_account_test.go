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
func testAccCloudAwsAccountConfig_basic(resourceName, account string, organization_id string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "%s" {
  account_id                         = "%s"
  organization_id                    = "%s"
  target_ous                         = ["ou-abcd-defghijk", "r-abcd"]
  account_type                       = "commercial"
}
`, resourceName, account, organization_id)
}

// Updated configuration with multiple products.
func testAccCloudAwsAccountConfig_update(resourceName, account string, organization_id string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "%s" {
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
`, resourceName, account, organization_id)
}

// Minimal configuration with only required attributes.
func testAccCloudAwsAccountConfig_minimal(resourceName, account string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "%s" {
    account_id                         = "%s"
}
`, resourceName, account)
}

func testAccCloudAwsAccountConfig_vulnerabilityScanning(resourceName, account string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "%s" {
  account_id = "%s"
  vulnerability_scanning = {
    enabled   = true
    role_name = "%s"
  }
}
`, resourceName, account, testVulnRoleName)
}

func testAccCloudAwsAccountConfig_vulnerabilityScanningNoRoleName(resourceName, account string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "%s" {
  account_id = "%s"
  vulnerability_scanning = {
    enabled   = true
  }
}
`, resourceName, account)
}

func testAccCloudAwsAccountConfig_bothDSPMAndVulnScanning(resourceName, account string, roleName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "%s" {
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
`, resourceName, account, roleName, roleName)
}

func testAccCloudAwsAccountConfig_roleMismatch(resourceName, account string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "%s" {
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
`, resourceName, account, testDSPMRoleName, testVulnRoleName)
}

func testAccCloudAwsAccountConfig_dspmOnly(resourceName, account string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "%s" {
  account_id = "%s"
  dspm = {
    enabled   = true
    role_name = "%s"
  }
}
`, resourceName, account, testDSPMRoleName)
}

func testAccCloudAwsAccountConfig_bothDSPMAndVulnEnabledNoRoles(resourceName, account string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "%s" {
  account_id = "%s"
  dspm = {
    enabled = true
  }
  vulnerability_scanning = {
    enabled = true
  }
}
`, resourceName, account)
}

func testAccCloudAwsAccountConfig_DSPMCustomRoleVulnDefaultRoleConfig(resourceName, account string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "%s" {
  account_id = "%s"
  dspm = {
    enabled   = true
    role_name = "%s"
  }
  vulnerability_scanning = {
    enabled = true
  }
}
`, resourceName, account, testDSPMRoleName)
}

func TestAccCloudAwsAccountResource(t *testing.T) {
	testResourceName := "test_main"
	fullResourceName := fmt.Sprintf("%s.%s", crowdstrikeAWSAccountResourceType, testResourceName)
	account_id := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)
	org_id := fmt.Sprintf("o-%s", sdkacctest.RandStringFromCharSet(10, sdkacctest.CharSetAlpha))

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccCloudAwsAccountConfig_basic(testResourceName, account_id, org_id),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fullResourceName, "account_id", account_id),
					resource.TestCheckResourceAttr(fullResourceName, "organization_id", org_id),
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
					resource.TestCheckResourceAttrSet(fullResourceName, "dspm_role_arn"),
					resource.TestCheckResourceAttrSet(fullResourceName, "vulnerability_scanning_role_arn"),
					resource.TestCheckResourceAttrSet(fullResourceName, "vulnerability_scanning_role_name"),
					resource.TestCheckResourceAttrSet(fullResourceName, "agentless_scanning_role_name"),
				),
			},
			// Import testing
			{
				ResourceName:                         fullResourceName,
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
				Config: testAccCloudAwsAccountConfig_update(testResourceName, account_id, org_id),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fullResourceName, "account_id", account_id),
					resource.TestCheckResourceAttr(fullResourceName, "organization_id", org_id),
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
					resource.TestCheckResourceAttrSet(fullResourceName, "dspm_role_arn"),
					resource.TestCheckResourceAttrSet(fullResourceName, "vulnerability_scanning_role_arn"),
					resource.TestCheckResourceAttrSet(fullResourceName, "vulnerability_scanning_role_name"),
					resource.TestCheckResourceAttrSet(fullResourceName, "agentless_scanning_role_name"),
				),
			},
			// Test minimal configuration
			{
				Config: testAccCloudAwsAccountConfig_minimal(testResourceName, account_id),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fullResourceName, "account_id", account_id),
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
					resource.TestCheckResourceAttrSet(fullResourceName, "dspm_role_arn"),
					resource.TestCheckResourceAttrSet(fullResourceName, "vulnerability_scanning_role_arn"),
					resource.TestCheckResourceAttrSet(fullResourceName, "vulnerability_scanning_role_name"),
					resource.TestCheckResourceAttrSet(fullResourceName, "agentless_scanning_role_name"),
				),
			},
		},
	})
}

func TestAccCloudAwsAccountResourceMinimal(t *testing.T) {
	testResourceName := "test_minimal"
	fullResourceName := fmt.Sprintf("%s.%s", crowdstrikeAWSAccountResourceType, testResourceName)
	account_id := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Test minimal configuration
			{
				Config: testAccCloudAwsAccountConfig_minimal(testResourceName, account_id),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fullResourceName, "account_id", account_id),
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
					resource.TestCheckResourceAttrSet(fullResourceName, "dspm_role_arn"),
					resource.TestCheckResourceAttrSet(fullResourceName, "vulnerability_scanning_role_arn"),
					resource.TestCheckResourceAttrSet(fullResourceName, "vulnerability_scanning_role_name"),
					resource.TestCheckResourceAttrSet(fullResourceName, "agentless_scanning_role_name"),
				),
			},
		},
	})
}

func TestAccCloudAwsAccountResourceVulnerabilityScanning(t *testing.T) {
	testResourceName := "test_vuln"
	fullResourceName := fmt.Sprintf("%s.%s", crowdstrikeAWSAccountResourceType, testResourceName)
	account_id := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAwsAccountConfig_vulnerabilityScanning(testResourceName, account_id),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fullResourceName, "account_id", account_id),
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
	testResourceName := "test_vuln_no_role_name"
	fullResourceName := fmt.Sprintf("%s.%s", crowdstrikeAWSAccountResourceType, testResourceName)
	account_id := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAwsAccountConfig_vulnerabilityScanningNoRoleName(testResourceName, account_id),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fullResourceName, "account_id", account_id),
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
	testResourceName := "test_both"
	fullResourceName := fmt.Sprintf("%s.%s", crowdstrikeAWSAccountResourceType, testResourceName)
	account_id := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAwsAccountConfig_bothDSPMAndVulnScanning(testResourceName, account_id, testAgentlessScanningRole),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fullResourceName, "account_id", account_id),
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
	testResourceName := "test_mismatch"
	account_id := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccCloudAwsAccountConfig_roleMismatch(testResourceName, account_id),
				ExpectError: regexp.MustCompile("Role Name Mismatch"),
			},
		},
	})
}

func TestAccCloudAwsAccountResourceAgentlessRoleUpdates(t *testing.T) {
	testResourceName := "test_updates"
	fullResourceName := fmt.Sprintf("%s.%s", crowdstrikeAWSAccountResourceType, testResourceName)
	account_id := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Start with DSPM only
			{
				Config: testAccCloudAwsAccountConfig_dspmOnly(testResourceName, account_id),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fullResourceName, "account_id", account_id),
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
				Config: testAccCloudAwsAccountConfig_bothDSPMAndVulnScanning(testResourceName, account_id, testDSPMRoleName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fullResourceName, "account_id", account_id),
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
				Config:      testAccCloudAwsAccountConfig_roleMismatch(testResourceName, account_id),
				ExpectError: regexp.MustCompile("Role Name Mismatch"),
			},
			// Update to remove DSPM (vuln scanning takes over)
			{
				Config: testAccCloudAwsAccountConfig_vulnerabilityScanning(testResourceName, account_id),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fullResourceName, "account_id", account_id),
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
	testResourceName := "test_both_dspm_and_vuln_default_role"
	fullResourceName := fmt.Sprintf("%s.%s", crowdstrikeAWSAccountResourceType, testResourceName)
	account_id := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAwsAccountConfig_bothDSPMAndVulnEnabledNoRoles(testResourceName, account_id),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fullResourceName, "account_id", account_id),
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
	testResourceName := "test_dspm_custom_vuln_default_role"
	account_id := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccCloudAwsAccountConfig_DSPMCustomRoleVulnDefaultRoleConfig(testResourceName, account_id),
				ExpectError: regexp.MustCompile("Role Name Mismatch"),
			},
		},
	})
}
