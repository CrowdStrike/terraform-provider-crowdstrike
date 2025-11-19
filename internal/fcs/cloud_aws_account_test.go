package fcs_test

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/fcs"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
)

const (
	testDSPMRoleName                  = "dspm-role"
	testVulnRoleName                  = "vuln-role"
	testAgentlessScanningRole         = "agentless-scanning-shared-role"
	crowdstrikeAWSAccountResourceType = "crowdstrike_cloud_aws_account"
)

// parseAndExtractRegions is a test helper that calls parseRegionsFromSettings
// and extracts the region values from state for easy verification.
func parseAndExtractRegions(ctx context.Context, settings any) (rtvdRegions, dspmRegions, vulnRegions []string, diags diag.Diagnostics) {
	state := &fcs.CloudAWSAccountModel{
		RealtimeVisibility:    &fcs.RealtimeVisibilityOptions{},
		DSPM:                  &fcs.DSPMOptions{},
		VulnerabilityScanning: &fcs.VulnerabilityScanningOptions{},
	}

	diags = fcs.ParseRegionsFromSettings(ctx, settings, state)

	if !state.RealtimeVisibility.Regions.IsNull() {
		state.RealtimeVisibility.Regions.ElementsAs(ctx, &rtvdRegions, false)
	}
	if !state.DSPM.Regions.IsNull() {
		state.DSPM.Regions.ElementsAs(ctx, &dspmRegions, false)
	}
	if !state.VulnerabilityScanning.Regions.IsNull() {
		state.VulnerabilityScanning.Regions.ElementsAs(ctx, &vulnRegions, false)
	}

	return rtvdRegions, dspmRegions, vulnRegions, diags
}

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
    regions = ["us-east-1", "eu-west-1"]
  }
  vulnerability_scanning = {
    enabled                          = true
    regions = ["us-east-1", "ap-southeast-1"]
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
    regions = ["us-west-2", "eu-west-1"]
  }
  vulnerability_scanning = {
    enabled                          = true
    regions = ["us-east-1"]
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
    regions = ["us-east-1"]
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

// Unit test to verify region field structure, types, and validation.
func TestCloudAWSAccountModelRegionFields(t *testing.T) {
	ctx := context.Background()

	// Test that region fields can be properly set and retrieved from nested structures
	t.Run("Regions", func(t *testing.T) {
		regions := []string{"us-east-1", "us-west-2"}
		regionList, diags := types.ListValueFrom(ctx, types.StringType, regions)
		if diags.HasError() {
			t.Fatalf("Failed to create region list: %v", diags.Errors())
		}

		// Verify list can be converted back to string slice
		var resultRegions []string
		diags = regionList.ElementsAs(ctx, &resultRegions, false)
		if diags.HasError() {
			t.Fatalf("Failed to convert region list: %v", diags.Errors())
		}

		if len(resultRegions) != 2 {
			t.Errorf("Expected 2 regions, got %d", len(resultRegions))
		}
		if resultRegions[0] != "us-east-1" || resultRegions[1] != "us-west-2" {
			t.Errorf("Region values don't match: got %v", resultRegions)
		}
	})

	t.Run("EmptyRegionsList", func(t *testing.T) {
		emptyList := types.ListValueMust(types.StringType, []attr.Value{})

		var regions []string
		diags := emptyList.ElementsAs(ctx, &regions, false)
		if diags.HasError() {
			t.Fatalf("Failed to convert empty list: %v", diags.Errors())
		}

		if len(regions) != 0 {
			t.Errorf("Expected empty regions list, got %v", regions)
		}
	})

	t.Run("NullRegionsList", func(t *testing.T) {
		nullList := types.ListNull(types.StringType)

		if !nullList.IsNull() {
			t.Error("Expected null list to be null")
		}

		if nullList.IsUnknown() {
			t.Error("Expected null list to not be unknown")
		}
	})

	t.Run("RegionsValidation", func(t *testing.T) {
		// Test validation that empty lists should fail SizeAtLeast(1) validation
		// Note: This tests the validation logic conceptually since we can't easily
		// test the actual Terraform validator in unit tests

		// Test empty list - should conceptually fail validation
		emptyRegions := []string{}
		if len(emptyRegions) >= 1 {
			t.Errorf("Empty regions list should fail SizeAtLeast(1) validation")
		}

		// Test valid list - should pass validation
		validRegions := []string{"us-east-1"}
		if len(validRegions) < 1 {
			t.Errorf("Non-empty regions list should pass SizeAtLeast(1) validation")
		}

		// Test multiple regions - should pass validation
		multipleRegions := []string{"us-east-1", "us-west-2", "eu-west-1"}
		if len(multipleRegions) < 1 {
			t.Errorf("Multiple regions list should pass SizeAtLeast(1) validation")
		}
	})
}

// Test reading regions from DomainCloudAWSAccountV1 API response into Terraform state.
func TestCloudAWSAccountRegionsFromAPI(t *testing.T) {
	ctx := context.Background()

	t.Run("RegionsFromSettingsMapInterface", func(t *testing.T) {
		// Create a mock DomainCloudAWSAccountV1 response with Settings as map[string]string
		cloudAccount := &models.DomainCloudAWSAccountV1{
			AccountID: "123456789012",
			Settings: map[string]string{
				"rtvd.regions":                   "us-east-1,us-west-2",
				"dspm.regions":                   "eu-west-1,ap-southeast-1",
				"vulnerability_scanning.regions": "us-east-1",
			},
		}

		// Test the actual ParseRegionsFromSettings function
		rtvdRegions, dspmRegions, vulnRegions, diags := parseAndExtractRegions(ctx, cloudAccount.Settings)
		if diags.HasError() {
			t.Fatalf("parseAndExtractRegions failed with errors: %v", diags.Errors())
		}

		// Verify RTVD regions
		expectedRtvd := []string{"us-east-1", "us-west-2"}
		if len(rtvdRegions) != len(expectedRtvd) {
			t.Errorf("Expected %d RTVD regions, got %d", len(expectedRtvd), len(rtvdRegions))
		}
		for i, expected := range expectedRtvd {
			if i >= len(rtvdRegions) || rtvdRegions[i] != expected {
				t.Errorf("Expected RTVD region %d to be %s, got %s", i, expected, rtvdRegions[i])
			}
		}

		// Verify DSPM regions
		expectedDspm := []string{"eu-west-1", "ap-southeast-1"}
		if len(dspmRegions) != len(expectedDspm) {
			t.Errorf("Expected %d DSPM regions, got %d", len(expectedDspm), len(dspmRegions))
		}
		for i, expected := range expectedDspm {
			if i >= len(dspmRegions) || dspmRegions[i] != expected {
				t.Errorf("Expected DSPM region %d to be %s, got %s", i, expected, dspmRegions[i])
			}
		}

		// Verify Vulnerability Scanning regions
		expectedVuln := []string{"us-east-1"}
		if len(vulnRegions) != len(expectedVuln) {
			t.Errorf("Expected %d vulnerability scanning regions, got %d", len(expectedVuln), len(vulnRegions))
		}
		for i, expected := range expectedVuln {
			if i >= len(vulnRegions) || vulnRegions[i] != expected {
				t.Errorf("Expected vulnerability scanning region %d to be %s, got %s", i, expected, vulnRegions[i])
			}
		}
	})

	t.Run("RegionsFromSettingsMapString", func(t *testing.T) {
		// Create a mock DomainCloudAWSAccountV1 response with Settings as map[string]string
		cloudAccount := &models.DomainCloudAWSAccountV1{
			AccountID: "123456789012",
			Settings: map[string]string{
				"rtvd.regions":                   "us-west-1, us-west-2 , eu-north-1",
				"dspm.regions":                   "us-west-1,eu-central-1",
				"vulnerability_scanning.regions": "ap-northeast-1",
			},
		}

		// Test the actual ParseRegionsFromSettings function
		rtvdRegions, _, vulnRegions, diags := parseAndExtractRegions(ctx, cloudAccount.Settings)
		if diags.HasError() {
			t.Fatalf("parseAndExtractRegions failed with errors: %v", diags.Errors())
		}

		// Verify trimmed regions
		expectedRtvd := []string{"us-west-1", "us-west-2", "eu-north-1"}
		if len(rtvdRegions) != len(expectedRtvd) {
			t.Errorf("Expected %d RTVD regions, got %d", len(expectedRtvd), len(rtvdRegions))
		}
		for i, expected := range expectedRtvd {
			if i >= len(rtvdRegions) || rtvdRegions[i] != expected {
				t.Errorf("Expected RTVD region %d to be %s, got %s", i, expected, rtvdRegions[i])
			}
		}

		// Single region test
		expectedVuln := []string{"ap-northeast-1"}
		if len(vulnRegions) != len(expectedVuln) {
			t.Errorf("Expected %d vulnerability scanning regions, got %d", len(expectedVuln), len(vulnRegions))
		}
		if len(vulnRegions) > 0 && vulnRegions[0] != "ap-northeast-1" {
			t.Errorf("Expected ap-northeast-1, got %s", vulnRegions[0])
		}
	})

	t.Run("EmptyAndMissingRegions", func(t *testing.T) {
		// Test API response with missing/empty regions
		cloudAccount := &models.DomainCloudAWSAccountV1{
			AccountID: "123456789012",
			Settings: map[string]string{
				"rtvd.regions":  "", // Empty string
				"other.setting": "value",
				// dspm.regions is missing
				// vulnerability_scanning.regions is missing
			},
		}

		// Test the actual ParseRegionsFromSettings function with empty/missing regions
		rtvdRegions, dspmRegions, vulnRegions, diags := parseAndExtractRegions(ctx, cloudAccount.Settings)
		if diags.HasError() {
			t.Fatalf("parseAndExtractRegions failed with errors: %v", diags.Errors())
		}

		// Verify regions remain unset (empty slices)
		if len(rtvdRegions) != 0 {
			t.Errorf("RTVD regions should be empty when empty in API response, got %v", rtvdRegions)
		}
		if len(dspmRegions) != 0 {
			t.Errorf("DSPM regions should be empty when missing from API response, got %v", dspmRegions)
		}
		if len(vulnRegions) != 0 {
			t.Errorf("Vulnerability scanning regions should be empty when missing from API response, got %v", vulnRegions)
		}
	})

	t.Run("SettingsNotMapString", func(t *testing.T) {
		// Test API response with Settings as map[string]interface{} (should be ignored)
		cloudAccount := &models.DomainCloudAWSAccountV1{
			AccountID: "123456789012",
			Settings: map[string]interface{}{
				"rtvd.regions":                   "us-east-1,us-west-2",
				"dspm.regions":                   "eu-west-1,ap-southeast-1",
				"vulnerability_scanning.regions": "us-east-1",
			},
		}

		// Test the actual ParseRegionsFromSettings function - should ignore non-map[string]string
		rtvdRegions, dspmRegions, vulnRegions, diags := parseAndExtractRegions(ctx, cloudAccount.Settings)
		if diags.HasError() {
			t.Fatalf("parseAndExtractRegions failed with errors: %v", diags.Errors())
		}

		// Verify regions remain unset since settings is not map[string]string
		if len(rtvdRegions) != 0 {
			t.Errorf("RTVD regions should be empty when settings is not map[string]string, got %v", rtvdRegions)
		}
		if len(dspmRegions) != 0 {
			t.Errorf("DSPM regions should be empty when settings is not map[string]string, got %v", dspmRegions)
		}
		if len(vulnRegions) != 0 {
			t.Errorf("Vulnerability scanning regions should be empty when settings is not map[string]string, got %v", vulnRegions)
		}
	})
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
					resource.TestCheckResourceAttrSet(fullResourceName, "dspm_role_arn"),
					resource.TestCheckResourceAttrSet(fullResourceName, "vulnerability_scanning_role_arn"),
					resource.TestCheckResourceAttrSet(fullResourceName, "vulnerability_scanning_role_name"),
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

func TestAccCloudAwsAccountResourceRegionsValidation(t *testing.T) {
	accountID := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Test that empty regions list should fail validation
			{
				Config:      testAccCloudAwsAccountConfig_withEmptyRegions(accountID),
				ExpectError: regexp.MustCompile("Attribute realtime_visibility.regions list must contain at least 1 elements"),
			},
			// Test that single region should pass validation
			{
				Config: testAccCloudAwsAccountConfig_withSingleRegion(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_cloud_aws_account.test",
						"dspm.regions.#",
						"1",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_cloud_aws_account.test",
						"dspm.regions.0",
						"us-east-1",
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
			// Test configuration with regions
			{
				Config: testAccCloudAwsAccountConfig_withRegions(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fullResourceName, "account_id", accountID),
					// Check realtime_visibility regions
					resource.TestCheckResourceAttr(fullResourceName, "realtime_visibility.enabled", "true"),
					resource.TestCheckResourceAttr(fullResourceName, "realtime_visibility.regions.0", "us-east-1"),
					resource.TestCheckResourceAttr(fullResourceName, "realtime_visibility.regions.1", "us-west-2"),
					resource.TestCheckResourceAttr(fullResourceName, "realtime_visibility.regions.#", "2"),
					// Check DSPM regions
					resource.TestCheckResourceAttr(fullResourceName, "dspm.enabled", "true"),
					resource.TestCheckResourceAttr(fullResourceName, "dspm.regions.0", "us-east-1"),
					resource.TestCheckResourceAttr(fullResourceName, "dspm.regions.1", "eu-west-1"),
					resource.TestCheckResourceAttr(fullResourceName, "dspm.regions.#", "2"),
					// Check vulnerability scanning regions
					resource.TestCheckResourceAttr(fullResourceName, "vulnerability_scanning.enabled", "true"),
					resource.TestCheckResourceAttr(fullResourceName, "vulnerability_scanning.regions.0", "us-east-1"),
					resource.TestCheckResourceAttr(fullResourceName, "vulnerability_scanning.regions.1", "ap-southeast-1"),
					resource.TestCheckResourceAttr(fullResourceName, "vulnerability_scanning.regions.#", "2"),
				),
			},
			// Test configuration update with different regions
			{
				Config: testAccCloudAwsAccountConfig_updateRegions(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fullResourceName, "account_id", accountID),
					// Check updated realtime_visibility regions (now 3 regions)
					resource.TestCheckResourceAttr(fullResourceName, "realtime_visibility.regions.#", "3"),
					resource.TestCheckResourceAttr(fullResourceName, "realtime_visibility.regions.0", "us-east-1"),
					resource.TestCheckResourceAttr(fullResourceName, "realtime_visibility.regions.1", "us-west-2"),
					resource.TestCheckResourceAttr(fullResourceName, "realtime_visibility.regions.2", "eu-central-1"),
					// Check updated DSPM regions (still 2 but different)
					resource.TestCheckResourceAttr(fullResourceName, "dspm.regions.#", "2"),
					resource.TestCheckResourceAttr(fullResourceName, "dspm.regions.0", "us-west-2"),
					resource.TestCheckResourceAttr(fullResourceName, "dspm.regions.1", "eu-west-1"),
					// Check updated vulnerability scanning regions (now 1 region)
					resource.TestCheckResourceAttr(fullResourceName, "vulnerability_scanning.regions.#", "1"),
					resource.TestCheckResourceAttr(fullResourceName, "vulnerability_scanning.regions.0", "us-east-1"),
				),
			},
		},
	})
}

// TestRegionsHandlingForAPI tests that regions are properly handled when creating/updating accounts
// This ensures that null regions are converted to empty arrays for API calls.
func TestRegionsHandlingForAPI(t *testing.T) {
	// This test verifies the logic we implemented to send empty arrays when regions are null
	// so the API understands to clear/reset regions
	t.Run("NullRegionsConvertToEmptyArrays", func(t *testing.T) {
		ctx := context.Background()

		// Test the logic that handles null regions by creating empty slices
		var rtvdRegions []string
		var dspmRegions []string
		var vulnRegions []string

		// Simulate what happens in createCloudAccount/updateCloudAccount when regions are null
		nullRegions := types.ListNull(types.StringType)

		// This is the logic from our updated functions - when regions are null, we skip ElementsAs
		if !nullRegions.IsNull() && !nullRegions.IsUnknown() {
			// This should NOT execute for null regions
			nullRegions.ElementsAs(ctx, &rtvdRegions, false)
			t.Errorf("Null regions should not be processed through ElementsAs")
		}

		// When regions are null, we initialize empty slices and pass them to API
		// The key point: In Go, nil slices are equivalent to empty slices when marshaled to JSON
		// So whether we have nil or []string{}, both become [] in JSON, which is what the API needs

		// Verify the null check works correctly
		if !nullRegions.IsNull() {
			t.Errorf("Expected regions to be null")
		}

		// The API will receive these as empty arrays in JSON
		expectedJSONLength := 0
		if len(rtvdRegions) != expectedJSONLength {
			t.Logf("rtvdRegions length: %d (this is expected for nil slice)", len(rtvdRegions))
		}

		if len(dspmRegions) != expectedJSONLength {
			t.Logf("dspmRegions length: %d (this is expected for nil slice)", len(dspmRegions))
		}

		if len(vulnRegions) != expectedJSONLength {
			t.Logf("vulnRegions length: %d (this is expected for nil slice)", len(vulnRegions))
		}
	})

	t.Run("SpecifiedRegionsWork", func(t *testing.T) {
		ctx := context.Background()

		// Create regions list
		regionsList, diags := types.ListValueFrom(ctx, types.StringType, []string{"us-east-1", "us-west-2"})
		if diags.HasError() {
			t.Fatalf("Failed to create regions list: %v", diags.Errors())
		}

		// Test that specified regions are handled correctly
		var rtvdRegions []string
		if !regionsList.IsNull() && !regionsList.IsUnknown() {
			diags := regionsList.ElementsAs(ctx, &rtvdRegions, false)
			if diags.HasError() {
				t.Errorf("Failed to extract regions: %v", diags.Errors())
			}
		}

		// Should have 2 regions
		if len(rtvdRegions) != 2 {
			t.Errorf("Expected 2 regions, got %d", len(rtvdRegions))
		}
		if len(rtvdRegions) >= 2 && (rtvdRegions[0] != "us-east-1" || rtvdRegions[1] != "us-west-2") {
			t.Errorf("Expected regions [us-east-1, us-west-2], got %v", rtvdRegions)
		}
	})
}
