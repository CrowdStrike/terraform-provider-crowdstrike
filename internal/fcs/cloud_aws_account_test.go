package fcs_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
)

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
				),
			},
		},
	})
}

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
				),
			},
		},
	})
}

// Minimal configuration with only required attributes.
func testAccCloudAwsAccountConfig_minimal(account string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
    account_id                         = "%s"
}
`, account)
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
