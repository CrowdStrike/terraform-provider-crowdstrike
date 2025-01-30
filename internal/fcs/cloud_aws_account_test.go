package fcs_test

import (
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccCloudAwsAccountResource(t *testing.T) {
	resourceName := "crowdstrike_cloud_aws_account.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccCloudAwsAccountConfig_basic(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", "123456789010"),
					resource.TestCheckResourceAttr(resourceName, "organization_id", "o-tfacctestt"),
					resource.TestCheckResourceAttr(resourceName, "is_organization_management_account", "true"),
					resource.TestCheckResourceAttr(resourceName, "csp_events", "false"),
					// Test products list
					resource.TestCheckResourceAttr(resourceName, "products.#", "0"),
				),
			},
			// Import testing
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateId:                        "123456789010",
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "account_id",
				ImportStateVerifyIgnore: []string{
					"id",
				},
			},
			// Update testing
			{
				Config: testAccCloudAwsAccountConfig_update(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", "123456789010"),
					resource.TestCheckResourceAttr(resourceName, "csp_events", "true"),
					// Test updated products
					resource.TestCheckResourceAttr(resourceName, "products.0.product", "idp"),
					resource.TestCheckResourceAttr(resourceName, "products.0.features.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "products.0.features.0", "default"),
				),
			},
			// Test minimal configuration
			{
				Config: testAccCloudAwsAccountConfig_minimal(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", "123456789020"),
					resource.TestCheckResourceAttr(resourceName, "csp_events", "true"),
					resource.TestCheckResourceAttr(resourceName, "products.#", "0"),
				),
			},
		},
	})
}

// Basic configuration.
func testAccCloudAwsAccountConfig_basic() string {
	return `
resource "crowdstrike_cspm_aws_account" "this" {
    account_id                         = "123456789010"
    organization_id                    = "o-tfacctestt"
    is_organization_management_account = true
    cloudtrail_region                  = "us-east-1"
    enable_realtime_visibility         = true
    deployment_method                  = "terraform-native"
}

resource "crowdstrike_cloud_aws_account" "test" {
    account_id                         = "123456789010"
    organization_id                    = "o-tfacctestt"
    is_organization_management_account = true
    csp_events                         = false
    products = [
    ]
    depends_on = [
        crowdstrike_cspm_aws_account.this
    ]
}
`
}

// Updated configuration with multiple products.
func testAccCloudAwsAccountConfig_update() string {
	return `
resource "crowdstrike_cspm_aws_account" "this" {
    account_id                         = "123456789010"
    organization_id                    = "o-tfacctestt"
    is_organization_management_account = true
    cloudtrail_region                  = "us-east-1"
    enable_realtime_visibility         = true
    deployment_method                  = "terraform-native"
}

resource "crowdstrike_cloud_aws_account" "test" {
    account_id                         = "123456789010"
    organization_id                    = "o-tfacctestt"
    is_organization_management_account = true
    csp_events                         = true
    products = [
        {
            product  = "idp"
            features = ["default"]
        }
    ]
    depends_on = [
        crowdstrike_cspm_aws_account.this
    ]
}
`
}

// Minimal configuration with only required attributes.
func testAccCloudAwsAccountConfig_minimal() string {
	return `
resource "crowdstrike_cspm_aws_account" "this" {
    account_id                         = "123456789020"
    cloudtrail_region                  = "us-east-1"
    enable_realtime_visibility         = true
}

resource "crowdstrike_cloud_aws_account" "test" {
    account_id = "123456789020"
    csp_events = true
    depends_on = [
        crowdstrike_cspm_aws_account.this
    ]
}
`
}
