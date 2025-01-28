package fcs_test

import (
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccCspmAwsAccountResource(t *testing.T) {
	resourceName := "crowdstrike_cspm_aws_account.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccCspmAwsAccountConfig_basic(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", "123456789000"),
					resource.TestCheckResourceAttr(resourceName, "organization_id", "o-tfunittest"),
					resource.TestCheckResourceAttr(resourceName, "cloudtrail_region", "us-east-1"),
					resource.TestCheckResourceAttr(resourceName, "enable_realtime_visibility", "true"),
					resource.TestCheckResourceAttr(resourceName, "target_ous.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "account_type", "commercial"),

					// Computed fields should exist
					resource.TestCheckResourceAttrSet(resourceName, "external_id"),
					resource.TestCheckResourceAttrSet(resourceName, "intermediate_role_arn"),
					resource.TestCheckResourceAttrSet(resourceName, "iam_role_arn"),
				),
			},
			// Test importing the resource
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateId:                        "123456789000",
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "account_id",
				ImportStateVerifyIgnore: []string{
					"id",
					"target_ous",
					"deployment_method",
				},
			},
			// Update testing
			{
				Config: testAccCspmAwsAccountConfig_update(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", "123456789000"),
					resource.TestCheckResourceAttr(resourceName, "enable_realtime_visibility", "true"),
					resource.TestCheckResourceAttr(resourceName, "enable_sensor_management", "true"),
					resource.TestCheckResourceAttr(resourceName, "cloudtrail_region", "us-west-2"),
				),
			},
			// Test with minimal configuration
			{
				Config: testAccCspmAwsAccountConfig_minimal(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", "123456789001"),
					resource.TestCheckResourceAttr(resourceName, "enable_realtime_visibility", "false"),
					resource.TestCheckResourceAttr(resourceName, "enable_sensor_management", "false"),
					resource.TestCheckResourceAttr(resourceName, "enable_dspm", "false"),
				),
			},
		},
	})
}

func testAccCspmAwsAccountConfig_basic() string {
	return `
resource "crowdstrike_cspm_aws_account" "test" {
    account_id                         = "123456789000"
    organization_id                    = "o-tfunittest"
    is_organization_management_account = true
    cloudtrail_region                  = "us-east-1"
    enable_realtime_visibility         = true
    target_ous                         = ["ou-abcd-defghijk", "r-abcd"]
    deployment_method                  = "terraform-native"
}
`
}
func testAccCspmAwsAccountConfig_update() string {
	return `
resource "crowdstrike_cspm_aws_account" "test" {
    account_id                         = "123456789000"
    organization_id                    = "o-tfunittest"
    is_organization_management_account = true
    cloudtrail_region                  = "us-west-2"
    enable_realtime_visibility         = true
    enable_sensor_management           = true
    target_ous                         = ["ou-abcd-defghijk", "r-abcd"]
    deployment_method                  = "terraform-native"
}
`
}

func testAccCspmAwsAccountConfig_minimal() string {
	return `
resource "crowdstrike_cspm_aws_account" "test" {
    account_id        = "123456789001"
}
`
}
