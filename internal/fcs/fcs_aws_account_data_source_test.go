package fcs_test

import (
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccCloudAwsAccountDataSource(t *testing.T) {
	dataSourceName := "data.crowdstrike_cloud_aws_accounts.test"
	resourceName := "crowdstrike_cloud_aws_account.this"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// First create the resources
			{
				Config: testAccCloudAwsAccountDataSource_resource(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", "123456789030"),
					resource.TestCheckResourceAttr(resourceName, "csp_events", "true"),
				),
			},
			// Test data source by account_id
			{
				Config: testAccCloudAwsAccountDataSource_byAccountID(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, "account.account_id", "123456789030"),
					resource.TestCheckResourceAttr(dataSourceName, "account.account_type", "commercial"),
					resource.TestCheckResourceAttr(dataSourceName, "account.csp_events", "true"),
					resource.TestCheckResourceAttr(dataSourceName, "account.is_organization_management_account", "false"),
					resource.TestCheckResourceAttr(dataSourceName, "account.organization_id", ""),

					// Verify products
					resource.TestCheckResourceAttr(dataSourceName, "account.products.#", "1"),
					resource.TestCheckResourceAttr(dataSourceName, "account.products.0.product", "idp"),
					resource.TestCheckResourceAttr(dataSourceName, "account.products.0.features.#", "1"),
					// resource.TestCheckResourceAttr(dataSourceName, "account.products.0.features.0", "default"),
				),
			},
		},
	})
}

func testAccCloudAwsAccountDataSource_resource() string {
	return `
resource "crowdstrike_cspm_aws_account" "this" {
    account_id                         = "123456789030"
    cloudtrail_region                  = "us-east-1"
    enable_realtime_visibility         = true
}

resource "crowdstrike_cloud_aws_account" "this" {
    account_id = "123456789030"
    csp_events = true
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

func testAccCloudAwsAccountDataSource_byAccountID() string {
	return `
data "crowdstrike_cloud_aws_accounts" "test" {
    account_id = "123456789030"
}
`
}
