package fcs_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
)

func TestAccCloudAwsAccountValidationDataSource(t *testing.T) {
	testAccountID := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)
	testOrgAccountID := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)
	testOrgID := fmt.Sprintf("o-%s", sdkacctest.RandStringFromCharSet(10, sdkacctest.CharSetAlpha))

	dataSourceNameStandalone := "data.crowdstrike_cloud_aws_account_validation.standalone"
	dataSourceNameOrg := "data.crowdstrike_cloud_aws_account_validation.org"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Test validation for standalone account
			{
				Config: testAccCloudAwsAccountValidationDataSource_standalone(testAccountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Check resource was created
					resource.TestCheckResourceAttr(
						"crowdstrike_cloud_aws_account.standalone",
						"account_id",
						testAccountID,
					),

					// Check data source attributes
					resource.TestCheckResourceAttr(
						dataSourceNameStandalone,
						"account_id",
						testAccountID,
					),
					// organization_id should not be specified for standalone accounts
					resource.TestCheckNoResourceAttr(
						dataSourceNameStandalone,
						"organization_id",
					),
					resource.TestCheckNoResourceAttr(
						dataSourceNameStandalone,
						"wait_time",
					),
					resource.TestCheckResourceAttr(
						dataSourceNameStandalone,
						"validated",
						"true",
					),
				),
			},
			// Test validation for organization account
			{
				Config: testAccCloudAwsAccountValidationDataSource_organization(testOrgAccountID, testOrgID, 0),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Check resource was created
					resource.TestCheckResourceAttr(
						"crowdstrike_cloud_aws_account.org",
						"account_id",
						testOrgAccountID,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_cloud_aws_account.org",
						"organization_id",
						testOrgID,
					),

					// Check data source attributes
					resource.TestCheckResourceAttr(
						dataSourceNameOrg,
						"account_id",
						testOrgAccountID,
					),
					resource.TestCheckResourceAttr(
						dataSourceNameOrg,
						"organization_id",
						testOrgID,
					),
					resource.TestCheckResourceAttr(
						dataSourceNameOrg,
						"wait_time",
						"0",
					),
					resource.TestCheckResourceAttr(
						dataSourceNameOrg,
						"validated",
						"true",
					),
				),
			},
		},
	})
}

func testAccCloudAwsAccountValidationDataSource_standalone(accountID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "standalone" {
  account_id = "%s"
}

data "crowdstrike_cloud_aws_account_validation" "standalone" {
  account_id = "%s"
  depends_on = [
    crowdstrike_cloud_aws_account.standalone
  ]
}
`, accountID, accountID)
}

func testAccCloudAwsAccountValidationDataSource_organization(accountID, organizationID string, waitTime int) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "org" {
  account_id      = "%s"
  organization_id = "%s"
}

data "crowdstrike_cloud_aws_account_validation" "org" {
  account_id      = "%s"
  organization_id = "%s"
  wait_time       = %d
  depends_on = [
    crowdstrike_cloud_aws_account.org
  ]
}
`, accountID, organizationID, accountID, organizationID, waitTime)
}
