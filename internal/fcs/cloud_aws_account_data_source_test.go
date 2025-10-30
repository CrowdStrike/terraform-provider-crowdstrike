package fcs_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
)

var test_account_id = sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)
var test_org_account_id = sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)
var test_org_id = fmt.Sprintf("o-%s", sdkacctest.RandStringFromCharSet(10, sdkacctest.CharSetAlpha))

func TestAccCloudAwsAccountDataSource(t *testing.T) {
	dataSourceNameAcc := "data.crowdstrike_cloud_aws_account.acc"
	dataSourceNameOrg := "data.crowdstrike_cloud_aws_account.org"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Test data source by account_id
			{
				Config: testAccCloudAwsAccountDataSource_byAccountID(),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Check resource was created
					resource.TestCheckResourceAttr(
						"crowdstrike_cloud_aws_account.acc",
						"account_id",
						test_account_id,
					),

					resource.TestCheckResourceAttr(dataSourceNameAcc, "accounts.#", "1"),
					resource.TestCheckResourceAttr(
						dataSourceNameAcc,
						"accounts.0.account_id",
						test_account_id,
					),
					resource.TestCheckResourceAttr(
						dataSourceNameAcc,
						"accounts.0.organization_id",
						"",
					),
					resource.TestCheckResourceAttr(
						dataSourceNameAcc,
						"accounts.0.is_organization_management_account",
						"false",
					),
					resource.TestCheckResourceAttr(
						dataSourceNameAcc,
						"accounts.0.account_type",
						"commercial",
					),
					// Computed fields should exist
					resource.TestCheckResourceAttrSet(dataSourceNameAcc, "accounts.0.external_id"),
					resource.TestCheckResourceAttrSet(
						dataSourceNameAcc,
						"accounts.0.intermediate_role_arn",
					),
					resource.TestCheckResourceAttrSet(dataSourceNameAcc, "accounts.0.iam_role_arn"),
					resource.TestCheckResourceAttrSet(
						dataSourceNameAcc,
						"accounts.0.eventbus_name",
					),
					resource.TestCheckResourceAttrSet(dataSourceNameAcc, "accounts.0.eventbus_arn"),
					resource.TestCheckResourceAttrSet(
						dataSourceNameAcc,
						"accounts.0.dspm_role_arn",
					),
					resource.TestCheckResourceAttr(dataSourceNameAcc, "accounts.0.vulnerability_scanning_role_arn", ""),
					resource.TestCheckResourceAttr(dataSourceNameAcc, "accounts.0.vulnerability_scanning_role_name", ""),
					resource.TestCheckResourceAttrSet(dataSourceNameAcc, "accounts.0.agentless_scanning_role_name"),
				),
			},
			// Test data source by organization_id
			{
				Config: testAccCloudAwsAccountDataSource_byOrgID(),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Check resource was created
					resource.TestCheckResourceAttr(
						"crowdstrike_cloud_aws_account.org",
						"account_id",
						test_org_account_id,
					),

					resource.TestCheckResourceAttr(dataSourceNameOrg, "accounts.#", "1"),
					resource.TestCheckResourceAttr(
						dataSourceNameOrg,
						"accounts.0.account_id",
						test_org_account_id,
					),
					resource.TestCheckResourceAttr(
						dataSourceNameOrg,
						"accounts.0.organization_id",
						test_org_id,
					),
					resource.TestCheckResourceAttr(
						dataSourceNameOrg,
						"accounts.0.is_organization_management_account",
						"true",
					),
					resource.TestCheckResourceAttr(
						dataSourceNameOrg,
						"accounts.0.account_type",
						"commercial",
					),
					// Computed fields should exist
					resource.TestCheckResourceAttrSet(dataSourceNameOrg, "accounts.0.external_id"),
					resource.TestCheckResourceAttrSet(
						dataSourceNameOrg,
						"accounts.0.intermediate_role_arn",
					),
					resource.TestCheckResourceAttrSet(dataSourceNameOrg, "accounts.0.iam_role_arn"),
					resource.TestCheckResourceAttrSet(
						dataSourceNameOrg,
						"accounts.0.eventbus_name",
					),
					resource.TestCheckResourceAttrSet(dataSourceNameOrg, "accounts.0.eventbus_arn"),
					resource.TestCheckResourceAttrSet(
						dataSourceNameOrg,
						"accounts.0.dspm_role_arn",
					),
					resource.TestCheckResourceAttr(dataSourceNameOrg, "accounts.0.vulnerability_scanning_role_arn", ""),
					resource.TestCheckResourceAttr(dataSourceNameOrg, "accounts.0.vulnerability_scanning_role_name", ""),
					resource.TestCheckResourceAttrSet(
						dataSourceNameOrg,
						"accounts.0.agentless_scanning_role_name",
					),
				),
			},
		},
	})
}

func testAccCloudAwsAccountDataSource_byAccountID() string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "acc" {
  account_id                         = "%s"
}

data "crowdstrike_cloud_aws_account" "acc" {
  account_id = "%s"
  depends_on = [
    crowdstrike_cloud_aws_account.acc
  ]
}
`, test_account_id, test_account_id)
}

func testAccCloudAwsAccountDataSource_byOrgID() string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "org" {
  account_id                         = "%s"
  organization_id                    = "%s"
}

data "crowdstrike_cloud_aws_account" "org" {
  organization_id = "%s"
  depends_on = [
    crowdstrike_cloud_aws_account.org
  ]
}
`, test_org_account_id, test_org_id, test_org_id)
}
