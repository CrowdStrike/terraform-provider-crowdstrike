package fcs_test

import (
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccCspmAwsAccountDataSource(t *testing.T) {
	dataSourceName := "data.crowdstrike_cspm_aws_accounts.all"
	resourceName := "crowdstrike_cspm_aws_account.this"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Test querying by organization_id
			{
				Config: testAccCspmAwsAccountDataSource_byOrgId(),
				Check: resource.ComposeTestCheckFunc(
					// Verify the data source attributes
					resource.TestCheckResourceAttrSet(dataSourceName, "id"),
					resource.TestCheckResourceAttr(dataSourceName, "organization_id", "o-aaabbbccdd"),
					// Verify we can get accounts
					resource.TestCheckResourceAttrSet(dataSourceName, "accounts.#"),
					// Verify specific account details
					resource.TestCheckTypeSetElemNestedAttrs(dataSourceName, "accounts.*", map[string]string{
						"account_id":                         "123456789003",
						"organization_id":                    "o-aaabbbccdd",
						"is_organization_management_account": "true",
						"cloudtrail_region":                  "us-east-1",
						"enable_realtime_visibility":         "true",
					}),
					// Verify the account has all required computed fields
					resource.TestCheckTypeSetElemAttrPair(
						dataSourceName, "accounts.*.external_id",
						resourceName, "external_id",
					),
					resource.TestCheckTypeSetElemAttrPair(
						dataSourceName, "accounts.*.intermediate_role_arn",
						resourceName, "intermediate_role_arn",
					),
					resource.TestCheckTypeSetElemAttrPair(
						dataSourceName, "accounts.*.iam_role_arn",
						resourceName, "iam_role_arn",
					),
				),
			},
			// Test querying by account_id
			{
				Config: testAccCspmAwsAccountDataSource_byAccountId(),
				Check: resource.ComposeTestCheckFunc(
					// Verify the data source attributes
					resource.TestCheckResourceAttrSet(dataSourceName, "id"),
					resource.TestCheckResourceAttr(dataSourceName, "account_id", "123456789004"),
					// Should return exactly one account
					resource.TestCheckResourceAttr(dataSourceName, "accounts.#", "1"),
					// Verify specific account details
					resource.TestCheckResourceAttr(dataSourceName, "accounts.0.account_id", "123456789004"),
					resource.TestCheckResourceAttr(dataSourceName, "accounts.0.is_organization_management_account", "false"),
					resource.TestCheckResourceAttr(dataSourceName, "accounts.0.cloudtrail_region", "us-east-1"),
					resource.TestCheckResourceAttr(dataSourceName, "accounts.0.enable_realtime_visibility", "true"),
					// Verify computed fields exist
					resource.TestCheckResourceAttrSet(dataSourceName, "accounts.0.external_id"),
					resource.TestCheckResourceAttrSet(dataSourceName, "accounts.0.intermediate_role_arn"),
					resource.TestCheckResourceAttrSet(dataSourceName, "accounts.0.iam_role_arn"),
				),
			},
		},
	})
}

func testAccCspmAwsAccountDataSource_byOrgId() string {
	return `
resource "crowdstrike_cspm_aws_account" "this" {
    account_id                         = "123456789003"
    organization_id                    = "o-aaabbbccdd"
    is_organization_management_account = true
    cloudtrail_region                  = "us-east-1"
    enable_realtime_visibility         = true
    target_ous                         = ["ou-abcd-defghijk", "r-abcd"]
}

data "crowdstrike_cspm_aws_accounts" "all" {
    organization_id = "o-aaabbbccdd"
    depends_on = [
        crowdstrike_cspm_aws_account.this
    ]
}
`
}

func testAccCspmAwsAccountDataSource_byAccountId() string {
	return `
resource "crowdstrike_cspm_aws_account" "this" {
    account_id                         = "123456789004"
    cloudtrail_region                  = "us-east-1"
    enable_realtime_visibility         = true
}

data "crowdstrike_cspm_aws_accounts" "all" {
    account_id = "123456789004"
    depends_on = [
        crowdstrike_cspm_aws_account.this
    ]
}
`
}
