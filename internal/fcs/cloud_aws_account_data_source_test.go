package fcs_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
)

func TestAccCloudAwsAccountDataSource(t *testing.T) {
	testAccountID := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)
	testOrgAccountID := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)
	testOrgID := fmt.Sprintf("o-%s", sdkacctest.RandStringFromCharSet(10, sdkacctest.CharSetAlpha))

	resourceNameAcc := "crowdstrike_cloud_aws_account.acc"
	dataSourceNameAcc := "data.crowdstrike_cloud_aws_account.acc"
	resourceNameOrg := "crowdstrike_cloud_aws_account.org"
	dataSourceNameOrg := "data.crowdstrike_cloud_aws_account.org"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAwsAccountDataSource_byAccountID(testAccountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceNameAcc, "accounts.#", "1"),
					resource.TestCheckResourceAttrPair(resourceNameAcc, "account_id", dataSourceNameAcc, "accounts.0.account_id"),
					resource.TestCheckResourceAttrPair(resourceNameAcc, "is_organization_management_account", dataSourceNameAcc, "accounts.0.is_organization_management_account"),
					resource.TestCheckResourceAttrPair(resourceNameAcc, "account_type", dataSourceNameAcc, "accounts.0.account_type"),
					resource.TestCheckResourceAttrPair(resourceNameAcc, "external_id", dataSourceNameAcc, "accounts.0.external_id"),
					resource.TestCheckResourceAttrPair(resourceNameAcc, "intermediate_role_arn", dataSourceNameAcc, "accounts.0.intermediate_role_arn"),
					resource.TestCheckResourceAttrPair(resourceNameAcc, "iam_role_arn", dataSourceNameAcc, "accounts.0.iam_role_arn"),
					resource.TestCheckResourceAttrPair(resourceNameAcc, "eventbus_name", dataSourceNameAcc, "accounts.0.eventbus_name"),
					resource.TestCheckResourceAttrPair(resourceNameAcc, "eventbus_arn", dataSourceNameAcc, "accounts.0.eventbus_arn"),
					resource.TestCheckResourceAttrPair(resourceNameAcc, "cloudtrail_bucket_name", dataSourceNameAcc, "accounts.0.cloudtrail_bucket_name"),
					resource.TestCheckResourceAttrPair(resourceNameAcc, "realtime_visibility.cloudtrail_region", dataSourceNameAcc, "accounts.0.cloudtrail_region"),
					resource.TestCheckResourceAttrPair(resourceNameAcc, "dspm_role_arn", dataSourceNameAcc, "accounts.0.dspm_role_arn"),
					resource.TestCheckResourceAttrPair(resourceNameAcc, "vulnerability_scanning_role_arn", dataSourceNameAcc, "accounts.0.vulnerability_scanning_role_arn"),
					resource.TestCheckResourceAttrPair(resourceNameAcc, "vulnerability_scanning_role_name", dataSourceNameAcc, "accounts.0.vulnerability_scanning_role_name"),
					resource.TestCheckResourceAttrSet(dataSourceNameAcc, "accounts.0.agentless_scanning_role_name"),
					resource.TestCheckResourceAttrPair(resourceNameAcc, "realtime_visibility.enabled", dataSourceNameAcc, "accounts.0.realtime_visibility_enabled"),
					resource.TestCheckResourceAttrPair(resourceNameAcc, "idp.enabled", dataSourceNameAcc, "accounts.0.idp_enabled"),
					resource.TestCheckResourceAttrPair(resourceNameAcc, "sensor_management.enabled", dataSourceNameAcc, "accounts.0.sensor_management_enabled"),
					resource.TestCheckResourceAttrPair(resourceNameAcc, "dspm.enabled", dataSourceNameAcc, "accounts.0.dspm_enabled"),
					resource.TestCheckResourceAttrPair(resourceNameAcc, "vulnerability_scanning.enabled", dataSourceNameAcc, "accounts.0.vulnerability_scanning_enabled"),
				),
			},
			{
				Config: testAccCloudAwsAccountDataSource_byOrgID(testOrgAccountID, testOrgID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceNameOrg, "accounts.#", "1"),
					resource.TestCheckResourceAttrPair(resourceNameOrg, "account_id", dataSourceNameOrg, "accounts.0.account_id"),
					resource.TestCheckResourceAttrPair(resourceNameOrg, "organization_id", dataSourceNameOrg, "accounts.0.organization_id"),
					resource.TestCheckResourceAttrPair(resourceNameOrg, "is_organization_management_account", dataSourceNameOrg, "accounts.0.is_organization_management_account"),
					resource.TestCheckResourceAttrPair(resourceNameOrg, "account_type", dataSourceNameOrg, "accounts.0.account_type"),
					resource.TestCheckResourceAttrPair(resourceNameOrg, "external_id", dataSourceNameOrg, "accounts.0.external_id"),
					resource.TestCheckResourceAttrPair(resourceNameOrg, "intermediate_role_arn", dataSourceNameOrg, "accounts.0.intermediate_role_arn"),
					resource.TestCheckResourceAttrPair(resourceNameOrg, "iam_role_arn", dataSourceNameOrg, "accounts.0.iam_role_arn"),
					resource.TestCheckResourceAttrPair(resourceNameOrg, "eventbus_name", dataSourceNameOrg, "accounts.0.eventbus_name"),
					resource.TestCheckResourceAttrPair(resourceNameOrg, "eventbus_arn", dataSourceNameOrg, "accounts.0.eventbus_arn"),
					resource.TestCheckResourceAttrPair(resourceNameOrg, "cloudtrail_bucket_name", dataSourceNameOrg, "accounts.0.cloudtrail_bucket_name"),
					resource.TestCheckResourceAttrPair(resourceNameOrg, "realtime_visibility.cloudtrail_region", dataSourceNameOrg, "accounts.0.cloudtrail_region"),
					resource.TestCheckResourceAttrPair(resourceNameOrg, "dspm_role_arn", dataSourceNameOrg, "accounts.0.dspm_role_arn"),
					resource.TestCheckResourceAttrPair(resourceNameOrg, "vulnerability_scanning_role_arn", dataSourceNameOrg, "accounts.0.vulnerability_scanning_role_arn"),
					resource.TestCheckResourceAttrPair(resourceNameOrg, "vulnerability_scanning_role_name", dataSourceNameOrg, "accounts.0.vulnerability_scanning_role_name"),
					resource.TestCheckResourceAttrSet(dataSourceNameOrg, "accounts.0.agentless_scanning_role_name"),
					resource.TestCheckResourceAttrPair(resourceNameOrg, "realtime_visibility.enabled", dataSourceNameOrg, "accounts.0.realtime_visibility_enabled"),
					resource.TestCheckResourceAttrPair(resourceNameOrg, "idp.enabled", dataSourceNameOrg, "accounts.0.idp_enabled"),
					resource.TestCheckResourceAttrPair(resourceNameOrg, "sensor_management.enabled", dataSourceNameOrg, "accounts.0.sensor_management_enabled"),
					resource.TestCheckResourceAttrPair(resourceNameOrg, "dspm.enabled", dataSourceNameOrg, "accounts.0.dspm_enabled"),
					resource.TestCheckResourceAttrPair(resourceNameOrg, "vulnerability_scanning.enabled", dataSourceNameOrg, "accounts.0.vulnerability_scanning_enabled"),
				),
			},
		},
	})
}

func TestAccCloudAwsAccountDataSource_Minimal(t *testing.T) {
	accountID := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)

	resourceName := "crowdstrike_cloud_aws_account.test"
	dataSourceName := "data.crowdstrike_cloud_aws_account.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAwsAccountDataSource_minimal(accountID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, "accounts.#", "1"),
					resource.TestCheckResourceAttrPair(resourceName, "account_id", dataSourceName, "accounts.0.account_id"),
					resource.TestCheckResourceAttrPair(resourceName, "is_organization_management_account", dataSourceName, "accounts.0.is_organization_management_account"),
					resource.TestCheckResourceAttrPair(resourceName, "account_type", dataSourceName, "accounts.0.account_type"),
					resource.TestCheckResourceAttrPair(resourceName, "external_id", dataSourceName, "accounts.0.external_id"),
					resource.TestCheckResourceAttrPair(resourceName, "intermediate_role_arn", dataSourceName, "accounts.0.intermediate_role_arn"),
					resource.TestCheckResourceAttrPair(resourceName, "iam_role_arn", dataSourceName, "accounts.0.iam_role_arn"),
					resource.TestCheckResourceAttrPair(resourceName, "iam_role_name", dataSourceName, "accounts.0.iam_role_name"),
					resource.TestCheckResourceAttrPair(resourceName, "eventbus_name", dataSourceName, "accounts.0.eventbus_name"),
					resource.TestCheckResourceAttrPair(resourceName, "eventbus_arn", dataSourceName, "accounts.0.eventbus_arn"),
					resource.TestCheckResourceAttrPair(resourceName, "cloudtrail_bucket_name", dataSourceName, "accounts.0.cloudtrail_bucket_name"),
					resource.TestCheckResourceAttrPair(resourceName, "realtime_visibility.cloudtrail_region", dataSourceName, "accounts.0.cloudtrail_region"),
					resource.TestCheckResourceAttrPair(resourceName, "dspm_role_arn", dataSourceName, "accounts.0.dspm_role_arn"),
					resource.TestCheckResourceAttrPair(resourceName, "dspm_role_name", dataSourceName, "accounts.0.dspm_role_name"),
					resource.TestCheckResourceAttrPair(resourceName, "vulnerability_scanning_role_arn", dataSourceName, "accounts.0.vulnerability_scanning_role_arn"),
					resource.TestCheckResourceAttrPair(resourceName, "vulnerability_scanning_role_name", dataSourceName, "accounts.0.vulnerability_scanning_role_name"),
					resource.TestCheckResourceAttrPair(resourceName, "agentless_scanning_role_name", dataSourceName, "accounts.0.agentless_scanning_role_name"),
					resource.TestCheckResourceAttrPair(resourceName, "asset_inventory.enabled", dataSourceName, "accounts.0.asset_inventory_enabled"),
					resource.TestCheckResourceAttrPair(resourceName, "realtime_visibility.enabled", dataSourceName, "accounts.0.realtime_visibility_enabled"),
					resource.TestCheckResourceAttrPair(resourceName, "idp.enabled", dataSourceName, "accounts.0.idp_enabled"),
					resource.TestCheckResourceAttrPair(resourceName, "sensor_management.enabled", dataSourceName, "accounts.0.sensor_management_enabled"),
					resource.TestCheckResourceAttrPair(resourceName, "dspm.enabled", dataSourceName, "accounts.0.dspm_enabled"),
					resource.TestCheckResourceAttrPair(resourceName, "vulnerability_scanning.enabled", dataSourceName, "accounts.0.vulnerability_scanning_enabled"),
				),
			},
		},
	})
}

func testAccCloudAwsAccountDataSource_byAccountID(accountID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "acc" {
  account_id = %[1]q

  realtime_visibility = {
    enabled           = true
    cloudtrail_region = "us-east-1"
  }

  dspm = {
    enabled = true
  }

  vulnerability_scanning = {
    enabled = true
  }

  idp = {
    enabled = true
  }

  sensor_management = {
    enabled = true
  }
}

data "crowdstrike_cloud_aws_account" "acc" {
  account_id = %[1]q
  depends_on = [
    crowdstrike_cloud_aws_account.acc
  ]
}
`, accountID)
}

func testAccCloudAwsAccountDataSource_byOrgID(accountID, orgID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "org" {
  account_id      = %[1]q
  organization_id = %[2]q

  realtime_visibility = {
    enabled           = true
    cloudtrail_region = "us-east-1"
  }

  dspm = {
    enabled = true
  }

  vulnerability_scanning = {
    enabled = true
  }

  idp = {
    enabled = true
  }

  sensor_management = {
    enabled = true
  }
}

data "crowdstrike_cloud_aws_account" "org" {
  organization_id = %[2]q
  depends_on = [
    crowdstrike_cloud_aws_account.org
  ]
}
`, accountID, orgID)
}

func testAccCloudAwsAccountDataSource_minimal(accountID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "test" {
  account_id = %[1]q
}

data "crowdstrike_cloud_aws_account" "test" {
  account_id = %[1]q
  depends_on = [
    crowdstrike_cloud_aws_account.test
  ]
}
`, accountID)
}
