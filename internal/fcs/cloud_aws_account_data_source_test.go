package fcs_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
)

var (
	test_account_id     = sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)
	test_org_account_id = sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)
	test_org_id         = fmt.Sprintf("o-%s", sdkacctest.RandStringFromCharSet(10, sdkacctest.CharSetAlpha))
)

func TestAccCloudAwsAccountDataSource(t *testing.T) {
	resourceNameAcc := "crowdstrike_cloud_aws_account.acc"
	dataSourceNameAcc := "data.crowdstrike_cloud_aws_account.acc"
	resourceNameOrg := "crowdstrike_cloud_aws_account.org"
	dataSourceNameOrg := "data.crowdstrike_cloud_aws_account.org"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudAwsAccountDataSource_byAccountID(),
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
				Config: testAccCloudAwsAccountDataSource_byOrgID(),
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

func testAccCloudAwsAccountDataSource_byAccountID() string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_aws_account" "acc" {
  account_id                         = "%s"
  
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
  organization_id = "%s"
  depends_on = [
    crowdstrike_cloud_aws_account.org
  ]
}
`, test_org_account_id, test_org_id, test_org_id)
}
