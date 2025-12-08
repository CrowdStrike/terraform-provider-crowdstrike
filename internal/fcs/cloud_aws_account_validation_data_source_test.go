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

	dataSourceNameStandalone := "data.crowdstrike_cloud_aws_account_validation.standalone"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Test validation for standalone account (should skip validation)
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
					resource.TestCheckResourceAttr(
						dataSourceNameStandalone,
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
  account_id                         = "%s"
  depends_on = [
    crowdstrike_cloud_aws_account.standalone
  ]
}
`, accountID, accountID)
}
