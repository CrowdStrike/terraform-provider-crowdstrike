package fcs_test

import (
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCspmAwsAccountResource(t *testing.T) {
	resourceName := "crowdstrike_cspm_aws_account.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + `
				resource "crowdstrike_fcs_aws_account" "test" {
					account_id = "123456789012"
					organization_id = "o-1234567890"
				}
				`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "account_id", "123456789012"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     "123456789012",
				ImportStateVerify: true,
			},
		},
	})
}
