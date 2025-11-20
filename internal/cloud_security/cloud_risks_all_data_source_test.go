package cloudsecurity_test

import (
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccCloudRisksAllDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCloudRisksAllDataSourceConfig(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.crowdstrike_cloud_risks_all.test", "risks.#"),
				),
			},
		},
	})
}

func TestAccCloudRisksAllDataSourceWithFilter(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCloudRisksAllDataSourceConfigWithFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.crowdstrike_cloud_risks_all.filtered", "risks.#"),
				),
			},
		},
	})
}

func testAccCloudRisksAllDataSourceConfig() string {
	return acctest.ProviderConfig + `
data "crowdstrike_cloud_risks_all" "test" {
  filter = "status:'Open'+severity:'High'"
}
`
}

func testAccCloudRisksAllDataSourceConfigWithFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_cloud_risks_all" "filtered" {
  filter = "status:'Open'+severity:'High'"
  sort   = "first_seen|desc"
}
`
}
