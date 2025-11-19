package cloudsecurity_test

import (
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccCloudRisksDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCloudRisksDataSourceConfig(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.crowdstrike_cloud_risks.test", "risks.#"),
				),
			},
		},
	})
}

func TestAccCloudRisksDataSourceWithFilter(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCloudRisksDataSourceConfigWithFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.crowdstrike_cloud_risks.filtered", "risks.#"),
				),
			},
		},
	})
}

func TestAccCloudRisksDataSourceNoLimit(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCloudRisksDataSourceNoLimit(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.crowdstrike_cloud_risks.limitless", "risks.#"),
				),
			},
		},
	})
}

func testAccCloudRisksDataSourceConfig() string {
	return acctest.ProviderConfig + `
data "crowdstrike_cloud_risks" "test" {
  limit = 10000
}
`
}

func testAccCloudRisksDataSourceConfigWithFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_cloud_risks" "filtered" {
  filter = "status:'Open'"
  sort   = "first_seen|desc"
  limit  = 1000
}
`
}

func testAccCloudRisksDataSourceNoLimit() string {
	return acctest.ProviderConfig + `
data "crowdstrike_cloud_risks" "limitless" {
  filter = "cloud_provider:'aws'+status:'Open'"
  sort   = "severity|desc"
}
`
}
