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
					resource.TestCheckResourceAttrSet("data.crowdstrike_cloud_risks.test", "total_count"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_cloud_risks.test", "returned_count"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_cloud_risks.test", "has_more"),
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
					resource.TestCheckResourceAttrSet("data.crowdstrike_cloud_risks.filtered", "total_count"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_cloud_risks.filtered", "returned_count"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_cloud_risks.filtered", "has_more"),
				),
			},
		},
	})
}

func TestAccCloudRisksDataSourceWithPagination(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCloudRisksDataSourceConfigWithPagination(),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Page 1 checks
					resource.TestCheckResourceAttrSet("data.crowdstrike_cloud_risks.page1", "risks.#"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_cloud_risks.page1", "total_count"),
					resource.TestCheckResourceAttr("data.crowdstrike_cloud_risks.page1", "returned_count", "10"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_cloud_risks.page1", "has_more"),
					// Page 2 checks
					resource.TestCheckResourceAttrSet("data.crowdstrike_cloud_risks.page2", "risks.#"),
					resource.TestCheckResourceAttr("data.crowdstrike_cloud_risks.page2", "returned_count", "10"),
				),
			},
		},
	})
}

func testAccCloudRisksDataSourceConfig() string {
	return acctest.ProviderConfig + `
data "crowdstrike_cloud_risks" "test" {
  filter = "status:'Open'"
  limit  = 10
  offset = 0
}
`
}

func testAccCloudRisksDataSourceConfigWithFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_cloud_risks" "filtered" {
  filter = "status:'Open'"
  sort   = "first_seen|desc"
  limit  = 10
  offset = 0
}
`
}

func testAccCloudRisksDataSourceConfigWithPagination() string {
	return acctest.ProviderConfig + `
data "crowdstrike_cloud_risks" "page1" {
  filter = "status:'Open'"
  limit  = 10
  offset = 0
}

data "crowdstrike_cloud_risks" "page2" {
  filter = "status:'Open'"
  limit  = 10
  offset = 10
}
`
}
