package cloudsecurity_test

import (
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccCloudRiskFindingsDataSource(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCloudRiskFindingsDataSourceConfig(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.crowdstrike_cloud_risk_findings.test", "risks.#"),
				),
			},
		},
	})
}

func TestAccCloudRiskFindingsDataSourceWithFilter(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCloudRiskFindingsDataSourceConfigWithFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.crowdstrike_cloud_risk_findings.filtered", "risks.#"),
				),
			},
		},
	})
}

func testAccCloudRiskFindingsDataSourceConfig() string {
	return acctest.ProviderConfig + `
data "crowdstrike_cloud_risk_findings" "test" {
  filter = "status:'Open'+severity:'High'"
}
`
}

func testAccCloudRiskFindingsDataSourceConfigWithFilter() string {
	return acctest.ProviderConfig + `
data "crowdstrike_cloud_risk_findings" "filtered" {
  filter = "status:'Open'+severity:'High'"
  sort   = "first_seen.desc"
}
`
}
