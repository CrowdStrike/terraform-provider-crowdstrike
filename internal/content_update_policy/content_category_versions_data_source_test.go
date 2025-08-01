package contentupdatepolicy

import (
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccContentCategoryVersionsDataSource_Basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccContentCategoryVersionsDataSourceConfig(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.crowdstrike_content_category_versions.test", "sensor_operations.#"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_content_category_versions.test", "system_critical.#"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_content_category_versions.test", "vulnerability_management.#"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_content_category_versions.test", "rapid_response.#"),
				),
			},
		},
	})
}

func testAccContentCategoryVersionsDataSourceConfig() string {
	return `
data "crowdstrike_content_category_versions" "test" {}
`
}
