package falconcontainerimage_test

import (
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccFalconContainerImageDataSource(t *testing.T) {
	t.Skip("Skipping test: requires a pre-existing falcon container image registry")
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccFalconContainerImageDataSourceConfig(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.crowdstrike_falcon_container_image.test", "id"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_falcon_container_image.test", "url"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_falcon_container_image.test", "type"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_falcon_container_image.test", "state"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_falcon_container_image.test", "created_at"),
					resource.TestCheckResourceAttrSet("data.crowdstrike_falcon_container_image.test", "refresh_interval"),
				),
			},
		},
	})
}

func testAccFalconContainerImageDataSourceConfig() string {
	return acctest.ProviderConfig + `
data "crowdstrike_falcon_container_image" "test" {
  id = "12345678-1234-1234-1234-123456789012"
}
`
}
