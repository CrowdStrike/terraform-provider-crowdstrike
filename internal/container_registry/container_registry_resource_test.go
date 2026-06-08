package containerregistry_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccContainerRegistryResource_DockerHub(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_container_registry.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccContainerRegistryDockerHubConfig(rName, "user1", "pass1"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "type", "dockerhub"),
					resource.TestCheckResourceAttr(resourceName, "user_defined_alias", rName),
					resource.TestCheckResourceAttr(resourceName, "credential.username", "user1"),
					resource.TestCheckResourceAttrSet(resourceName, "state"),
					resource.TestCheckResourceAttrSet(resourceName, "created_at"),
				),
			},
			{
				Config: testAccContainerRegistryDockerHubConfig(rName, "user1", "pass2"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "credential.username", "user1"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"last_updated",
					"credential.username",
					"credential.password",
					"credential.aws_iam_role",
					"credential.aws_external_id",
					"credential.aws_gov_using_commercial_connection",
					"credential.domain_url",
					"credential.credential_type",
					"credential.project_id",
					"credential.scope_name",
					"credential.cert",
					"credential.auth_type",
					"credential.tenant_id",
					"credential.client",
					"credential.compartment_ids",
					"credential.service_account_json",
					"url_uniqueness_key",
				},
			},
		},
	})
}

func testAccContainerRegistryDockerHubConfig(alias, username, password string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_container_registry" "test" {
  url                = "https://registry-1.docker.io/"
  type               = "dockerhub"
  user_defined_alias = %[1]q
  url_uniqueness_key = %[1]q

  credential = {
    username = %[2]q
    password = %[3]q
  }
}
`, alias, username, password)
}
