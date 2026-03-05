package falconcontainerimage_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const resourceName = "crowdstrike_falcon_container_image.test"

func TestAccFalconContainerImageResource_DockerHub(t *testing.T) {
	rName := acctest.RandomResourceName()
	username := os.Getenv("TEST_DOCKERHUB_USERNAME")
	password := os.Getenv("TEST_DOCKERHUB_TOKEN")

	if username == "" || password == "" {
		t.Skip("TEST_DOCKERHUB_USERNAME and TEST_DOCKERHUB_TOKEN must be set for this test")
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFalconContainerImageConfigDockerHub(rName, username, password),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("dockerhub")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_defined_alias"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("state"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"credential.details"},
			},
		},
	})
}

func TestAccFalconContainerImageResource_ECR(t *testing.T) {
	rName := acctest.RandomResourceName()
	awsIAMRole := os.Getenv("TEST_AWS_IAM_ROLE")
	awsExternalID := os.Getenv("TEST_AWS_EXTERNAL_ID")
	ecrURL := os.Getenv("TEST_ECR_URL")

	if awsIAMRole == "" || awsExternalID == "" || ecrURL == "" {
		t.Skip("TEST_AWS_IAM_ROLE, TEST_AWS_EXTERNAL_ID, and TEST_ECR_URL must be set for this test")
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFalconContainerImageConfigECR(rName, ecrURL, awsIAMRole, awsExternalID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("ecr")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_defined_alias"), knownvalue.StringExact(rName)),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"credential.details"},
			},
		},
	})
}

func TestAccFalconContainerImageResource_Update(t *testing.T) {
	rName := acctest.RandomResourceName()
	rNameUpdated := rName + "-updated"
	username := os.Getenv("TEST_DOCKERHUB_USERNAME")
	password := os.Getenv("TEST_DOCKERHUB_TOKEN")

	if username == "" || password == "" {
		t.Skip("TEST_DOCKERHUB_USERNAME and TEST_DOCKERHUB_TOKEN must be set for this test")
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFalconContainerImageConfigDockerHub(rName, username, password),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_defined_alias"), knownvalue.StringExact(rName)),
				},
			},
			{
				Config: testAccFalconContainerImageConfigDockerHub(rNameUpdated, username, password),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_defined_alias"), knownvalue.StringExact(rNameUpdated)),
				},
			},
		},
	})
}

func testAccFalconContainerImageConfigDockerHub(alias, username, password string) string {
	return fmt.Sprintf(`
resource "crowdstrike_falcon_container_image" "test" {
  url  = "https://registry-1.docker.io/"
  type = "dockerhub"

  user_defined_alias = %[1]q
  url_uniqueness_key = %[1]q

  credential {
    details {
      username = %[2]q
      password = %[3]q
    }
  }
}
`, alias, username, password)
}

func testAccFalconContainerImageConfigECR(alias, url, iamRole, externalID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_falcon_container_image" "test" {
  url  = %[2]q
  type = "ecr"

  user_defined_alias = %[1]q

  credential {
    details {
      aws_iam_role    = %[3]q
      aws_external_id = %[4]q
    }
  }
}
`, alias, url, iamRole, externalID)
}
