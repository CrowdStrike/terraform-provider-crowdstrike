package cloudgroup_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccCloudSecurityGroupResource_AWS(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_cloud_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudSecurityGroupResourceConfigAWS(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test AWS cloud security group"),
					resource.TestCheckResourceAttr(resourceName, "business_impact", "high"),
					resource.TestCheckResourceAttr(resourceName, "business_unit", "Engineering"),
					resource.TestCheckResourceAttr(resourceName, "environment", "dev"),
					resource.TestCheckResourceAttr(resourceName, "owners.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "owners.0", "test@example.com"),
					resource.TestCheckResourceAttr(resourceName, "aws.account_ids.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "aws.account_ids.0", "123456789012"),
					resource.TestCheckResourceAttr(resourceName, "aws.filters.region.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "aws.filters.region.0", "us-east-1"),
					resource.TestCheckResourceAttr(resourceName, "aws.filters.tags.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "aws.filters.tags.0", "env=prod"),
					resource.TestCheckResourceAttrSet(resourceName, "created_at"),
					resource.TestCheckResourceAttrSet(resourceName, "updated_at"),
					resource.TestCheckResourceAttrSet(resourceName, "created_by"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccCloudSecurityGroupResource_Azure(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_cloud_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudSecurityGroupResourceConfigAzure(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test Azure cloud security group"),
					resource.TestCheckResourceAttr(resourceName, "azure.account_ids.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "azure.account_ids.0", "12345678-1234-1234-1234-123456789012"),
					resource.TestCheckResourceAttr(resourceName, "azure.filters.region.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "azure.filters.region.0", "eastus"),
					resource.TestCheckResourceAttrSet(resourceName, "created_at"),
					resource.TestCheckResourceAttrSet(resourceName, "updated_at"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccCloudSecurityGroupResource_GCP(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_cloud_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudSecurityGroupResourceConfigGCP(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test GCP cloud security group"),
					resource.TestCheckResourceAttr(resourceName, "gcp.account_ids.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "gcp.account_ids.0", "my-gcp-project"),
					resource.TestCheckResourceAttr(resourceName, "gcp.filters.region.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "gcp.filters.region.0", "us-central1"),
					resource.TestCheckResourceAttrSet(resourceName, "created_at"),
					resource.TestCheckResourceAttrSet(resourceName, "updated_at"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccCloudSecurityGroupResource_Images(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_cloud_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudSecurityGroupResourceConfigImages(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test container images group"),
					resource.TestCheckResourceAttr(resourceName, "images.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "images.0.registry", "docker.io"),
					resource.TestCheckResourceAttr(resourceName, "images.0.repository", "nginx"),
					resource.TestCheckResourceAttr(resourceName, "images.0.tag", "latest"),
					resource.TestCheckResourceAttr(resourceName, "images.1.registry", "gcr.io"),
					resource.TestCheckResourceAttr(resourceName, "images.1.repository", "my-project/my-app"),
					resource.TestCheckResourceAttr(resourceName, "images.1.tag", "v1.0.0"),
					resource.TestCheckResourceAttrSet(resourceName, "created_at"),
					resource.TestCheckResourceAttrSet(resourceName, "updated_at"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccCloudSecurityGroupResource_MultiCloud(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_cloud_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudSecurityGroupResourceConfigMultiCloud(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Multi-cloud security group"),
					resource.TestCheckResourceAttr(resourceName, "aws.account_ids.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "aws.account_ids.0", "123456789012"),
					resource.TestCheckResourceAttr(resourceName, "aws.account_ids.1", "210987654321"),
					resource.TestCheckResourceAttr(resourceName, "azure.account_ids.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "gcp.account_ids.#", "1"),
					resource.TestCheckResourceAttrSet(resourceName, "created_at"),
					resource.TestCheckResourceAttrSet(resourceName, "updated_at"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccCloudSecurityGroupResource_Update(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	rNameUpdated := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_cloud_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudSecurityGroupResourceConfigAWS(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test AWS cloud security group"),
					resource.TestCheckResourceAttr(resourceName, "business_impact", "high"),
					resource.TestCheckResourceAttr(resourceName, "owners.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "aws.account_ids.#", "1"),
				),
			},
			{
				Config: testAccCloudSecurityGroupResourceConfigAWSUpdated(rNameUpdated),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rNameUpdated),
					resource.TestCheckResourceAttr(resourceName, "description", "Updated AWS cloud security group"),
					resource.TestCheckResourceAttr(resourceName, "business_impact", "moderate"),
					resource.TestCheckResourceAttr(resourceName, "owners.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "owners.0", "test@example.com"),
					resource.TestCheckResourceAttr(resourceName, "owners.1", "admin@example.com"),
					resource.TestCheckResourceAttr(resourceName, "aws.account_ids.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "aws.filters.region.#", "2"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccCloudSecurityGroupResource_MinimalConfig(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_cloud_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudSecurityGroupResourceConfigMinimal(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "aws.account_ids.#", "1"),
					resource.TestCheckResourceAttrSet(resourceName, "created_at"),
					resource.TestCheckResourceAttrSet(resourceName, "updated_at"),
					resource.TestCheckResourceAttrSet(resourceName, "created_by"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccCloudSecurityGroupResource_NoProviders(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_cloud_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudSecurityGroupResourceConfigNoProviders(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttrSet(resourceName, "created_at"),
					resource.TestCheckResourceAttrSet(resourceName, "updated_at"),
					resource.TestCheckResourceAttrSet(resourceName, "created_by"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccCloudSecurityGroupResource_AddRemoveFields(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_cloud_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudSecurityGroupResourceConfigMinimal(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
				),
			},
			{
				Config: testAccCloudSecurityGroupResourceConfigAWS(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test AWS cloud security group"),
					resource.TestCheckResourceAttr(resourceName, "business_impact", "high"),
					resource.TestCheckResourceAttr(resourceName, "owners.#", "1"),
				),
			},
			{
				Config: testAccCloudSecurityGroupResourceConfigMinimal(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
				),
			},
		},
	})
}

func TestAccCloudSecurityGroupResource_Validation(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	testCases := map[string]struct {
		configFunc  func(string) string
		expectError *regexp.Regexp
	}{
		"empty_name": {
			configFunc:  testAccCloudSecurityGroupResourceConfigEmptyName,
			expectError: regexp.MustCompile("Invalid Attribute Value Length|attribute name string length must be between 1 and 100"),
		},
		"name_too_long": {
			configFunc:  testAccCloudSecurityGroupResourceConfigNameTooLong,
			expectError: regexp.MustCompile("Invalid Attribute Value Length|attribute name string length must be between 1 and 100"),
		},
		"invalid_business_impact": {
			configFunc:  testAccCloudSecurityGroupResourceConfigInvalidBusinessImpact,
			expectError: regexp.MustCompile("Invalid Attribute Value Match|value must be one of"),
		},
		"invalid_environment": {
			configFunc:  testAccCloudSecurityGroupResourceConfigInvalidEnvironment,
			expectError: regexp.MustCompile("Invalid Attribute Value Match|value must be one of"),
		},
		"invalid_owner_email": {
			configFunc:  testAccCloudSecurityGroupResourceConfigInvalidOwnerEmail,
			expectError: regexp.MustCompile("Invalid Attribute Value|must be a valid email address"),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			resource.ParallelTest(t, resource.TestCase{
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				PreCheck:                 func() { acctest.PreCheck(t) },
				Steps: []resource.TestStep{
					{
						Config:      tc.configFunc(rName),
						ExpectError: tc.expectError,
					},
				},
			})
		})
	}
}

func TestAccCloudSecurityGroupResource_AllBusinessImpacts(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_cloud_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudSecurityGroupResourceConfigBusinessImpact(rName, "high"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "business_impact", "high"),
				),
			},
			{
				Config: testAccCloudSecurityGroupResourceConfigBusinessImpact(rName, "moderate"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "business_impact", "moderate"),
				),
			},
			{
				Config: testAccCloudSecurityGroupResourceConfigBusinessImpact(rName, "low"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "business_impact", "low"),
				),
			},
		},
	})
}

func TestAccCloudSecurityGroupResource_AllEnvironments(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_cloud_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudSecurityGroupResourceConfigEnvironment(rName, "dev"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "environment", "dev"),
				),
			},
			{
				Config: testAccCloudSecurityGroupResourceConfigEnvironment(rName, "test"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "environment", "test"),
				),
			},
			{
				Config: testAccCloudSecurityGroupResourceConfigEnvironment(rName, "stage"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "environment", "stage"),
				),
			},
			{
				Config: testAccCloudSecurityGroupResourceConfigEnvironment(rName, "prod"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "environment", "prod"),
				),
			},
		},
	})
}

func TestAccCloudSecurityGroupResource_ComplexImages(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_cloud_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudSecurityGroupResourceConfigComplexImages(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "images.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "images.0.registry", "docker.io"),
					resource.TestCheckResourceAttr(resourceName, "images.0.repository", "library/nginx"),
					resource.TestCheckResourceAttr(resourceName, "images.1.registry", "quay.io"),
					resource.TestCheckResourceAttr(resourceName, "images.1.repository", "prometheus/prometheus"),
					resource.TestCheckResourceAttr(resourceName, "images.1.tag", "v2.40.0"),
					resource.TestCheckResourceAttr(resourceName, "images.2.registry", "ghcr.io"),
					resource.TestCheckResourceAttr(resourceName, "images.2.repository", "my-org/my-app"),
					resource.TestCheckResourceAttr(resourceName, "images.2.tag", "latest"),
				),
			},
			{
				Config: testAccCloudSecurityGroupResourceConfigImagesUpdated(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "images.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "images.0.registry", "docker.io"),
					resource.TestCheckResourceAttr(resourceName, "images.0.repository", "alpine"),
					resource.TestCheckResourceAttr(resourceName, "images.0.tag", "3.18"),
				),
			},
		},
	})
}

func TestAccCloudSecurityGroupResource_AllAccounts(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_cloud_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudSecurityGroupResourceConfigAllAccounts(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "All AWS accounts with filters"),
					resource.TestCheckResourceAttr(resourceName, "aws.filters.region.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "aws.filters.region.0", "us-east-1"),
					resource.TestCheckResourceAttr(resourceName, "aws.filters.region.1", "us-west-2"),
					resource.TestCheckResourceAttr(resourceName, "aws.filters.tags.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "aws.filters.tags.0", "Environment=Production"),
					resource.TestCheckResourceAttrSet(resourceName, "created_at"),
					resource.TestCheckResourceAttrSet(resourceName, "updated_at"),
					resource.TestCheckResourceAttrSet(resourceName, "created_by"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccCloudSecurityGroupResourceConfigAWS(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name            = %[1]q
  description     = "Test AWS cloud security group"
  business_impact = "high"
  business_unit   = "Engineering"
  environment     = "dev"
  owners          = ["test@example.com"]

  aws = {
    account_ids = ["123456789012"]
    filters = {
      region = ["us-east-1"]
      tags   = ["env=prod"]
    }
  }
}
`, rName)
}

func testAccCloudSecurityGroupResourceConfigAWSUpdated(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name            = %[1]q
  description     = "Updated AWS cloud security group"
  business_impact = "moderate"
  business_unit   = "Engineering"
  environment     = "prod"
  owners          = ["test@example.com", "admin@example.com"]

  aws = {
    account_ids = ["123456789012", "210987654321"]
    filters = {
      region = ["us-east-1", "us-west-2"]
      tags   = ["env=prod", "team=security"]
    }
  }
}
`, rName)
}

func testAccCloudSecurityGroupResourceConfigAzure(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name        = %[1]q
  description = "Test Azure cloud security group"

  azure = {
    account_ids = ["12345678-1234-1234-1234-123456789012"]
    filters = {
      region = ["eastus"]
      tags   = ["env=dev"]
    }
  }
}
`, rName)
}

func testAccCloudSecurityGroupResourceConfigGCP(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name        = %[1]q
  description = "Test GCP cloud security group"

  gcp = {
    account_ids = ["my-gcp-project"]
    filters = {
      region = ["us-central1"]
    }
  }
}
`, rName)
}

func testAccCloudSecurityGroupResourceConfigImages(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name        = %[1]q
  description = "Test container images group"

  images = [
    {
      registry   = "docker.io"
      repository = "nginx"
      tag        = "latest"
    },
    {
      registry   = "gcr.io"
      repository = "my-project/my-app"
      tag        = "v1.0.0"
    }
  ]
}
`, rName)
}

func testAccCloudSecurityGroupResourceConfigMultiCloud(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name        = %[1]q
  description = "Multi-cloud security group"

  aws = {
    account_ids = ["123456789012", "210987654321"]
    filters = {
      region = ["us-east-1"]
    }
  }

  azure = {
    account_ids = ["12345678-1234-1234-1234-123456789012"]
    filters = {
      region = ["eastus"]
    }
  }

  gcp = {
    account_ids = ["my-gcp-project"]
    filters = {
      region = ["us-central1"]
    }
  }
}
`, rName)
}

func testAccCloudSecurityGroupResourceConfigMinimal(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name = %[1]q

  aws = {
    account_ids = ["123456789012"]
  }
}
`, rName)
}

func testAccCloudSecurityGroupResourceConfigNoProviders(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name = %[1]q
}
`, rName)
}

func testAccCloudSecurityGroupResourceConfigBusinessImpact(rName, impact string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name            = %[1]q
  business_impact = %[2]q

  aws = {
    account_ids = ["123456789012"]
  }
}
`, rName, impact)
}

func testAccCloudSecurityGroupResourceConfigEnvironment(rName, env string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name        = %[1]q
  environment = %[2]q

  aws = {
    account_ids = ["123456789012"]
  }
}
`, rName, env)
}

func testAccCloudSecurityGroupResourceConfigComplexImages(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name = %[1]q

  images = [
    {
      registry   = "docker.io"
      repository = "library/nginx"
    },
    {
      registry   = "quay.io"
      repository = "prometheus/prometheus"
      tag        = "v2.40.0"
    },
    {
      registry   = "ghcr.io"
      repository = "my-org/my-app"
      tag        = "latest"
    }
  ]
}
`, rName)
}

func testAccCloudSecurityGroupResourceConfigImagesUpdated(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name = %[1]q

  images = [
    {
      registry   = "docker.io"
      repository = "alpine"
      tag        = "3.18"
    }
  ]
}
`, rName)
}

func testAccCloudSecurityGroupResourceConfigEmptyName(_ string) string {
	return acctest.ProviderConfig + `
resource "crowdstrike_cloud_group" "test" {
  name = ""

  aws = {
    account_ids = ["123456789012"]
  }
}
`
}

func testAccCloudSecurityGroupResourceConfigNameTooLong(_ string) string {
	longName := sdkacctest.RandString(101)
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name = %[1]q

  aws = {
    account_ids = ["123456789012"]
  }
}
`, longName)
}

func testAccCloudSecurityGroupResourceConfigInvalidBusinessImpact(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name            = %[1]q
  business_impact = "invalid"

  aws = {
    account_ids = ["123456789012"]
  }
}
`, rName)
}

func testAccCloudSecurityGroupResourceConfigInvalidEnvironment(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name        = %[1]q
  environment = "invalid"

  aws = {
    account_ids = ["123456789012"]
  }
}
`, rName)
}

func testAccCloudSecurityGroupResourceConfigInvalidOwnerEmail(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name   = %[1]q
  owners = ["not-an-email"]

  aws = {
    account_ids = ["123456789012"]
  }
}
`, rName)
}

func testAccCloudSecurityGroupResourceConfigAllAccounts(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name        = %[1]q
  description = "All AWS accounts with filters"

  aws = {
    filters = {
      region = ["us-east-1", "us-west-2"]
      tags   = ["Environment=Production"]
    }
  }
}
`, rName)
}
