package cloudgroup_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccCloudSecurityGroupResource_Basic(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_cloud_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudSecurityGroupResourceConfigBasic(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckNoResourceAttr(resourceName, "description"),
					resource.TestCheckNoResourceAttr(resourceName, "business_impact"),
					resource.TestCheckNoResourceAttr(resourceName, "business_unit"),
					resource.TestCheckNoResourceAttr(resourceName, "environment"),
					resource.TestCheckNoResourceAttr(resourceName, "owners"),
					resource.TestCheckNoResourceAttr(resourceName, "aws"),
					resource.TestCheckNoResourceAttr(resourceName, "azure"),
					resource.TestCheckNoResourceAttr(resourceName, "gcp"),
					resource.TestCheckNoResourceAttr(resourceName, "images"),
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
func TestAccCloudSecurityGroupResource_CloudProviders(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_cloud_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudSecurityGroupResourceConfigCloudProvidersInitial(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Multi-cloud group with all providers"),
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
					resource.TestCheckResourceAttr(resourceName, "azure.account_ids.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "azure.account_ids.0", "12345678-1234-1234-1234-123456789012"),
					resource.TestCheckResourceAttr(resourceName, "azure.filters.region.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "azure.filters.region.0", "eastus"),
					resource.TestCheckResourceAttr(resourceName, "azure.filters.tags.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "azure.filters.tags.0", "env=dev"),
					resource.TestCheckResourceAttr(resourceName, "gcp.account_ids.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "gcp.account_ids.0", "my-gcp-project"),
					resource.TestCheckResourceAttr(resourceName, "gcp.filters.region.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "gcp.filters.region.0", "us-central1"),
					resource.TestCheckResourceAttrSet(resourceName, "created_at"),
					resource.TestCheckResourceAttrSet(resourceName, "updated_at"),
					resource.TestCheckResourceAttrSet(resourceName, "created_by"),
				),
			},
			{
				Config: testAccCloudSecurityGroupResourceConfigCloudProvidersUpdated(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Updated multi-cloud group"),
					resource.TestCheckResourceAttr(resourceName, "business_impact", "moderate"),
					resource.TestCheckResourceAttr(resourceName, "owners.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "owners.0", "test@example.com"),
					resource.TestCheckResourceAttr(resourceName, "owners.1", "admin@example.com"),
					resource.TestCheckResourceAttr(resourceName, "aws.account_ids.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "aws.account_ids.0", "123456789012"),
					resource.TestCheckResourceAttr(resourceName, "aws.account_ids.1", "210987654321"),
					resource.TestCheckResourceAttr(resourceName, "aws.filters.region.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "aws.filters.region.0", "us-east-1"),
					resource.TestCheckResourceAttr(resourceName, "aws.filters.region.1", "us-west-2"),
					resource.TestCheckResourceAttr(resourceName, "aws.filters.tags.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "aws.filters.tags.0", "env=prod"),
					resource.TestCheckResourceAttr(resourceName, "aws.filters.tags.1", "team=security"),
					resource.TestCheckResourceAttr(resourceName, "azure.account_ids.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "azure.account_ids.0", "12345678-1234-1234-1234-123456789012"),
					resource.TestCheckResourceAttr(resourceName, "azure.account_ids.1", "87654321-4321-4321-4321-210987654321"),
					resource.TestCheckResourceAttr(resourceName, "azure.filters.region.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "azure.filters.region.0", "eastus"),
					resource.TestCheckResourceAttr(resourceName, "azure.filters.region.1", "westus"),
					resource.TestCheckResourceAttr(resourceName, "gcp.account_ids.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "gcp.account_ids.0", "my-gcp-project"),
					resource.TestCheckResourceAttr(resourceName, "gcp.account_ids.1", "my-second-gcp-project"),
					resource.TestCheckResourceAttr(resourceName, "gcp.filters.region.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "gcp.filters.region.0", "us-central1"),
					resource.TestCheckResourceAttr(resourceName, "gcp.filters.region.1", "us-east1"),
					resource.TestCheckResourceAttrSet(resourceName, "created_at"),
					resource.TestCheckResourceAttrSet(resourceName, "updated_at"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccCloudSecurityGroupResourceConfigBasic(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckNoResourceAttr(resourceName, "description"),
					resource.TestCheckNoResourceAttr(resourceName, "business_impact"),
					resource.TestCheckNoResourceAttr(resourceName, "business_unit"),
					resource.TestCheckNoResourceAttr(resourceName, "environment"),
					resource.TestCheckNoResourceAttr(resourceName, "owners"),
					resource.TestCheckNoResourceAttr(resourceName, "aws"),
					resource.TestCheckNoResourceAttr(resourceName, "azure"),
					resource.TestCheckNoResourceAttr(resourceName, "gcp"),
					resource.TestCheckNoResourceAttr(resourceName, "images"),
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
				Config: testAccCloudSecurityGroupResourceConfigImagesUpdated(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Updated container images group"),
					resource.TestCheckResourceAttr(resourceName, "images.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "images.0.registry", "docker.io"),
					resource.TestCheckResourceAttr(resourceName, "images.0.repository", "alpine"),
					resource.TestCheckResourceAttr(resourceName, "images.0.tag", "3.18"),
					resource.TestCheckResourceAttr(resourceName, "images.1.registry", "quay.io"),
					resource.TestCheckResourceAttr(resourceName, "images.1.repository", "prometheus/prometheus"),
					resource.TestCheckResourceAttr(resourceName, "images.1.tag", "v2.40.0"),
					resource.TestCheckResourceAttr(resourceName, "images.2.registry", "ghcr.io"),
					resource.TestCheckResourceAttr(resourceName, "images.2.repository", "my-org/my-app"),
					resource.TestCheckResourceAttr(resourceName, "images.2.tag", "latest"),
					resource.TestCheckResourceAttrSet(resourceName, "created_at"),
					resource.TestCheckResourceAttrSet(resourceName, "updated_at"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccCloudSecurityGroupResourceConfigBasic(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckNoResourceAttr(resourceName, "images"),
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
					resource.TestCheckResourceAttr(resourceName, "aws.account_ids.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "azure.account_ids.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "gcp.account_ids.#", "0"),
					resource.TestCheckNoResourceAttr(resourceName, "images"),
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

func TestAccCloudSecurityGroupResource_BusinessImpact(t *testing.T) {
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
			{
				Config: testAccCloudSecurityGroupResourceConfigBusinessImpact(rName, ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr(resourceName, "business_impact"),
				),
			},
		},
	})
}

func TestAccCloudSecurityGroupResource_Environment(t *testing.T) {
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
			{
				Config: testAccCloudSecurityGroupResourceConfigEnvironment(rName, ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr(resourceName, "environment"),
				),
			},
		},
	})
}

func TestAccCloudSecurityGroupResource_MultiCloudToEmpty(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_cloud_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudSecurityGroupResourceConfigMultiCloudFull(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Multi-cloud with all providers"),
					resource.TestCheckResourceAttr(resourceName, "aws.account_ids.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "aws.account_ids.0", "123456789012"),
					resource.TestCheckResourceAttr(resourceName, "aws.account_ids.1", "210987654321"),
					resource.TestCheckResourceAttr(resourceName, "aws.filters.region.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "aws.filters.region.0", "us-east-1"),
					resource.TestCheckResourceAttr(resourceName, "aws.filters.region.1", "us-west-2"),
					resource.TestCheckResourceAttr(resourceName, "aws.filters.tags.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "aws.filters.tags.0", "Environment=Production"),
					resource.TestCheckResourceAttr(resourceName, "azure.account_ids.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "azure.account_ids.0", "12345678-1234-1234-1234-123456789012"),
					resource.TestCheckResourceAttr(resourceName, "azure.filters.region.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "azure.filters.region.0", "eastus"),
					resource.TestCheckResourceAttr(resourceName, "azure.filters.tags.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "azure.filters.tags.0", "Team=Engineering"),
					resource.TestCheckResourceAttr(resourceName, "gcp.account_ids.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "gcp.account_ids.0", "my-gcp-project"),
					resource.TestCheckResourceAttr(resourceName, "gcp.filters.region.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "gcp.filters.region.0", "us-central1"),
					resource.TestCheckResourceAttrSet(resourceName, "created_at"),
					resource.TestCheckResourceAttrSet(resourceName, "updated_at"),
				),
			},
			{
				Config: testAccCloudSecurityGroupResourceConfigMultiCloudEmpty(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Multi-cloud with all providers"),
					resource.TestCheckResourceAttr(resourceName, "aws.account_ids.#", "0"),
					resource.TestCheckNoResourceAttr(resourceName, "aws.filters.region"),
					resource.TestCheckNoResourceAttr(resourceName, "aws.filters.tags"),
					resource.TestCheckResourceAttr(resourceName, "azure.account_ids.#", "0"),
					resource.TestCheckNoResourceAttr(resourceName, "azure.filters.region"),
					resource.TestCheckNoResourceAttr(resourceName, "azure.filters.tags"),
					resource.TestCheckResourceAttr(resourceName, "gcp.account_ids.#", "0"),
					resource.TestCheckNoResourceAttr(resourceName, "gcp.filters.region"),
				),
			},
			{
				Config: testAccCloudSecurityGroupResourceConfigBasic(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckNoResourceAttr(resourceName, "description"),
					resource.TestCheckNoResourceAttr(resourceName, "business_impact"),
					resource.TestCheckNoResourceAttr(resourceName, "business_unit"),
					resource.TestCheckNoResourceAttr(resourceName, "environment"),
					resource.TestCheckNoResourceAttr(resourceName, "owners"),
					resource.TestCheckNoResourceAttr(resourceName, "aws"),
					resource.TestCheckNoResourceAttr(resourceName, "azure"),
					resource.TestCheckNoResourceAttr(resourceName, "gcp"),
					resource.TestCheckNoResourceAttr(resourceName, "images"),
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

func testAccCloudSecurityGroupResourceConfigBasic(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name = %[1]q
}
`, rName)
}

func testAccCloudSecurityGroupResourceConfigNoProviders(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name = %[1]q

  aws = {}

  azure = {}

  gcp = {}
}
`, rName)
}

func testAccCloudSecurityGroupResourceConfigBusinessImpact(rName, impact string) string {
	impactLine := ""
	if impact != "" {
		impactLine = fmt.Sprintf("  business_impact = %q\n", impact)
	}
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name = %[1]q
%[2]s
  aws = {
    account_ids = ["123456789012"]
  }
}
`, rName, impactLine)
}

func testAccCloudSecurityGroupResourceConfigEnvironment(rName, env string) string {
	envLine := ""
	if env != "" {
		envLine = fmt.Sprintf("  environment = %q\n", env)
	}
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name = %[1]q
%[2]s
  aws = {
    account_ids = ["123456789012"]
  }
}
`, rName, envLine)
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

func testAccCloudSecurityGroupResourceConfigMultiCloudFull(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name        = %[1]q
  description = "Multi-cloud with all providers"

  aws = {
    account_ids = ["123456789012", "210987654321"]
    filters = {
      region = ["us-east-1", "us-west-2"]
      tags   = ["Environment=Production"]
    }
  }

  azure = {
    account_ids = ["12345678-1234-1234-1234-123456789012"]
    filters = {
      region = ["eastus"]
      tags   = ["Team=Engineering"]
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

func testAccCloudSecurityGroupResourceConfigMultiCloudEmpty(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name        = %[1]q
  description = "Multi-cloud with all providers"

  aws = {}

  azure = {}

  gcp = {}
}
`, rName)
}

func testAccCloudSecurityGroupResourceConfigCloudProvidersInitial(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name            = %[1]q
  description     = "Multi-cloud group with all providers"
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

  azure = {
    account_ids = ["12345678-1234-1234-1234-123456789012"]
    filters = {
      region = ["eastus"]
      tags   = ["env=dev"]
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

func testAccCloudSecurityGroupResourceConfigCloudProvidersUpdated(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name            = %[1]q
  description     = "Updated multi-cloud group"
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

  azure = {
    account_ids = ["12345678-1234-1234-1234-123456789012", "87654321-4321-4321-4321-210987654321"]
    filters = {
      region = ["eastus", "westus"]
    }
  }

  gcp = {
    account_ids = ["my-gcp-project", "my-second-gcp-project"]
    filters = {
      region = ["us-central1", "us-east1"]
    }
  }
}
`, rName)
}

func testAccCloudSecurityGroupResourceConfigImagesUpdated(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_group" "test" {
  name        = %[1]q
  description = "Updated container images group"

  images = [
    {
      registry   = "docker.io"
      repository = "alpine"
      tag        = "3.18"
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
