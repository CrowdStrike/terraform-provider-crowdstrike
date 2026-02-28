package mlexclusion_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccMLExclusionResource_Basic(t *testing.T) {
	resourceName := "crowdstrike_ml_exclusion.test"
	pattern := fmt.Sprintf("/tmp/%s/*", acctest.RandomResourceName())
	updatedPattern := fmt.Sprintf("/tmp/%s-updated/*", acctest.RandomResourceName())
	uploadsOnlyPattern := fmt.Sprintf("/tmp/%s-uploads/*", acctest.RandomResourceName())

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccMLExclusionResourceConfigBasic(pattern),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "pattern", pattern),
					resource.TestCheckResourceAttr(resourceName, "exclude_detections", "true"),
					resource.TestCheckResourceAttr(resourceName, "exclude_uploads", "false"),
					resource.TestCheckResourceAttr(resourceName, "applied_globally", "true"),
					resource.TestCheckTypeSetElemAttr(resourceName, "host_groups.*", "all"),
					resource.TestCheckResourceAttrSet(resourceName, "regexp_value"),
					resource.TestCheckResourceAttrSet(resourceName, "value_hash"),
					resource.TestCheckResourceAttrSet(resourceName, "created_by"),
					resource.TestCheckResourceAttrSet(resourceName, "created_on"),
					resource.TestCheckResourceAttrSet(resourceName, "modified_by"),
					resource.TestCheckResourceAttrSet(resourceName, "last_modified"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
				),
			},
			{
				Config: testAccMLExclusionResourceConfigUpdated(updatedPattern),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "pattern", updatedPattern),
					resource.TestCheckResourceAttr(resourceName, "exclude_detections", "true"),
					resource.TestCheckResourceAttr(resourceName, "exclude_uploads", "true"),
					resource.TestCheckResourceAttr(resourceName, "applied_globally", "true"),
					resource.TestCheckTypeSetElemAttr(resourceName, "host_groups.*", "all"),
					resource.TestCheckResourceAttrSet(resourceName, "regexp_value"),
					resource.TestCheckResourceAttrSet(resourceName, "value_hash"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
				),
			},
			{
				Config: testAccMLExclusionResourceConfigUploadsOnly(uploadsOnlyPattern),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "pattern", uploadsOnlyPattern),
					resource.TestCheckResourceAttr(resourceName, "exclude_detections", "false"),
					resource.TestCheckResourceAttr(resourceName, "exclude_uploads", "true"),
					resource.TestCheckResourceAttr(resourceName, "applied_globally", "true"),
					resource.TestCheckTypeSetElemAttr(resourceName, "host_groups.*", "all"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
		},
	})
}

func TestAccMLExclusionResource_SpecificHostGroups(t *testing.T) {
	resourceName := "crowdstrike_ml_exclusion.test"
	pattern := fmt.Sprintf("/tmp/%s-host-group/*", acctest.RandomResourceName())
	hostGroupName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccMLExclusionResourceConfigSpecificHostGroup(pattern, hostGroupName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "pattern", pattern),
					resource.TestCheckResourceAttr(resourceName, "exclude_detections", "false"),
					resource.TestCheckResourceAttr(resourceName, "exclude_uploads", "true"),
					resource.TestCheckResourceAttr(resourceName, "applied_globally", "false"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "1"),
				),
			},
		},
	})
}

func TestAccMLExclusionResource_InvalidConfiguration(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccMLExclusionResourceConfigInvalid(),
				ExpectError: regexp.MustCompile("At least one of .*exclude_detections.*exclude_uploads.*must be set to true"),
				PlanOnly:    true,
			},
		},
	})
}

func testAccMLExclusionResourceConfigBasic(pattern string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ml_exclusion" "test" {
  pattern            = %[1]q
  host_groups        = ["all"]
  exclude_detections = true
}
`, pattern)
}

func testAccMLExclusionResourceConfigUpdated(pattern string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ml_exclusion" "test" {
  pattern            = %[1]q
  host_groups        = ["all"]
  exclude_detections = true
  exclude_uploads    = true
}
`, pattern)
}

func testAccMLExclusionResourceConfigUploadsOnly(pattern string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ml_exclusion" "test" {
  pattern         = %[1]q
  host_groups     = ["all"]
  exclude_uploads = true
}
`, pattern)
}

func testAccMLExclusionResourceConfigSpecificHostGroup(pattern, hostGroupName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name        = %[2]q
  description = "ML exclusion host group acceptance test"
  type        = "static"
  hostnames   = ["tf-acc-test-ml-host-1"]
}

resource "crowdstrike_ml_exclusion" "test" {
  pattern         = %[1]q
  host_groups     = [crowdstrike_host_group.test.id]
  exclude_uploads = true
}
`, pattern, hostGroupName)
}

func testAccMLExclusionResourceConfigInvalid() string {
	return acctest.ProviderConfig + `
resource "crowdstrike_ml_exclusion" "test" {
  pattern            = "/tmp/tf-acc-test-ml-invalid/*"
  host_groups        = ["all"]
  exclude_detections = false
  exclude_uploads    = false
}
`
}
