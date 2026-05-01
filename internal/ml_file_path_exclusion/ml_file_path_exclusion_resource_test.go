package mlfilepathexclusion_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccMLFilePathExclusionResource_basic(t *testing.T) {
	resourceName := "crowdstrike_ml_file_path_exclusion.test"
	hostGroupResourceName := "crowdstrike_host_group.test"
	pattern := fmt.Sprintf("/tmp/%s/*", acctest.RandomResourceName())
	hgName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccMLFilePathExclusionConfig_basic(pattern, hgName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("regexp_value"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("value_hash"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_modified"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("modified_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_on"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("pattern"), knownvalue.StringExact(pattern)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(1)),
					statecheck.CompareValueCollection(resourceName, []tfjsonpath.Path{tfjsonpath.New("host_groups")}, hostGroupResourceName, tfjsonpath.New("id"), compare.ValuesSame()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("exclude_detections"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("exclude_uploads"), knownvalue.Bool(false)),
				},
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

func TestAccMLFilePathExclusionResource_update(t *testing.T) {
	resourceName := "crowdstrike_ml_file_path_exclusion.test"
	hostGroupResourceName := "crowdstrike_host_group.test"
	pattern := fmt.Sprintf("/tmp/%s/*", acctest.RandomResourceName())
	updatedPattern := fmt.Sprintf("/tmp/%s/*", acctest.RandomResourceName())
	hgName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccMLFilePathExclusionConfig_basic(pattern, hgName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("regexp_value"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("value_hash"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_modified"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("modified_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_on"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("pattern"), knownvalue.StringExact(pattern)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(1)),
					statecheck.CompareValueCollection(resourceName, []tfjsonpath.Path{tfjsonpath.New("host_groups")}, hostGroupResourceName, tfjsonpath.New("id"), compare.ValuesSame()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("comment"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("exclude_detections"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("exclude_uploads"), knownvalue.Bool(false)),
				},
			},
			{
				Config: testAccMLFilePathExclusionConfig_updated(updatedPattern, hgName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("regexp_value"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("value_hash"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_modified"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("modified_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_on"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("pattern"), knownvalue.StringExact(updatedPattern)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(1)),
					statecheck.CompareValueCollection(resourceName, []tfjsonpath.Path{tfjsonpath.New("host_groups")}, hostGroupResourceName, tfjsonpath.New("id"), compare.ValuesSame()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("comment"), knownvalue.StringExact("updated via acceptance test")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("exclude_detections"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("exclude_uploads"), knownvalue.Bool(true)),
				},
			},
			{
				Config: testAccMLFilePathExclusionConfig_basic(pattern, hgName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("regexp_value"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("value_hash"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_modified"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("modified_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_on"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("pattern"), knownvalue.StringExact(pattern)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(1)),
					statecheck.CompareValueCollection(resourceName, []tfjsonpath.Path{tfjsonpath.New("host_groups")}, hostGroupResourceName, tfjsonpath.New("id"), compare.ValuesSame()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("comment"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("exclude_detections"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("exclude_uploads"), knownvalue.Bool(false)),
				},
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

func TestAccMLFilePathExclusionResource_appliedGlobally(t *testing.T) {
	resourceName := "crowdstrike_ml_file_path_exclusion.test"
	pattern := fmt.Sprintf("/tmp/%s/*", acctest.RandomResourceName())
	hgName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccMLFilePathExclusionConfig_appliedGlobally(pattern),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("pattern"), knownvalue.StringExact(pattern)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact("all"),
					})),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("exclude_detections"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("exclude_uploads"), knownvalue.Bool(false)),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			{
				Config: testAccMLFilePathExclusionConfig_basic(pattern, hgName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("pattern"), knownvalue.StringExact(pattern)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(false)),
				},
			},
		},
	})
}

func TestAccMLFilePathExclusionResource_invalidConfiguration(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccMLFilePathExclusionConfig_invalid(),
				ExpectError: regexp.MustCompile(`At least one of`),
				PlanOnly:    true,
			},
		},
	})
}

func testAccMLFilePathExclusionConfig_basic(pattern, hostGroupName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name        = %[2]q
  description = "ML exclusion acceptance test"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_ml_file_path_exclusion" "test" {
  pattern            = %[1]q
  host_groups        = [crowdstrike_host_group.test.id]
  exclude_detections = true
}
`, pattern, hostGroupName)
}

func testAccMLFilePathExclusionConfig_updated(pattern, hostGroupName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name        = %[2]q
  description = "ML exclusion acceptance test"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_ml_file_path_exclusion" "test" {
  pattern            = %[1]q
  host_groups        = [crowdstrike_host_group.test.id]
  exclude_detections = true
  exclude_uploads    = true
  comment            = "updated via acceptance test"
}
`, pattern, hostGroupName)
}

func testAccMLFilePathExclusionConfig_appliedGlobally(pattern string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ml_file_path_exclusion" "test" {
  pattern            = %[1]q
  host_groups        = ["all"]
  exclude_detections = true
}
`, pattern)
}

func testAccMLFilePathExclusionConfig_invalid() string {
	return acctest.ProviderConfig + `
resource "crowdstrike_ml_file_path_exclusion" "test" {
  pattern            = "/tmp/tf-acc-test-ml-invalid/*"
  host_groups        = ["all"]
  exclude_detections = false
  exclude_uploads    = false
}
`
}
