package selfserviceioaexclusion_test

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

func requireIOAPatternID(t *testing.T) string {
	t.Helper()

	patternID := os.Getenv(string(acctest.RequireIOAPatternID))
	if patternID == "" {
		t.Skip("Set IOA_PATTERN_ID to run this test")
	}

	return patternID
}

func TestAccSelfServiceIOAExclusionResource_basic(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_self_service_ioa_exclusion.test"
	patternID := requireIOAPatternID(t)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSelfServiceIOAExclusionConfig_basic(rName, patternID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("pattern_id"), knownvalue.StringExact(patternID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cl_regex"), knownvalue.StringExact(`.*--tf-test-initial.*`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("ifn_regex"), knownvalue.StringExact(`.*tf-test-initial\.exe`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("parent_cl_regex"), knownvalue.StringExact(`.*--tf-parent-initial.*`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("parent_ifn_regex"), knownvalue.StringExact(`.*tf-parent-initial\.exe`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("grandparent_cl_regex"), knownvalue.StringExact(`.*--tf-grandparent-initial.*`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("grandparent_ifn_regex"), knownvalue.StringExact(`.*tf-grandparent-initial\.exe`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_on"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("modified_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_modified"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated", "comment"},
			},
		},
	})
}

func TestAccSelfServiceIOAExclusionResource_update(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_self_service_ioa_exclusion.test"
	patternID := requireIOAPatternID(t)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSelfServiceIOAExclusionConfig_basic(rName, patternID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cl_regex"), knownvalue.StringExact(`.*--tf-test-initial.*`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("parent_cl_regex"), knownvalue.StringExact(`.*--tf-parent-initial.*`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("grandparent_cl_regex"), knownvalue.StringExact(`.*--tf-grandparent-initial.*`)),
				},
			},
			{
				Config: testAccSelfServiceIOAExclusionConfig_updated(fmt.Sprintf("%s-updated", rName), patternID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(fmt.Sprintf("%s-updated", rName))),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Updated self-service IOA exclusion")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("pattern_id"), knownvalue.StringExact(patternID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cl_regex"), knownvalue.StringExact(`.*--tf-test-updated.*`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("ifn_regex"), knownvalue.StringExact(`.*tf-test-updated\.exe`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("parent_cl_regex"), knownvalue.StringExact(`.*--tf-parent-updated.*`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("parent_ifn_regex"), knownvalue.StringExact(`.*tf-parent-updated\.exe`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("grandparent_cl_regex"), knownvalue.StringExact(`.*--tf-grandparent-updated.*`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("grandparent_ifn_regex"), knownvalue.StringExact(`.*tf-grandparent-updated\.exe`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("comment"), knownvalue.StringExact("Updated during acceptance testing")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(false)),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated", "comment"},
			},
		},
	})
}

func TestAccSelfServiceIOAExclusionResource_omittedHostGroups(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_self_service_ioa_exclusion.test"
	patternID := requireIOAPatternID(t)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSelfServiceIOAExclusionConfig_omittedHostGroups(rName, patternID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("pattern_id"), knownvalue.StringExact(patternID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cl_regex"), knownvalue.StringExact(`.*--tf-test-omitted-host-groups.*`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("ifn_regex"), knownvalue.StringExact(`.*tf-test-omitted-host-groups\.exe`)),
				},
			},
		},
	})
}

func testAccSelfServiceIOAExclusionConfig_basic(name, patternID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name        = "%[1]s-hg"
  description = "%[1]s-hg"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_self_service_ioa_exclusion" "test" {
  name                       = %[1]q
  pattern_id                 = %[2]q
  cl_regex                   = ".*--tf-test-initial.*"
  ifn_regex                  = ".*tf-test-initial\\.exe"
  parent_cl_regex            = ".*--tf-parent-initial.*"
  parent_ifn_regex           = ".*tf-parent-initial\\.exe"
  grandparent_cl_regex       = ".*--tf-grandparent-initial.*"
  grandparent_ifn_regex      = ".*tf-grandparent-initial\\.exe"
  host_groups                = [crowdstrike_host_group.test.id]
}`, name, patternID)
}

func testAccSelfServiceIOAExclusionConfig_updated(name, patternID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name        = "%[1]s-hg"
  description = "%[1]s-hg"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_self_service_ioa_exclusion" "test" {
  name                       = %[1]q
  description                = "Updated self-service IOA exclusion"
  pattern_id                 = %[2]q
  cl_regex                   = ".*--tf-test-updated.*"
  ifn_regex                  = ".*tf-test-updated\\.exe"
  parent_cl_regex            = ".*--tf-parent-updated.*"
  parent_ifn_regex           = ".*tf-parent-updated\\.exe"
  grandparent_cl_regex       = ".*--tf-grandparent-updated.*"
  grandparent_ifn_regex      = ".*tf-grandparent-updated\\.exe"
  host_groups                = [crowdstrike_host_group.test.id]
  comment                    = "Updated during acceptance testing"
}`, name, patternID)
}

func testAccSelfServiceIOAExclusionConfig_omittedHostGroups(name, patternID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_self_service_ioa_exclusion" "test" {
  name        = %[1]q
  pattern_id  = %[2]q
  cl_regex    = ".*--tf-test-omitted-host-groups.*"
  ifn_regex   = ".*tf-test-omitted-host-groups\\.exe"
}`, name, patternID)
}
