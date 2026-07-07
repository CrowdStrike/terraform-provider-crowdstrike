package ioaexclusion_test

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/ioa_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/testconfig"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
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

func TestAccIOAExclusionResource_basic(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_ioa_exclusion.test"
	patternID := requireIOAPatternID(t)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccIOAExclusionConfig_basic(rName, patternID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("pattern_id"), knownvalue.StringExact(patternID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("pattern_name"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cl_regex"), knownvalue.StringExact(`.*--tf-test-initial.*`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("ifn_regex"), knownvalue.StringExact(`.*tf-test-initial\.exe`)),
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
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
		},
	})
}

func TestAccIOAExclusionResource_update(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_ioa_exclusion.test"
	patternID := requireIOAPatternID(t)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccIOAExclusionConfig_basic(rName, patternID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("pattern_id"), knownvalue.StringExact(patternID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("pattern_name"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cl_regex"), knownvalue.StringExact(`.*--tf-test-initial.*`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("ifn_regex"), knownvalue.StringExact(`.*tf-test-initial\.exe`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("parent_cl_regex"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("parent_ifn_regex"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("grandparent_cl_regex"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("grandparent_ifn_regex"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("comment"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_on"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("modified_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_modified"), knownvalue.NotNull()),
				},
			},
			{
				Config: testAccIOAExclusionConfig_updated(fmt.Sprintf("%s-updated", rName), patternID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(fmt.Sprintf("%s-updated", rName))),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("pattern_id"), knownvalue.StringExact(patternID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("pattern_name"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cl_regex"), knownvalue.StringExact(`.*--tf-test-updated.*`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("ifn_regex"), knownvalue.StringExact(`.*tf-test-updated\.exe`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("parent_cl_regex"), knownvalue.StringExact(`.*--tf-parent-updated.*`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("parent_ifn_regex"), knownvalue.StringExact(`.*tf-parent-updated\.exe`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("grandparent_cl_regex"), knownvalue.StringExact(`.*--tf-grandparent-updated.*`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("grandparent_ifn_regex"), knownvalue.StringExact(`.*tf-grandparent-updated\.exe`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Updated IOA exclusion")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("comment"), knownvalue.StringExact("Updated during acceptance testing")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_on"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("modified_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_modified"), knownvalue.NotNull()),
				},
			},
			{
				Config: testAccIOAExclusionConfig_processTreeChanged(fmt.Sprintf("%s-updated", rName), patternID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("parent_cl_regex"), knownvalue.StringExact(`.*--tf-parent-changed.*`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("parent_ifn_regex"), knownvalue.StringExact(`.*tf-parent-changed\.exe`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("grandparent_cl_regex"), knownvalue.StringExact(`.*--tf-grandparent-changed.*`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("grandparent_ifn_regex"), knownvalue.StringExact(`.*tf-grandparent-changed\.exe`)),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			{
				Config: testAccIOAExclusionConfig_basic(rName, patternID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("pattern_id"), knownvalue.StringExact(patternID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("pattern_name"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cl_regex"), knownvalue.StringExact(`.*--tf-test-initial.*`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("ifn_regex"), knownvalue.StringExact(`.*tf-test-initial\.exe`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("parent_cl_regex"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("parent_ifn_regex"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("grandparent_cl_regex"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("grandparent_ifn_regex"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("comment"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_on"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("modified_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_modified"), knownvalue.NotNull()),
				},
			},
		},
	})
}

func TestAccIOAExclusionResource_appliedGlobally(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_ioa_exclusion.test"
	patternID := requireIOAPatternID(t)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccIOAExclusionConfig_appliedGlobally(rName, patternID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("pattern_id"), knownvalue.StringExact(patternID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact("all"),
					})),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(true)),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			{
				Config: testAccIOAExclusionConfig_basic(rName, patternID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(false)),
				},
			},
		},
	})
}

func TestAccIOAExclusionResource_comment(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_ioa_exclusion.test"
	patternID := requireIOAPatternID(t)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccIOAExclusionConfig_comment(rName, patternID, "created via acceptance test"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("comment"), knownvalue.StringExact("created via acceptance test")),
				},
			},
			{
				Config: testAccIOAExclusionConfig_comment(rName, patternID, "updated via acceptance test"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("comment"), knownvalue.StringExact("updated via acceptance test")),
				},
			},
			{
				Config: testAccIOAExclusionConfig_basic(rName, patternID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("comment"), knownvalue.Null()),
				},
			},
		},
	})
}

func TestAccIOAExclusionResource_v1Compatibility(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_ioa_exclusion.test"
	patternID := requireIOAPatternID(t)
	var exclusionID string

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(t)
			exclusionID = createV1IOAExclusion(t, rName, patternID)
			t.Cleanup(func() { deleteV2IOAExclusion(t, exclusionID) })
		},
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:             testAccIOAExclusionConfig_v1Compatibility(rName, patternID, false),
				ResourceName:       resourceName,
				ImportState:        true,
				ImportStatePersist: true,
				ImportStateIdFunc: func(*terraform.State) (string, error) {
					return exclusionID, nil
				},
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					if len(states) != 1 {
						return fmt.Errorf("expected one imported IOA exclusion, got %d", len(states))
					}
					if states[0].ID != exclusionID {
						return fmt.Errorf("expected imported IOA exclusion ID %q, got %q", exclusionID, states[0].ID)
					}
					return nil
				},
			},
			{
				Config:             testAccIOAExclusionConfig_v1Compatibility(rName, patternID, false),
				PlanOnly:           true,
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
			{
				Config: testAccIOAExclusionConfig_v1Compatibility(rName, patternID, true),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.StringExact(exclusionID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("parent_cl_regex"), knownvalue.StringExact(`.*--tf-parent-v2.*`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("parent_ifn_regex"), knownvalue.StringExact(`.*tf-parent-v2\.exe`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("grandparent_cl_regex"), knownvalue.StringExact(`.*--tf-grandparent-v2.*`)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("grandparent_ifn_regex"), knownvalue.StringExact(`.*tf-grandparent-v2\.exe`)),
				},
			},
		},
	})
}

func TestAccIOAExclusionResource_validation(t *testing.T) {
	testCases := []struct {
		name        string
		config      string
		expectError *regexp.Regexp
	}{
		{
			name: "all_with_other_group",
			config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_exclusion" "test" {
  name        = %q
  description = "Validation test"
  pattern_id  = "12345"
  cl_regex    = ".*"
  ifn_regex   = ".*"
  host_groups = ["all", "0123456789abcdef"]
}
`, acctest.RandomResourceName()),
			expectError: regexp.MustCompile(`host_groups cannot contain "all" with other host group IDs`),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resource.ParallelTest(t, resource.TestCase{
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				PreCheck:                 func() { acctest.PreCheck(t) },
				Steps: []resource.TestStep{
					{
						Config:      tc.config,
						ExpectError: tc.expectError,
					},
				},
			})
		})
	}
}

func testAccIOAExclusionConfig_basic(name, patternID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name        = "%[1]s-hg"
  description = "%[1]s-hg"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_ioa_exclusion" "test" {
  name        = %[1]q
  pattern_id  = %[2]q
  cl_regex    = ".*--tf-test-initial.*"
  ifn_regex   = ".*tf-test-initial\\.exe"
  host_groups = [crowdstrike_host_group.test.id]
}`, name, patternID)
}

func testAccIOAExclusionConfig_appliedGlobally(name, patternID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_ioa_exclusion" "test" {
  name        = %[1]q
  pattern_id  = %[2]q
  cl_regex    = ".*--tf-test-initial.*"
  ifn_regex   = ".*tf-test-initial\\.exe"
  host_groups = ["all"]
}`, name, patternID)
}

func testAccIOAExclusionConfig_comment(name, patternID, comment string) string {
	return fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name        = "%[1]s-hg"
  description = "%[1]s-hg"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_ioa_exclusion" "test" {
  name        = %[1]q
  pattern_id  = %[2]q
  cl_regex    = ".*--tf-test-initial.*"
  ifn_regex   = ".*tf-test-initial\\.exe"
  host_groups = [crowdstrike_host_group.test.id]
  comment     = %[3]q
}`, name, patternID, comment)
}

func testAccIOAExclusionConfig_updated(name, patternID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name        = "%[1]s-hg"
  description = "%[1]s-hg"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_ioa_exclusion" "test" {
  name        = %[1]q
  description = "Updated IOA exclusion"
  pattern_id  = %[2]q
  cl_regex    = ".*--tf-test-updated.*"
  ifn_regex   = ".*tf-test-updated\\.exe"

  parent_cl_regex       = ".*--tf-parent-updated.*"
  parent_ifn_regex      = ".*tf-parent-updated\\.exe"
  grandparent_cl_regex  = ".*--tf-grandparent-updated.*"
  grandparent_ifn_regex = ".*tf-grandparent-updated\\.exe"

  host_groups = [crowdstrike_host_group.test.id]
  comment     = "Updated during acceptance testing"
}`, name, patternID)
}

func testAccIOAExclusionConfig_processTreeChanged(name, patternID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name        = "%[1]s-hg"
  description = "%[1]s-hg"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_ioa_exclusion" "test" {
  name        = %[1]q
  description = "Updated IOA exclusion"
  pattern_id  = %[2]q
  cl_regex    = ".*--tf-test-updated.*"
  ifn_regex   = ".*tf-test-updated\\.exe"

  parent_cl_regex       = ".*--tf-parent-changed.*"
  parent_ifn_regex      = ".*tf-parent-changed\\.exe"
  grandparent_cl_regex  = ".*--tf-grandparent-changed.*"
  grandparent_ifn_regex = ".*tf-grandparent-changed\\.exe"

  host_groups = [crowdstrike_host_group.test.id]
  comment     = "Updated during acceptance testing"
}`, name, patternID)
}

func testAccIOAExclusionConfig_v1Compatibility(name, patternID string, includeProcessTree bool) string {
	processTree := ""
	if includeProcessTree {
		processTree = `
  parent_cl_regex       = ".*--tf-parent-v2.*"
  parent_ifn_regex      = ".*tf-parent-v2\\.exe"
  grandparent_cl_regex  = ".*--tf-grandparent-v2.*"
  grandparent_ifn_regex = ".*tf-grandparent-v2\\.exe"`
	}

	return fmt.Sprintf(`
resource "crowdstrike_ioa_exclusion" "test" {
  name        = %[1]q
  description = "Created through the V1 endpoint"
  pattern_id  = %[2]q
  cl_regex    = ".*--tf-v1-compatibility.*"
  ifn_regex   = ".*tf-v1-compatibility\\.exe"
  host_groups = ["all"]
  comment     = "created by V1 compatibility test"%[3]s
}`, name, patternID, processTree)
}

func createV1IOAExclusion(t *testing.T, name, patternID string) string {
	t.Helper()

	params := ioa_exclusions.NewCreateIOAExclusionsV1ParamsWithContext(t.Context())
	params.SetBody(&models.IoaExclusionsIoaExclusionCreateReqV1{
		Name:        utils.Addr(name),
		Description: utils.Addr("Created through the V1 endpoint"),
		PatternID:   utils.Addr(patternID),
		ClRegex:     utils.Addr(".*--tf-v1-compatibility.*"),
		IfnRegex:    utils.Addr(".*tf-v1-compatibility\\.exe"),
		Groups:      []string{"all"},
		Comment:     "created by V1 compatibility test",
	})

	resp, err := testconfig.GetTestClient().IoaExclusions.CreateIOAExclusionsV1(params)
	if err != nil {
		t.Fatalf("failed to create V1 IOA exclusion: %v", err)
	}
	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) != 1 || resp.Payload.Resources[0] == nil || resp.Payload.Resources[0].ID == nil {
		t.Fatalf("V1 create returned an unexpected response: %#v", resp)
	}

	return *resp.Payload.Resources[0].ID
}

func deleteV2IOAExclusion(t *testing.T, id string) {
	t.Helper()
	if id == "" || testconfig.GetTestClient() == nil {
		return
	}

	params := ioa_exclusions.NewSsIoaExclusionsDeleteV2ParamsWithContext(t.Context())
	params.SetIds([]string{id})
	params.SetComment(utils.Addr("deleted by V1 compatibility test cleanup"))
	if _, err := testconfig.GetTestClient().IoaExclusions.SsIoaExclusionsDeleteV2(params); err != nil {
		t.Logf("failed to clean up V1 compatibility IOA exclusion %s: %v", id, err)
	}
}
