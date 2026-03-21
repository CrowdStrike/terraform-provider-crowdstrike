package ioaexclusion_test

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

type ioaExclusionTestConfig struct {
	Name        string
	Description string
	PatternID   string
	PatternName string
	ClRegex     string
	IfnRegex    string
	Groups      []string
	Comment     string
}

func (c ioaExclusionTestConfig) String() string {
	var b strings.Builder

	b.WriteString(acctest.ProviderConfig)
	fmt.Fprintf(&b, `
resource "crowdstrike_ioa_exclusion" "test" {
  name        = %q
  description = %q
  pattern_id  = %q
`, c.Name, c.Description, c.PatternID)

	if c.PatternName != "" {
		fmt.Fprintf(&b, "  pattern_name = %q\n", c.PatternName)
	}

	fmt.Fprintf(&b, "  cl_regex    = %q\n", c.ClRegex)
	fmt.Fprintf(&b, "  ifn_regex   = %q\n", c.IfnRegex)

	groupValues := make([]string, 0, len(c.Groups))
	for _, group := range c.Groups {
		groupValues = append(groupValues, fmt.Sprintf("%q", group))
	}
	fmt.Fprintf(&b, "  groups      = [%s]\n", strings.Join(groupValues, ", "))

	if c.Comment != "" {
		fmt.Fprintf(&b, "  comment     = %q\n", c.Comment)
	}

	b.WriteString("}\n")

	return b.String()
}

func TestAccIOAExclusionResource_Basic(t *testing.T) {
	hostGroupID := os.Getenv(string(acctest.RequireHostGroupID))
	patternID := os.Getenv(string(acctest.RequireIOAPatternID))
	resourceName := "crowdstrike_ioa_exclusion.test"
	baseName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	initial := ioaExclusionTestConfig{
		Name:        baseName,
		Description: "Initial IOA exclusion",
		PatternID:   patternID,
		PatternName: "Initial IOA Pattern",
		ClRegex:     `.*--terraform-test-initial.*`,
		IfnRegex:    `.*terraform-test-initial\.exe`,
		Groups:      []string{hostGroupID},
		Comment:     "Created during acceptance testing",
	}

	updated := ioaExclusionTestConfig{
		Name:        baseName + "-updated",
		Description: "Updated IOA exclusion",
		PatternID:   patternID,
		PatternName: "Updated IOA Pattern",
		ClRegex:     `.*--terraform-test-updated.*`,
		IfnRegex:    `.*terraform-test-updated\.exe`,
		Groups:      []string{hostGroupID},
		Comment:     "Updated during acceptance testing",
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck: func() {
			acctest.PreCheck(t, acctest.RequireHostGroupID, acctest.RequireIOAPatternID)
		},
		Steps: []resource.TestStep{
			{
				Config: initial.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
					resource.TestCheckResourceAttr(resourceName, "name", initial.Name),
					resource.TestCheckResourceAttr(resourceName, "description", initial.Description),
					resource.TestCheckResourceAttr(resourceName, "pattern_id", initial.PatternID),
					resource.TestCheckResourceAttr(resourceName, "pattern_name", initial.PatternName),
					resource.TestCheckResourceAttr(resourceName, "cl_regex", initial.ClRegex),
					resource.TestCheckResourceAttr(resourceName, "ifn_regex", initial.IfnRegex),
					resource.TestCheckResourceAttr(resourceName, "groups.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "groups.*", hostGroupID),
					resource.TestCheckResourceAttr(resourceName, "comment", initial.Comment),
					resource.TestCheckResourceAttr(resourceName, "applied_globally", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "created_by"),
					resource.TestCheckResourceAttrSet(resourceName, "created_on"),
					resource.TestCheckResourceAttrSet(resourceName, "modified_by"),
					resource.TestCheckResourceAttrSet(resourceName, "last_modified"),
				),
			},
			{
				Config: updated.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
					resource.TestCheckResourceAttr(resourceName, "name", updated.Name),
					resource.TestCheckResourceAttr(resourceName, "description", updated.Description),
					resource.TestCheckResourceAttr(resourceName, "pattern_id", updated.PatternID),
					resource.TestCheckResourceAttr(resourceName, "pattern_name", updated.PatternName),
					resource.TestCheckResourceAttr(resourceName, "cl_regex", updated.ClRegex),
					resource.TestCheckResourceAttr(resourceName, "ifn_regex", updated.IfnRegex),
					resource.TestCheckResourceAttr(resourceName, "groups.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "groups.*", hostGroupID),
					resource.TestCheckResourceAttr(resourceName, "comment", updated.Comment),
					resource.TestCheckResourceAttr(resourceName, "applied_globally", "false"),
				),
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

func TestAccIOAExclusionResource_Validation(t *testing.T) {
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
  groups      = ["all", "0123456789abcdef"]
}
`, sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)),
			expectError: regexp.MustCompile(`groups cannot contain "all" with other host group IDs`),
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
