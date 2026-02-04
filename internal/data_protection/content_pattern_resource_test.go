package dataprotection_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccDataProtectionContentPatternResource_Basic(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "crowdstrike_data_protection_content_pattern.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccDataProtectionContentPatternBasic(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "SSN pattern"),
					resource.TestCheckResourceAttr(resourceName, "regex", "\\b\\d{3}-\\d{2}-\\d{4}\\b"),
					resource.TestCheckResourceAttr(resourceName, "min_match_threshold", "1"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
				),
			},
			{
				Config: testAccDataProtectionContentPatternUpdated(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName+"-updated"),
					resource.TestCheckResourceAttr(resourceName, "description", "Updated email pattern"),
					resource.TestCheckResourceAttr(resourceName, "regex", "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b"),
					resource.TestCheckResourceAttr(resourceName, "min_match_threshold", "2"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
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

func TestAccDataProtectionContentPatternResource_InvalidRegex(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccDataProtectionContentPatternInvalidRegex(),
				ExpectError: regexp.MustCompile("Invalid Regular Expression"),
				PlanOnly:    true,
			},
		},
	})
}

func testAccDataProtectionContentPatternBasic(name string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_data_protection_content_pattern" "test" {
  name                = %[1]q
  description         = "SSN pattern"
  regex               = "\\b\\d{3}-\\d{2}-\\d{4}\\b"
  min_match_threshold = 1
}
`, name)
}

func testAccDataProtectionContentPatternUpdated(name string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_data_protection_content_pattern" "test" {
  name                = "%s-updated"
  description         = "Updated email pattern"
  regex               = "\\b[A-Za-z0-9._%%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b"
  min_match_threshold = 2
}
`, name)
}

func testAccDataProtectionContentPatternInvalidRegex() string {
	return acctest.ProviderConfig + `
resource "crowdstrike_data_protection_content_pattern" "test" {
  name                = "test-invalid-regex"
  regex               = "[invalid(regex"
  min_match_threshold = 1
}
`
}
