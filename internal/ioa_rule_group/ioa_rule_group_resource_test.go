package ioarulegroup_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccIOARuleGroupResource_Windows(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = "%s"
  description = "made with terraform"
  platform    = "windows"
  comment     = "test comment"
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"description",
						"made with terraform",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"platform",
						"windows",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"comment",
						"test comment",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_ioa_rule_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_ioa_rule_group.test",
						"last_updated",
					),
				),
			},
			// ImportState testing
			{
				ResourceName:            "crowdstrike_ioa_rule_group.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Update testing - should work with comment
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = "%s-updated"
  description = "updated with terraform"
  platform    = "windows"
  comment     = "updated comment"
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"name",
						rName+"-updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"description",
						"updated with terraform",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"comment",
						"updated comment",
					),
				),
			},
		},
	})
}

func TestAccIOARuleGroupResource_Linux(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = "%s"
  description = "made with terraform"
  platform    = "linux"
  comment     = "test comment"
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"description",
						"made with terraform",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"platform",
						"linux",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"comment",
						"test comment",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_ioa_rule_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_ioa_rule_group.test",
						"last_updated",
					),
				),
			},
			// ImportState testing
			{
				ResourceName:            "crowdstrike_ioa_rule_group.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Update testing - should work with comment
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = "%s-updated"
  description = "updated with terraform"
  platform    = "linux"
  comment     = "updated comment"
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"name",
						rName+"-updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"description",
						"updated with terraform",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"comment",
						"updated comment",
					),
				),
			},
		},
	})
}

func TestAccIOARuleGroupResource_Mac(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = "%s"
  description = "made with terraform"
  platform    = "mac"
  comment     = "test comment"
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"description",
						"made with terraform",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"platform",
						"mac",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"comment",
						"test comment",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_ioa_rule_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_ioa_rule_group.test",
						"last_updated",
					),
				),
			},
			// ImportState testing
			{
				ResourceName:            "crowdstrike_ioa_rule_group.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Update testing - should work with comment
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = "%s-updated"
  description = "updated with terraform"
  platform    = "mac"
  comment     = "updated comment"
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"name",
						rName+"-updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"description",
						"updated with terraform",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"comment",
						"updated comment",
					),
				),
			},
		},
	})
}

func TestAccIOARuleGroupResourceUpdateWithoutComment_Windows(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create without comment
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name     = "%s"
  platform = "windows"
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"platform",
						"windows",
					),
				),
			},
			// Try to update without comment - should fail
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = "%s-updated"
  description = "updated description"
  platform    = "windows"
}
`, rName),
				ExpectError: regexp.MustCompile("Comment required for updates"),
			},
		},
	})
}

func TestAccIOARuleGroupResourceUpdateWithoutComment_Linux(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create without comment
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name     = "%s"
  platform = "linux"
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"platform",
						"linux",
					),
				),
			},
			// Try to update without comment - should fail
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = "%s-updated"
  description = "updated description"
  platform    = "linux"
}
`, rName),
				ExpectError: regexp.MustCompile("Comment required for updates"),
			},
		},
	})
}

func TestAccIOARuleGroupResourceUpdateWithoutComment_Mac(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create without comment
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name     = "%s"
  platform = "mac"
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"name",
						rName,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"platform",
						"mac",
					),
				),
			},
			// Try to update without comment - should fail
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = "%s-updated"
  description = "updated description"
  platform    = "mac"
}
`, rName),
				ExpectError: regexp.MustCompile("Comment required for updates"),
			},
		},
	})
}

func TestAccIOARuleGroupResourceMinimal_Windows(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Test with minimal configuration (only required fields)
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name     = "%s-minimal"
  platform = "windows"
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"name",
						rName+"-minimal",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"platform",
						"windows",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_ioa_rule_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_ioa_rule_group.test",
						"last_updated",
					),
				),
			},
			// ImportState testing
			{
				ResourceName:            "crowdstrike_ioa_rule_group.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
		},
	})
}

func TestAccIOARuleGroupResourceMinimal_Linux(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Test with minimal configuration (only required fields)
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name     = "%s-minimal"
  platform = "linux"
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"name",
						rName+"-minimal",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"platform",
						"linux",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_ioa_rule_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_ioa_rule_group.test",
						"last_updated",
					),
				),
			},
			// ImportState testing
			{
				ResourceName:            "crowdstrike_ioa_rule_group.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
		},
	})
}

func TestAccIOARuleGroupResourceMinimal_Mac(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Test with minimal configuration (only required fields)
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name     = "%s-minimal"
  platform = "mac"
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"name",
						rName+"-minimal",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"platform",
						"mac",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_ioa_rule_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_ioa_rule_group.test",
						"last_updated",
					),
				),
			},
			// ImportState testing
			{
				ResourceName:            "crowdstrike_ioa_rule_group.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
		},
	})
}

func TestAccIOARuleGroupResourceWithRules_Windows(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create rule group with rules
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = "%s-with-rules"
  description = "Test rule group with rules"
  platform    = "windows"
  comment     = "Created with rules"

  rules = [
    {
      name             = "Test Rule 1"
      description      = "First test rule"
      pattern_severity = "high"
      ruletype_id      = "1"
      disposition_id   = 20
      enabled          = true

      field_values = [
        {
          name   = "ImageFilename"
          label  = "Image Filename"
          type   = "excludable"
          values = [
            {
              label = "include"
              value = ".*test_process.*"
            }
          ]
        }
      ]
    }
  ]
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"name",
						rName+"-with-rules",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"description",
						"Test rule group with rules",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"platform",
						"windows",
					),
					// Check that rules were created
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"rules.#",
						"1",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_ioa_rule_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_ioa_rule_group.test",
						"last_updated",
					),
				),
			},
			// Update rules - add another rule
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = "%s-with-rules"
  description = "Test rule group with updated rules"
  platform    = "windows"
  comment     = "Updated with more rules"

  rules = [
    {
      name             = "Test Rule 1"
      description      = "First test rule"
      pattern_severity = "high"
      ruletype_id      = "1"
      disposition_id   = 20
      enabled          = true

      field_values = [
        {
          name   = "ImageFilename"
          label  = "Image Filename"
          type   = "excludable"
          values = [
            {
              label = "include"
              value = ".*test_process.*"
            }
          ]
        }
      ]
    },
    {
      name             = "Test Rule 2"
      description      = "Second test rule"
      pattern_severity = "medium"
      ruletype_id      = "1"
      disposition_id   = 20
      enabled          = false

      field_values = [
        {
          name   = "CommandLine"
          label  = "Command Line"
          type   = "excludable"
          values = [
            {
              label = "include"
              value = ".*malicious_command.*"
            }
          ]
        }
      ]
    }
  ]
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"name",
						rName+"-with-rules",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"description",
						"Test rule group with updated rules",
					),
					// Check that both rules exist
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"rules.#",
						"2",
					),
				),
			},
		},
	})
}

func TestAccIOARuleGroupResourceWithRules_Linux(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create rule group with rules
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = "%s-with-rules"
  description = "Test rule group with rules"
  platform    = "linux"
  comment     = "Created with rules"

  rules = [
    {
      name             = "Test Rule 1"
      description      = "First test rule"
      pattern_severity = "high"
      ruletype_id      = "1"
      disposition_id   = 20
      enabled          = true

      field_values = [
        {
          name   = "ImageFilename"
          label  = "Image Filename"
          type   = "excludable"
          values = [
            {
              label = "include"
              value = ".*test_process.*"
            }
          ]
        }
      ]
    }
  ]
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"name",
						rName+"-with-rules",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"description",
						"Test rule group with rules",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"platform",
						"linux",
					),
					// Check that rules were created
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"rules.#",
						"1",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_ioa_rule_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_ioa_rule_group.test",
						"last_updated",
					),
				),
			},
			// Update rules - add another rule
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = "%s-with-rules"
  description = "Test rule group with updated rules"
  platform    = "linux"
  comment     = "Updated with more rules"

  rules = [
    {
      name             = "Test Rule 1"
      description      = "First test rule"
      pattern_severity = "high"
      ruletype_id      = "1"
      disposition_id   = 20
      enabled          = true

      field_values = [
        {
          name   = "ImageFilename"
          label  = "Image Filename"
          type   = "excludable"
          values = [
            {
              label = "include"
              value = ".*test_process.*"
            }
          ]
        }
      ]
    },
    {
      name             = "Test Rule 2"
      description      = "Second test rule"
      pattern_severity = "medium"
      ruletype_id      = "1"
      disposition_id   = 20
      enabled          = false

      field_values = [
        {
          name   = "CommandLine"
          label  = "Command Line"
          type   = "excludable"
          values = [
            {
              label = "include"
              value = ".*malicious_command.*"
            }
          ]
        }
      ]
    }
  ]
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"name",
						rName+"-with-rules",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"description",
						"Test rule group with updated rules",
					),
					// Check that both rules exist
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"rules.#",
						"2",
					),
				),
			},
		},
	})
}

func TestAccIOARuleGroupResourceWithRules_Mac(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create rule group with rules
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = "%s-with-rules"
  description = "Test rule group with rules"
  platform    = "mac"
  comment     = "Created with rules"

  rules = [
    {
      name             = "Test Rule 1"
      description      = "First test rule"
      pattern_severity = "high"
      ruletype_id      = "1"
      disposition_id   = 20
      enabled          = true

      field_values = [
        {
          name   = "ImageFilename"
          label  = "Image Filename"
          type   = "excludable"
          values = [
            {
              label = "include"
              value = ".*test_process.*"
            }
          ]
        }
      ]
    }
  ]
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"name",
						rName+"-with-rules",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"description",
						"Test rule group with rules",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"platform",
						"mac",
					),
					// Check that rules were created
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"rules.#",
						"1",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_ioa_rule_group.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_ioa_rule_group.test",
						"last_updated",
					),
				),
			},
			// Update rules - add another rule
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = "%s-with-rules"
  description = "Test rule group with updated rules"
  platform    = "mac"
  comment     = "Updated with more rules"

  rules = [
    {
      name             = "Test Rule 1"
      description      = "First test rule"
      pattern_severity = "high"
      ruletype_id      = "1"
      disposition_id   = 20
      enabled          = true

      field_values = [
        {
          name   = "ImageFilename"
          label  = "Image Filename"
          type   = "excludable"
          values = [
            {
              label = "include"
              value = ".*test_process.*"
            }
          ]
        }
      ]
    },
    {
      name             = "Test Rule 2"
      description      = "Second test rule"
      pattern_severity = "medium"
      ruletype_id      = "1"
      disposition_id   = 20
      enabled          = false

      field_values = [
        {
          name   = "CommandLine"
          label  = "Command Line"
          type   = "excludable"
          values = [
            {
              label = "include"
              value = ".*malicious_command.*"
            }
          ]
        }
      ]
    }
  ]
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"name",
						rName+"-with-rules",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"description",
						"Test rule group with updated rules",
					),
					// Check that both rules exist
					resource.TestCheckResourceAttr(
						"crowdstrike_ioa_rule_group.test",
						"rules.#",
						"2",
					),
				),
			},
		},
	})
}
