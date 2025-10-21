package cloudcompliance_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const customFrameworkResourceName = "crowdstrike_cloud_compliance_custom_framework.test"

// frameworkConfig represents a custom compliance framework configuration for testing
type frameworkConfig struct {
	Name        string
	Description string
	Active      *bool
}

// String generates Terraform configuration from frameworkConfig
func (config *frameworkConfig) String() string {
	activeConfig := ""
	if config.Active != nil {
		activeConfig = fmt.Sprintf("\n  active = %t", *config.Active)
	}

	descriptionConfig := ""
	if config.Description != "" {
		descriptionConfig = fmt.Sprintf("\n  description = %q", config.Description)
	}

	return fmt.Sprintf(`
resource "crowdstrike_cloud_compliance_custom_framework" "test" {
  name = %q%s%s
}
`, config.Name, descriptionConfig, activeConfig)
}

// TestChecks generates test checks for the framework configuration
func (config *frameworkConfig) TestChecks() resource.TestCheckFunc {
	var checks []resource.TestCheckFunc

	checks = append(checks,
		resource.TestCheckResourceAttrSet(customFrameworkResourceName, "id"),
		resource.TestCheckResourceAttr(customFrameworkResourceName, "name", config.Name),
		resource.TestCheckResourceAttr(customFrameworkResourceName, "description", config.Description),
	)

	if config.Active != nil {
		checks = append(checks, resource.TestCheckResourceAttr(customFrameworkResourceName, "active", fmt.Sprintf("%t", *config.Active)))
	} else {
		checks = append(checks, resource.TestCheckResourceAttrSet(customFrameworkResourceName, "active"))
	}

	return resource.ComposeAggregateTestCheckFunc(checks...)
}

func TestAccCloudComplianceCustomFrameworkResource_Basic(t *testing.T) {
	testCases := []struct {
		name   string
		config frameworkConfig
	}{
		{
			name: "initial_framework",
			config: frameworkConfig{
				Name:        "Test Framework Basic Initial",
				Description: "This is a test framework for basic functionality",
				Active:      utils.Addr(false), // API sets new frameworks to false by default
			},
		},
		{
			name: "updated_framework",
			config: frameworkConfig{
				Name:        "Test Framework Basic Updated",
				Description: "This is an updated test framework description",
				Active:      utils.Addr(false),
			},
		},
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: acctest.ProviderConfig + tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			// Add import test
			steps = append(steps, resource.TestStep{
				ResourceName:      customFrameworkResourceName,
				ImportState:       true,
				ImportStateVerify: true,
			})
			return steps
		}(),
	})
}

func TestAccCloudComplianceCustomFrameworkResource_ActiveToggle(t *testing.T) {
	testCases := []struct {
		name   string
		config frameworkConfig
	}{
		{
			name: "active_true",
			config: frameworkConfig{
				Name:        "Test Framework Active Toggle",
				Description: "Framework to test active field toggling",
				Active:      utils.Addr(true),
			},
		},
		{
			name: "active_false",
			config: frameworkConfig{
				Name:        "Test Framework Active Toggle",
				Description: "Framework to test active field toggling",
				Active:      utils.Addr(false),
			},
		},
		{
			name: "active_true_again",
			config: frameworkConfig{
				Name:        "Test Framework Active Toggle",
				Description: "Framework to test active field toggling",
				Active:      utils.Addr(true),
			},
		},
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: acctest.ProviderConfig + tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			return steps
		}(),
	})
}

func TestAccCloudComplianceCustomFrameworkResource_Updates(t *testing.T) {
	testCases := []struct {
		name   string
		config frameworkConfig
	}{
		{
			name: "initial_state",
			config: frameworkConfig{
				Name:        "Test Framework Updates Initial",
				Description: "Initial description for update testing",
				Active:      utils.Addr(false),
			},
		},
		{
			name: "updated_name",
			config: frameworkConfig{
				Name:        "Test Framework Updates Modified Name",
				Description: "Initial description for update testing",
				Active:      utils.Addr(false),
			},
		},
		{
			name: "updated_description",
			config: frameworkConfig{
				Name:        "Test Framework Updates Modified Name",
				Description: "Updated description after name change",
				Active:      utils.Addr(false),
			},
		},
		{
			name: "updated_all_fields",
			config: frameworkConfig{
				Name:        "Test Framework Final State",
				Description: "Final updated description",
				Active:      utils.Addr(false),
			},
		},
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: acctest.ProviderConfig + tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			return steps
		}(),
	})
}

func TestAccCloudComplianceCustomFrameworkResource_Minimal(t *testing.T) {
	testCases := []struct {
		name   string
		config frameworkConfig
	}{
		{
			name: "minimal_required_only",
			config: frameworkConfig{
				Name:        "Test Framework Minimal",
				Description: "Minimal test framework description",
			},
		},
		{
			name: "minimal_with_active",
			config: frameworkConfig{
				Name:        "Test Framework Minimal With Active",
				Description: "Minimal test framework with active setting",
				Active:      utils.Addr(false),
			},
		},
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: acctest.ProviderConfig + tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			return steps
		}(),
	})
}

func TestAccCloudComplianceCustomFrameworkResource_Validation(t *testing.T) {
	validationTests := []struct {
		name        string
		config      string
		expectError *regexp.Regexp
	}{
		{
			name: "empty_name",
			config: `
resource "crowdstrike_cloud_compliance_custom_framework" "test" {
  name = ""
  description = "Framework with empty name"
}
`,
			expectError: regexp.MustCompile("framework name must not be blank"),
		},
		{
			name: "empty_description",
			config: `
resource "crowdstrike_cloud_compliance_custom_framework" "test" {
  name = "Framework with empty description"
  description = ""
}
`,
			expectError: regexp.MustCompile("Attribute description string length must be at least 1"),
		},
		{
			name: "missing_name",
			config: `
resource "crowdstrike_cloud_compliance_custom_framework" "test" {
  description = "Framework without name"
}
`,
			expectError: regexp.MustCompile("The argument \"name\" is required"),
		},
		{
			name: "missing_description",
			config: `
resource "crowdstrike_cloud_compliance_custom_framework" "test" {
  name = "Framework without description"
}
`,
			expectError: regexp.MustCompile("The argument \"description\" is required"),
		},
	}

	for _, tc := range validationTests {
		t.Run(tc.name, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { acctest.PreCheck(t) },
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config:      acctest.ProviderConfig + tc.config,
						ExpectError: tc.expectError,
					},
				},
			})
		})
	}
}

func TestAccCloudComplianceCustomFrameworkResource_Import(t *testing.T) {
	config := frameworkConfig{
		Name:        "Test Framework Import",
		Description: "Framework for testing import functionality",
		Active:      utils.Addr(false),
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + config.String(),
				Check:  config.TestChecks(),
			},
			{
				ResourceName:                         customFrameworkResourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "id",
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					rs, ok := s.RootModule().Resources[customFrameworkResourceName]
					if !ok {
						return "", fmt.Errorf("Resource not found: %s", customFrameworkResourceName)
					}
					return rs.Primary.Attributes["id"], nil
				},
			},
		},
	})
}

func TestAccCloudComplianceCustomFrameworkResource_ActiveValidation(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create framework (defaults to active = false)
			{
				Config: acctest.ProviderConfig + `
resource "crowdstrike_cloud_compliance_custom_framework" "test" {
  name        = "Test Framework Active Validation"
  description = "Framework to test active field validation"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(customFrameworkResourceName, "active", "false"),
				),
			},
			// Step 2: Update to active = true
			{
				Config: acctest.ProviderConfig + `
resource "crowdstrike_cloud_compliance_custom_framework" "test" {
  name        = "Test Framework Active Validation"
  description = "Framework to test active field validation"
  active      = true
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(customFrameworkResourceName, "active", "true"),
				),
			},
			// Step 3: Try to change active from true back to false - should fail
			{
				Config: acctest.ProviderConfig + `
resource "crowdstrike_cloud_compliance_custom_framework" "test" {
  name        = "Test Framework Active Validation"
  description = "Framework to test active field validation"
  active      = false
}
`,
				ExpectError: regexp.MustCompile("The active field cannot be changed from true to false"),
			},
		},
	})
}
