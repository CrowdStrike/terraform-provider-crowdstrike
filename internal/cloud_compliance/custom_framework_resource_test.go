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

// minimalFrameworkConfig represents a bare minimum custom compliance framework
type minimalFrameworkConfig struct {
	Name        string
	Description string
	Active      *bool
}

// completeFrameworkConfig represents a complete custom framework with sections, controls, and rules
type completeFrameworkConfig struct {
	Name        string
	Description string
	Active      *bool
	Sections    map[string]sectionConfig
}

// sectionConfig represents a section within a framework
type sectionConfig struct {
	Description string
	Controls    map[string]controlConfig
}

// controlConfig represents a control within a section
type controlConfig struct {
	Description string
	Rules       []string
}

// String generates Terraform configuration from minimalFrameworkConfig
func (config *minimalFrameworkConfig) String() string {
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

// String generates Terraform configuration from completeFrameworkConfig
func (config *completeFrameworkConfig) String() string {
	activeConfig := ""
	if config.Active != nil {
		activeConfig = fmt.Sprintf("\n  active = %t", *config.Active)
	}

	sectionsConfig := ""
	if len(config.Sections) > 0 {
		sectionsConfig = "\n  sections = {\n"
		for sectionName, section := range config.Sections {
			sectionsConfig += fmt.Sprintf("    %q = {\n", sectionName)
			sectionsConfig += fmt.Sprintf("      description = %q\n", section.Description)

			if len(section.Controls) > 0 {
				sectionsConfig += "      controls = {\n"
				for controlName, control := range section.Controls {
					sectionsConfig += fmt.Sprintf("        %q = {\n", controlName)
					sectionsConfig += fmt.Sprintf("          description = %q\n", control.Description)

					if len(control.Rules) > 0 {
						rulesStr := "["
						for i, rule := range control.Rules {
							if i > 0 {
								rulesStr += ", "
							}
							rulesStr += fmt.Sprintf("%q", rule)
						}
						rulesStr += "]"
						sectionsConfig += fmt.Sprintf("          rules = %s\n", rulesStr)
					} else {
						sectionsConfig += "          rules = []\n"
					}
					sectionsConfig += "        }\n"
				}
				sectionsConfig += "      }\n"
			}
			sectionsConfig += "    }\n"
		}
		sectionsConfig += "  }"
	}

	return fmt.Sprintf(`
resource "crowdstrike_cloud_compliance_custom_framework" "test" {
  name = %q
  description = %q%s%s
}
`, config.Name, config.Description, activeConfig, sectionsConfig)
}

// TestChecks generates test checks for the completeFrameworkConfig
func (config *completeFrameworkConfig) TestChecks() resource.TestCheckFunc {
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

	// Check sections
	if len(config.Sections) > 0 {
		for sectionName, section := range config.Sections {
			sectionPath := fmt.Sprintf("sections.%s", sectionName)
			checks = append(checks, resource.TestCheckResourceAttr(customFrameworkResourceName, sectionPath+".description", section.Description))

			// Check controls within each section
			if len(section.Controls) > 0 {
				for controlName, control := range section.Controls {
					controlPath := fmt.Sprintf("%s.controls.%s", sectionPath, controlName)
					checks = append(checks, resource.TestCheckResourceAttr(customFrameworkResourceName, controlPath+".description", control.Description))

					// Check rules within each control
					if len(control.Rules) > 0 {
						for i, rule := range control.Rules {
							checks = append(checks, resource.TestCheckResourceAttr(customFrameworkResourceName, fmt.Sprintf("%s.rules.%d", controlPath, i), rule))
						}
					}
				}
			}
		}
	}

	return resource.ComposeAggregateTestCheckFunc(checks...)
}

// TestChecks generates test checks for the framework configuration
func (config *minimalFrameworkConfig) TestChecks() resource.TestCheckFunc {
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
		config minimalFrameworkConfig
	}{
		{
			name: "initial_framework",
			config: minimalFrameworkConfig{
				Name:        "Test Framework Basic Initial",
				Description: "This is a test framework for basic functionality",
				Active:      utils.Addr(false), // API sets new frameworks to false by default
			},
		},
		{
			name: "updated_framework",
			config: minimalFrameworkConfig{
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
		config minimalFrameworkConfig
	}{
		{
			name: "active_true",
			config: minimalFrameworkConfig{
				Name:        "Test Framework Active Toggle",
				Description: "Framework to test active field toggling",
				Active:      utils.Addr(true),
			},
		},
		{
			name: "active_false",
			config: minimalFrameworkConfig{
				Name:        "Test Framework Active Toggle",
				Description: "Framework to test active field toggling",
				Active:      utils.Addr(false),
			},
		},
		{
			name: "active_true_again",
			config: minimalFrameworkConfig{
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
		config minimalFrameworkConfig
	}{
		{
			name: "initial_state",
			config: minimalFrameworkConfig{
				Name:        "Test Framework Updates Initial",
				Description: "Initial description for update testing",
				Active:      utils.Addr(false),
			},
		},
		{
			name: "updated_name",
			config: minimalFrameworkConfig{
				Name:        "Test Framework Updates Modified Name",
				Description: "Initial description for update testing",
				Active:      utils.Addr(false),
			},
		},
		{
			name: "updated_description",
			config: minimalFrameworkConfig{
				Name:        "Test Framework Updates Modified Name",
				Description: "Updated description after name change",
				Active:      utils.Addr(false),
			},
		},
		{
			name: "updated_all_fields",
			config: minimalFrameworkConfig{
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
		config minimalFrameworkConfig
	}{
		{
			name: "minimal_required_only",
			config: minimalFrameworkConfig{
				Name:        "Test Framework Minimal",
				Description: "Minimal test framework description",
			},
		},
		{
			name: "minimal_with_active",
			config: minimalFrameworkConfig{
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
	config := minimalFrameworkConfig{
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

func TestAccCloudComplianceCustomFrameworkResource_WithSections(t *testing.T) {
	testCases := []struct {
		name   string
		config completeFrameworkConfig
	}{
		{
			name: "framework_with_sections",
			config: completeFrameworkConfig{
				Name:        "Test Framework With Sections",
				Description: "Framework to test sections, controls, and rules",
				Active:      utils.Addr(false),
				Sections: map[string]sectionConfig{
					"Section 1": {
						Description: "This is the first section",
						Controls: map[string]controlConfig{
							"Control 1": {
								Description: "This is the first control",
								Rules:       []string{"rule1", "rule2", "rule3"},
							},
							"Control 1b": {
								Description: "This is another control in section 1",
								Rules:       []string{"rule4", "rule5"},
							},
						},
					},
					"Section 2": {
						Description: "This is the second section",
						Controls: map[string]controlConfig{
							"Control 2": {
								Description: "This is the second control",
								Rules:       []string{},
							},
						},
					},
				},
			},
		},
		{
			name: "updated_framework_sections",
			config: completeFrameworkConfig{
				Name:        "Test Framework With Sections",
				Description: "Updated framework with modified sections",
				Active:      utils.Addr(false),
				Sections: map[string]sectionConfig{
					"Section 1": {
						Description: "Updated first section description",
						Controls: map[string]controlConfig{
							"Control 1": {
								Description: "Updated first control description",
								Rules:       []string{"rule1", "rule2", "rule6"}, // Modified rules
							},
							"Control 1c": { // New control
								Description: "New control in section 1",
								Rules:       []string{"rule7"},
							},
						},
					},
					"Section 3": { // New section
						Description: "This is the third section",
						Controls: map[string]controlConfig{
							"Control 3": {
								Description: "Control in new section",
								Rules:       []string{"rule8", "rule9"},
							},
						},
					},
				},
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

func TestAccCloudComplianceCustomFrameworkResource_SectionManagement(t *testing.T) {
	testCases := []struct {
		name   string
		config completeFrameworkConfig
	}{
		{
			name: "empty_framework",
			config: completeFrameworkConfig{
				Name:        "Test Framework Section Management",
				Description: "Framework to test section management",
				Active:      utils.Addr(false),
				Sections:    map[string]sectionConfig{},
			},
		},
		{
			name: "add_sections",
			config: completeFrameworkConfig{
				Name:        "Test Framework Section Management",
				Description: "Framework to test section management",
				Active:      utils.Addr(false),
				Sections: map[string]sectionConfig{
					"New Section": {
						Description: "Newly added section",
						Controls: map[string]controlConfig{
							"New Control": {
								Description: "Control in new section",
								Rules:       []string{"newrule1"},
							},
						},
					},
				},
			},
		},
		{
			name: "multiple_sections",
			config: completeFrameworkConfig{
				Name:        "Test Framework Section Management",
				Description: "Framework to test section management",
				Active:      utils.Addr(false),
				Sections: map[string]sectionConfig{
					"New Section": {
						Description: "Updated section description",
						Controls: map[string]controlConfig{
							"New Control": {
								Description: "Updated control description",
								Rules:       []string{"newrule1", "newrule2"},
							},
						},
					},
					"Another Section": {
						Description: "Second section added",
						Controls: map[string]controlConfig{
							"Another Control": {
								Description: "Control in second section",
								Rules:       []string{},
							},
						},
					},
				},
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

func TestAccCloudComplianceCustomFrameworkResource_RuleAssignment(t *testing.T) {
	testCases := []struct {
		name   string
		config completeFrameworkConfig
	}{
		{
			name: "control_with_rules",
			config: completeFrameworkConfig{
				Name:        "Test Framework Rule Assignment",
				Description: "Framework to test rule assignments",
				Active:      utils.Addr(false),
				Sections: map[string]sectionConfig{
					"Test Section": {
						Description: "Section for rule testing",
						Controls: map[string]controlConfig{
							"Control With Rules": {
								Description: "Control that has rules assigned",
								Rules:       []string{"rule_a", "rule_b", "rule_c"},
							},
							"Control Without Rules": {
								Description: "Control with no rules",
								Rules:       []string{},
							},
						},
					},
				},
			},
		},
		{
			name: "updated_rules",
			config: completeFrameworkConfig{
				Name:        "Test Framework Rule Assignment",
				Description: "Framework to test rule assignments",
				Active:      utils.Addr(false),
				Sections: map[string]sectionConfig{
					"Test Section": {
						Description: "Section for rule testing",
						Controls: map[string]controlConfig{
							"Control With Rules": {
								Description: "Control that has rules assigned",
								Rules:       []string{"rule_a", "rule_d", "rule_e"}, // Modified rules
							},
							"Control Without Rules": {
								Description: "Control with no rules",
								Rules:       []string{"rule_f"}, // Added rules
							},
						},
					},
				},
			},
		},
		{
			name: "removed_rules",
			config: completeFrameworkConfig{
				Name:        "Test Framework Rule Assignment",
				Description: "Framework to test rule assignments",
				Active:      utils.Addr(false),
				Sections: map[string]sectionConfig{
					"Test Section": {
						Description: "Section for rule testing",
						Controls: map[string]controlConfig{
							"Control With Rules": {
								Description: "Control that has rules assigned",
								Rules:       []string{}, // All rules removed
							},
							"Control Without Rules": {
								Description: "Control with no rules",
								Rules:       []string{}, // Rules removed
							},
						},
					},
				},
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
