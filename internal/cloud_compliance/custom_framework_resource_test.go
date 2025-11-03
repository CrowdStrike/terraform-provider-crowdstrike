package cloudcompliance_test

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
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
	Name     string
	Controls map[string]controlConfig
}

// controlConfig represents a control within a section
type controlConfig struct {
	Name        string
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
		for sectionKey, section := range config.Sections {
			sectionsConfig += fmt.Sprintf("    %q = {\n", sectionKey)
			sectionsConfig += fmt.Sprintf("      name = %q\n", section.Name)

			if len(section.Controls) > 0 {
				sectionsConfig += "      controls = {\n"
				for controlKey, control := range section.Controls {
					sectionsConfig += fmt.Sprintf("        %q = {\n", controlKey)
					sectionsConfig += fmt.Sprintf("          name = %q\n", control.Name)
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

	// Check sections count
	if len(config.Sections) > 0 {
		checks = append(checks, resource.TestCheckResourceAttr(customFrameworkResourceName, "sections.%", fmt.Sprintf("%d", len(config.Sections))))

		// For sets, we need to use TestCheckTypeSetElemNestedAttrs to check individual section elements
		for sectionKey, section := range config.Sections {
			sectionPath := fmt.Sprintf("sections.%s", sectionKey)
			checks = append(checks, resource.TestCheckResourceAttr(customFrameworkResourceName, sectionPath+".name", section.Name))

			// Check controls within each section
			if len(section.Controls) > 0 {
				checks = append(checks, resource.TestCheckResourceAttr(customFrameworkResourceName, sectionPath+".controls.%", fmt.Sprintf("%d", len(section.Controls))))

				for controlKey, control := range section.Controls {
					controlPath := fmt.Sprintf("%s.controls.%s", sectionPath, controlKey)
					checks = append(checks,
						resource.TestCheckResourceAttrSet(customFrameworkResourceName, controlPath+".id"),
						resource.TestCheckResourceAttr(customFrameworkResourceName, controlPath+".name", control.Name),
						resource.TestCheckResourceAttr(customFrameworkResourceName, controlPath+".description", control.Description),
					)

					// Check rules within each control (order-independent)
					if len(control.Rules) > 0 {
						checks = append(checks, resource.TestCheckResourceAttr(customFrameworkResourceName, fmt.Sprintf("%s.rules.#", controlPath), fmt.Sprintf("%d", len(control.Rules))))
						for _, rule := range control.Rules {
							checks = append(checks, resource.TestCheckTypeSetElemAttr(customFrameworkResourceName, fmt.Sprintf("%s.rules.*", controlPath), rule))
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

func _TestAccCloudComplianceCustomFrameworkResource_ActiveToggle(t *testing.T) {
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
			expectError: regexp.MustCompile("Attribute name string length must be at least 1"),
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

func TestAccCloudComplianceCustomFrameworkResource_CreateWithSections(t *testing.T) {
	initialConfig := completeFrameworkConfig{
		Name:        "Test Framework With Sections",
		Description: "Framework to test sections, controls, and rules",
		Active:      utils.Addr(false),
		Sections: map[string]sectionConfig{
			"section-1": {
				Name: "Section 1",
				Controls: map[string]controlConfig{
					"control-1a": {
						Name:        "Control 1a",
						Description: "This is the first control",
						Rules: []string{
							"2a11d9fc-6dfa-44f9-acc9-5ff046083716",
							"a28151f0-5077-49da-8999-f909d94b53a3",
						},
					},
					"control-1b": {
						Name:        "Control 1b",
						Description: "This is another control in section 1",
						Rules: []string{
							"6896e8e5-84c2-4310-8207-3f46e54b6abe",
						},
					},
				},
			},
			"section-2": {
				Name: "Section 2",
				Controls: map[string]controlConfig{
					"control-2a": {
						Name:        "Control 2a",
						Description: "This is the second control",
						Rules:       []string{},
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
			steps = append(steps, resource.TestStep{
				Config: acctest.ProviderConfig + initialConfig.String(),
				Check:  initialConfig.TestChecks(),
			})

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
					"test-section": {
						Name: "Test Section",
						Controls: map[string]controlConfig{
							"control-with-rules": {
								Name:        "Control With Rules",
								Description: "Control that has rules assigned",
								Rules: []string{
									"2a11d9fc-6dfa-44f9-acc9-5ff046083716",
									"a28151f0-5077-49da-8999-f909d94b53a3",
								},
							},
							"control-without-rules": {
								Name:        "Control Without Rules",
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
					"test-section": {
						Name: "Test Section",
						Controls: map[string]controlConfig{
							"control-with-rules": {
								Name:        "Control With Rules",
								Description: "Control that has rules assigned",
								Rules: []string{ // Modified rules
									"2a11d9fc-6dfa-44f9-acc9-5ff046083716",
									"0473a26b-7f29-43c7-9581-105f8c9c0b7d",
								},
							},
							"control-without-rules": {
								Name:        "Control Without Rules",
								Description: "Control with no rules",
								Rules:       []string{"6896e8e5-84c2-4310-8207-3f46e54b6abe"}, // Added rules
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
					"test-section": {
						Name: "Test Section",
						Controls: map[string]controlConfig{
							"control-with-rules": {
								Name:        "Control With Rules",
								Description: "Control that has rules assigned",
								Rules:       []string{}, // All rules removed
							},
							"control-without-rules": {
								Name:        "Control Without Rules",
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

func TestAccCloudComplianceCustomFrameworkResource_SimpleSectionRename(t *testing.T) {
	// Use timestamp to ensure unique framework name
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	frameworkName := fmt.Sprintf("Test Framework Simple Section Rename %s", timestamp)

	initialConfig := completeFrameworkConfig{
		Name:        frameworkName,
		Description: "Framework to test simple section renaming",
		Active:      utils.Addr(false),
		Sections: map[string]sectionConfig{
			"section-1": {
				Name: "Original Section",
				Controls: map[string]controlConfig{
					"test-control": {
						Name:        "Test Control",
						Description: "Test control description",
						Rules:       []string{},
					},
				},
			},
		},
	}

	// Rename just the section, keeping control the same
	renamedConfig := completeFrameworkConfig{
		Name:        frameworkName,
		Description: "Framework to test simple section renaming",
		Active:      utils.Addr(false),
		Sections: map[string]sectionConfig{
			"section-1": {
				Name: "Renamed Section",
				Controls: map[string]controlConfig{
					"test-control": {
						Name:        "Test Control",
						Description: "Test control description",
						Rules:       []string{},
					},
				},
			},
		},
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + initialConfig.String(),
				Check:  initialConfig.TestChecks(),
			},
			{
				Config: acctest.ProviderConfig + renamedConfig.String(),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						// Verify the resource is updated, not replaced
						plancheck.ExpectResourceAction(
							customFrameworkResourceName,
							plancheck.ResourceActionUpdate,
						),
						// Verify control ID persists after section renaming (simplified check for sets)
						plancheck.ExpectKnownValue(
							customFrameworkResourceName,
							tfjsonpath.New("sections").AtMapKey("section-1").AtMapKey("controls").AtMapKey("test-control").AtMapKey("id"),
							knownvalue.NotNull(),
						),
					},
				},
				Check: renamedConfig.TestChecks(),
			},
		},
	})
}

func TestAccCloudComplianceCustomFrameworkResource_ComprehensiveRenaming(t *testing.T) {
	initialConfig := completeFrameworkConfig{
		Name:        "Test Framework Comprehensive Renaming",
		Description: "Framework to test comprehensive renaming operations",
		Active:      utils.Addr(false),
		Sections: map[string]sectionConfig{
			"section-a": {
				Name: "Original Section A",
				Controls: map[string]controlConfig{
					"control-a1": {
						Name:        "Original Control A1",
						Description: "Original control description A1",
						Rules:       []string{},
					},
					"control-a2": {
						Name:        "Original Control A2",
						Description: "Original control description A2",
						Rules:       []string{},
					},
				},
			},
			"section-b": {
				Name: "Original Section B",
				Controls: map[string]controlConfig{
					"control-b1": {
						Name:        "Original Control B1",
						Description: "Original control description B1",
						Rules:       []string{},
					},
				},
			},
		},
	}

	// Test 3: Rename both section and control simultaneously
	renamedConfig := completeFrameworkConfig{
		Name:        "Test Framework Comprehensive Renaming",
		Description: "Framework to test comprehensive renaming operations",
		Active:      utils.Addr(false),
		Sections: map[string]sectionConfig{
			"section-a": {
				Name: "Renamed Section A",
				Controls: map[string]controlConfig{
					"control-a1": {
						Name:        "Renamed Control A1",
						Description: "Original control description A1",
						Rules:       []string{},
					},
					"control-a2": {
						Name:        "Original Control A2",
						Description: "Original control description A2",
						Rules:       []string{},
					},
				},
			},
			"section-b": {
				Name: "Original Section B",
				Controls: map[string]controlConfig{
					"control-b1": {
						Name:        "Renamed Control B1",
						Description: "Original control description B1",
						Rules:       []string{},
					},
				},
			},
		},
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + initialConfig.String(),
				Check:  initialConfig.TestChecks(),
			},
			{
				Config: acctest.ProviderConfig + renamedConfig.String(),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						// Verify the resource is updated, not replaced
						plancheck.ExpectResourceAction(
							customFrameworkResourceName,
							plancheck.ResourceActionUpdate,
						),
						// Verify control IDs persist after renaming (simplified checks for sets)
						plancheck.ExpectKnownValue(
							customFrameworkResourceName,
							tfjsonpath.New("sections").AtMapKey("section-a").AtMapKey("controls").AtMapKey("control-a1").AtMapKey("id"),
							knownvalue.NotNull(),
						),
						plancheck.ExpectKnownValue(
							customFrameworkResourceName,
							tfjsonpath.New("sections").AtMapKey("section-a").AtMapKey("controls").AtMapKey("control-a2").AtMapKey("id"),
							knownvalue.NotNull(),
						),
						plancheck.ExpectKnownValue(
							customFrameworkResourceName,
							tfjsonpath.New("sections").AtMapKey("section-b").AtMapKey("controls").AtMapKey("control-b1").AtMapKey("id"),
							knownvalue.NotNull(),
						),
					},
				},
				Check: renamedConfig.TestChecks(),
			},
		},
	})
}

func TestAccCloudComplianceCustomFrameworkResource_ComprehensiveCRUD(t *testing.T) {
	initialConfig := completeFrameworkConfig{
		Name:        "Test Framework Comprehensive CRUD",
		Description: "Framework to test comprehensive CRUD operations",
	}

	// Test 1: Add a new section with controls and rules
	addSectionConfig := completeFrameworkConfig{
		Name:        "Test Framework Comprehensive CRUD",
		Description: "Framework to test comprehensive CRUD operations",
		Active:      utils.Addr(false),
		Sections: map[string]sectionConfig{
			"section-1": {
				Name: "Section 1",
				Controls: map[string]controlConfig{
					"control-1.1": {
						Name:        "Control 1.1",
						Description: "Control 1.1 description",
						Rules: []string{
							"2a11d9fc-6dfa-44f9-acc9-5ff046083716",
							"a28151f0-5077-49da-8999-f909d94b53a3",
						},
					},
					"control-1.2": {
						Name:        "Control 1.2",
						Description: "Control 1.2 description",
						Rules:       []string{},
					},
				},
			},
		},
	}

	// Test 2: Add new section, and controls to existing section + delete control
	addSectionAndControlsConfig := completeFrameworkConfig{
		Name:        "Test Framework Comprehensive CRUD",
		Description: "Framework to test comprehensive CRUD operations",
		Active:      utils.Addr(false),
		Sections: map[string]sectionConfig{
			"section-1": {
				Name: "Section 1",
				Controls: map[string]controlConfig{
					// deleted control-1.1
					"control-1.2": {
						Name:        "Control 1.2",
						Description: "Control 1.2 description",
						Rules: []string{
							"2a11d9fc-6dfa-44f9-acc9-5ff046083716",
							"a28151f0-5077-49da-8999-f909d94b53a3",
						},
					},
					"control-1.3": {
						Name:        "Control 1.3",
						Description: "Control 1.3 description",
						Rules:       []string{},
					},
				},
			},
			"section-2": {
				Name: "Section 2",
				Controls: map[string]controlConfig{
					"control-2.1": {
						Name:        "New Control 2.1",
						Description: "New control 2.1 description",
						Rules:       []string{},
					},
					"control-2.2": {
						Name:        "New Control 2.2",
						Description: "New control 2.2 description",
						Rules:       []string{"0473a26b-7f29-43c7-9581-105f8c9c0b7d"},
					},
				},
			},
		},
	}

	// Test 3: Delete controls and sections
	deleteConfig := completeFrameworkConfig{
		Name:        "Test Framework Comprehensive CRUD",
		Description: "Framework to test comprehensive CRUD operations",
		Active:      utils.Addr(false),
		Sections: map[string]sectionConfig{
			// section-1 deleted entirely
			"section-2": {
				Name: "Section 2",
				Controls: map[string]controlConfig{
					// control-2.1 deleted
					"control-2.2": {
						Name:        "New Control 2.2",
						Description: "New control 2.2 description",
						Rules:       []string{"0473a26b-7f29-43c7-9581-105f8c9c0b7d"},
					},
				},
			},
		},
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + initialConfig.String(),
				Check:  initialConfig.TestChecks(),
			},
			{
				Config: acctest.ProviderConfig + addSectionConfig.String(),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(
							customFrameworkResourceName,
							plancheck.ResourceActionUpdate,
						),
					},
				},
				Check: addSectionConfig.TestChecks(),
			},
			{
				Config: acctest.ProviderConfig + addSectionAndControlsConfig.String(),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(
							customFrameworkResourceName,
							plancheck.ResourceActionUpdate,
						),
						// Verify existing control ID persists when adding and deleting controls
						plancheck.ExpectKnownValue(
							customFrameworkResourceName,
							tfjsonpath.New("sections").AtMapKey("section-1").AtMapKey("controls").AtMapKey("control-1.2").AtMapKey("id"),
							knownvalue.NotNull(),
						),
					},
				},
				Check: addSectionAndControlsConfig.TestChecks(),
			},
			{
				Config: acctest.ProviderConfig + deleteConfig.String(),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						// Verify resource is updated when deleting sections/controls
						plancheck.ExpectResourceAction(
							customFrameworkResourceName,
							plancheck.ResourceActionUpdate,
						),
						// Verify remaining control ID persists after deletions
						plancheck.ExpectKnownValue(
							customFrameworkResourceName,
							tfjsonpath.New("sections").AtMapKey("section-2").AtMapKey("controls").AtMapKey("control-2.2").AtMapKey("id"),
							knownvalue.NotNull(),
						),
					},
				},
				Check: deleteConfig.TestChecks(),
			},
		},
	})
}

func TestAccCloudComplianceCustomFrameworkResource_MixedOperations(t *testing.T) {
	initialConfig := completeFrameworkConfig{
		Name:        "Test Framework Mixed Operations",
		Description: "Framework to test mixed operations",
		Active:      utils.Addr(false),
		Sections: map[string]sectionConfig{
			"section-to-delete": {
				Name: "Section To Delete",
				Controls: map[string]controlConfig{
					"control-to-delete": {
						Name:        "Control To Delete",
						Description: "Control that will be deleted",
						Rules:       []string{},
					},
				},
			},
			"section-to-rename": {
				Name: "Section To Rename",
				Controls: map[string]controlConfig{
					"control-to-rename": {
						Name:        "Control To Rename",
						Description: "Control that will be renamed",
						Rules:       []string{},
					},
					"control-to-delete-2": {
						Name:        "Another Control To Delete",
						Description: "Another control that will be deleted",
						Rules:       []string{},
					},
				},
			},
		},
	}

	// Test: Delete one section while renaming another, and delete/rename controls
	mixedOperationsConfig := completeFrameworkConfig{
		Name:        "Test Framework Mixed Operations",
		Description: "Framework to test mixed operations",
		Active:      utils.Addr(false),
		Sections: map[string]sectionConfig{
			// "section-to-delete" - deleted entirely
			"section-to-rename": {
				Name: "Renamed Section",
				Controls: map[string]controlConfig{
					"control-to-rename": {
						Name:        "Renamed Control",
						Description: "Control that will be renamed",
						Rules:       []string{},
					},
					// "control-to-delete-2" - deleted
					"new-control": {
						Name:        "New Control",
						Description: "New control added during mixed operations",
						Rules:       []string{},
					},
				},
			},
			"new-section": {
				Name: "New Section",
				Controls: map[string]controlConfig{
					"new-section-control": {
						Name:        "New Section Control",
						Description: "Control in new section",
						Rules:       []string{},
					},
				},
			},
		},
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + initialConfig.String(),
				Check:  initialConfig.TestChecks(),
			},
			{
				Config: acctest.ProviderConfig + mixedOperationsConfig.String(),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(
							customFrameworkResourceName,
							plancheck.ResourceActionUpdate,
						),
						// Verify that renamed control maintains its ID (proving update vs delete+recreate)
						plancheck.ExpectKnownValue(
							customFrameworkResourceName,
							tfjsonpath.New("sections").AtMapKey("section-to-rename").AtMapKey("controls").AtMapKey("control-to-rename").AtMapKey("id"),
							knownvalue.NotNull(),
						),
					},
				},
				Check: mixedOperationsConfig.TestChecks(),
			},
		},
	})
}

func TestAccCloudComplianceCustomFrameworkResource_EmptySectionsValidation(t *testing.T) {
	emptyConfig := completeFrameworkConfig{
		Name:        "Test Framework Empty Sections Validation",
		Description: "Framework to test empty sections validation",
		Sections: map[string]sectionConfig{
			"empty-section": {
				Name:     "Empty Section",
				Controls: map[string]controlConfig{}, // Empty controls map
			},
		},
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      acctest.ProviderConfig + emptyConfig.String(),
				ExpectError: regexp.MustCompile("Inappropriate value for attribute \"sections\"|attribute \"controls\" is required"),
			},
		},
	})
}

func _TestAccCloudComplianceCustomFrameworkResource_ActiveValidation(t *testing.T) {
	initialConfig := minimalFrameworkConfig{
		Name:        "Test Framework Active Validation",
		Description: "Framework to test active field validation",
	}

	activeConfig := minimalFrameworkConfig{
		Name:        "Test Framework Active Validation",
		Description: "Framework to test active field validation",
		Active:      utils.Addr(true),
	}

	deactivateConfig := minimalFrameworkConfig{
		Name:        "Test Framework Active Validation",
		Description: "Framework to test active field validation",
		Active:      utils.Addr(false),
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create framework (defaults to active = false)
			{
				Config: acctest.ProviderConfig + initialConfig.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(customFrameworkResourceName, "active", "false"),
				),
			},
			// Step 2: Update to active = true
			{
				Config: acctest.ProviderConfig + activeConfig.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(customFrameworkResourceName, "active", "true"),
				),
			},
			// Step 3: Try to change active from true back to false - should fail
			{
				Config:      acctest.ProviderConfig + deactivateConfig.String(),
				ExpectError: regexp.MustCompile("The active field cannot be changed from true to false"),
			},
		},
	})
}
