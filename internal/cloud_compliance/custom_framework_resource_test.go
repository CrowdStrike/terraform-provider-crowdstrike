package cloudcompliance_test

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const (
	customFrameworkResourceName = "crowdstrike_cloud_compliance_custom_framework.test"
	awsAPIGatewayFilter         = "rule_service:'API Gateway'+rule_provider:'AWS'+rule_domain:'CSPM'+rule_subdomain:'IOM'"
)

// Helper function to generate a configuration that fetches AWS rules and returns specific rule IDs
func getAWSRulesConfig() string {
	return fmt.Sprintf(`
data "crowdstrike_cloud_security_rules" "aws_rules" {
  fql = "%s"
}

locals {
  # Convert set to list and check length once
  rules_list = tolist(data.crowdstrike_cloud_security_rules.aws_rules.rules)
  has_enough_rules = length(local.rules_list) >= 4

  # Predefined rule sets for different test scenarios
  rule_set_empty = toset([])

  rule_set_two = local.has_enough_rules ? toset([
    local.rules_list[0].id,
    local.rules_list[1].id
  ]) : toset([])

  rule_set_single = local.has_enough_rules ? toset([
    local.rules_list[2].id
  ]) : toset([])

  rule_set_mixed = local.has_enough_rules ? toset([
    local.rules_list[0].id,
    local.rules_list[3].id
  ]) : toset([])

  rule_set_alt_single = local.has_enough_rules ? toset([
    local.rules_list[3].id
  ]) : toset([])
}
`, awsAPIGatewayFilter)
}

// minimalFrameworkConfig represents a bare minimum custom compliance framework
type minimalFrameworkConfig struct {
	Name        string
	Description string
}

// completeFrameworkConfig represents a complete custom framework with sections, controls, and rules
type completeFrameworkConfig struct {
	Name        string
	Description string
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
	Rules       string // single string for local var injection from data source
}

// String generates Terraform configuration from minimalFrameworkConfig
func (config *minimalFrameworkConfig) String() string {
	descriptionConfig := ""
	if config.Description != "" {
		descriptionConfig = fmt.Sprintf("\n  description = %q", config.Description)
	}

	return fmt.Sprintf(`
resource "crowdstrike_cloud_compliance_custom_framework" "test" {
  name = %q%s
}
`, config.Name, descriptionConfig)
}

// String generates Terraform configuration from completeFrameworkConfig
func (config *completeFrameworkConfig) String() string {
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

					if control.Rules != "" {
						sectionsConfig += fmt.Sprintf("          rules = %s\n", control.Rules)
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

	return fmt.Sprintf(`%s

resource "crowdstrike_cloud_compliance_custom_framework" "test" {
  name = %q
  description = %q%s
}
`, getAWSRulesConfig(), config.Name, config.Description, sectionsConfig)
}

// TestChecks generates test checks for the completeFrameworkConfig
func (config *completeFrameworkConfig) TestChecks() resource.TestCheckFunc {
	var checks []resource.TestCheckFunc

	checks = append(checks,
		resource.TestCheckResourceAttrSet(customFrameworkResourceName, "id"),
		resource.TestCheckResourceAttr(customFrameworkResourceName, "name", config.Name),
		resource.TestCheckResourceAttr(customFrameworkResourceName, "description", config.Description),
	)

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

					// Check rules within each control - since we use dynamic rule sets, just verify rules exist
					if control.Rules != "" && control.Rules != "local.rule_set_empty" {
						checks = append(checks, resource.TestCheckResourceAttrSet(customFrameworkResourceName, fmt.Sprintf("%s.rules.#", controlPath)))
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
			},
		},
		{
			name: "updated_framework",
			config: minimalFrameworkConfig{
				Name:        "Test Framework Basic Updated",
				Description: "This is an updated test framework description",
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
			},
		},
		{
			name: "updated_name",
			config: minimalFrameworkConfig{
				Name:        "Test Framework Updates Modified Name",
				Description: "Initial description for update testing",
			},
		},
		{
			name: "updated_description",
			config: minimalFrameworkConfig{
				Name:        "Test Framework Updates Modified Name",
				Description: "Updated description after name change",
			},
		},
		{
			name: "updated_all_fields",
			config: minimalFrameworkConfig{
				Name:        "Test Framework Final State",
				Description: "Final updated description",
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
	minimalConfig := minimalFrameworkConfig{
		Name:        "Test Framework Minimal",
		Description: "Minimal test framework description",
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + minimalConfig.String(),
				Check:  minimalConfig.TestChecks(),
			},
		},
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
		Sections: map[string]sectionConfig{
			"section-1": {
				Name: "Section 1",
				Controls: map[string]controlConfig{
					"control-1a": {
						Name:        "Control 1a",
						Description: "This is the first control",
						Rules:       "local.rule_set_two",
					},
					"control-1b": {
						Name:        "Control 1b",
						Description: "This is another control in section 1",
						Rules:       "local.rule_set_single",
					},
				},
			},
			"section-2": {
				Name: "Section 2",
				Controls: map[string]controlConfig{
					"control-2a": {
						Name:        "Control 2a",
						Description: "This is the second control",
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
				Sections: map[string]sectionConfig{
					"test-section": {
						Name: "Test Section",
						Controls: map[string]controlConfig{
							"control-with-rules": {
								Name:        "Control With Rules",
								Description: "Control that has rules assigned",
								Rules:       "local.rule_set_two",
							},
							"control-without-rules": {
								Name:        "Control Without Rules",
								Description: "Control with no rules",
								Rules:       "local.rule_set_empty",
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
				Sections: map[string]sectionConfig{
					"test-section": {
						Name: "Test Section",
						Controls: map[string]controlConfig{
							"control-with-rules": {
								Name:        "Control With Rules",
								Description: "Control that has rules assigned",
								Rules:       "local.rule_set_mixed", // Modified rules
							},
							"control-without-rules": {
								Name:        "Control Without Rules",
								Description: "Control with no rules",
								Rules:       "local.rule_set_single", // Added rules
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
				Sections: map[string]sectionConfig{
					"test-section": {
						Name: "Test Section",
						Controls: map[string]controlConfig{
							"control-with-rules": {
								Name:        "Control With Rules",
								Description: "Control that has rules assigned",
								// Rules removed
							},
							"control-without-rules": {
								Name:        "Control Without Rules",
								Description: "Control with no rules",
								// Rules removed
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
		Sections: map[string]sectionConfig{
			"section-1": {
				Name: "Original Section",
				Controls: map[string]controlConfig{
					"test-control": {
						Name:        "Test Control",
						Description: "Test control description",
					},
				},
			},
		},
	}

	// Rename just the section, keeping control the same
	renamedConfig := completeFrameworkConfig{
		Name:        frameworkName,
		Description: "Framework to test simple section renaming",
		Sections: map[string]sectionConfig{
			"section-1": {
				Name: "Renamed Section",
				Controls: map[string]controlConfig{
					"test-control": {
						Name:        "Test Control",
						Description: "Test control description",
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
		Sections: map[string]sectionConfig{
			"section-a": {
				Name: "Original Section A",
				Controls: map[string]controlConfig{
					"control-a1": {
						Name:        "Original Control A1",
						Description: "Original control description A1",
					},
					"control-a2": {
						Name:        "Original Control A2",
						Description: "Original control description A2",
					},
				},
			},
			"section-b": {
				Name: "Original Section B",
				Controls: map[string]controlConfig{
					"control-b1": {
						Name:        "Original Control B1",
						Description: "Original control description B1",
					},
				},
			},
		},
	}

	// Test 3: Rename both section and control simultaneously
	renamedConfig := completeFrameworkConfig{
		Name:        "Test Framework Comprehensive Renaming",
		Description: "Framework to test comprehensive renaming operations",
		Sections: map[string]sectionConfig{
			"section-a": {
				Name: "Renamed Section A",
				Controls: map[string]controlConfig{
					"control-a1": {
						Name:        "Renamed Control A1",
						Description: "Original control description A1",
					},
					"control-a2": {
						Name:        "Original Control A2",
						Description: "Original control description A2",
					},
				},
			},
			"section-b": {
				Name: "Original Section B",
				Controls: map[string]controlConfig{
					"control-b1": {
						Name:        "Renamed Control B1",
						Description: "Original control description B1",
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
		Sections: map[string]sectionConfig{
			"section-1": {
				Name: "Section 1",
				Controls: map[string]controlConfig{
					"control-1.1": {
						Name:        "Control 1.1",
						Description: "Control 1.1 description",
						Rules:       "local.rule_set_two",
					},
					"control-1.2": {
						Name:        "Control 1.2",
						Description: "Control 1.2 description",
						Rules:       "local.rule_set_empty",
					},
				},
			},
		},
	}

	// Test 2: Add new section, and controls to existing section + delete control
	addSectionAndControlsConfig := completeFrameworkConfig{
		Name:        "Test Framework Comprehensive CRUD",
		Description: "Framework to test comprehensive CRUD operations",
		Sections: map[string]sectionConfig{
			"section-1": {
				Name: "Section 1",
				Controls: map[string]controlConfig{
					// deleted control-1.1
					"control-1.2": {
						Name:        "Control 1.2",
						Description: "Control 1.2 description",
						Rules:       "local.rule_set_two",
					},
					"control-1.3": {
						Name:        "Control 1.3",
						Description: "Control 1.3 description",
						Rules:       "local.rule_set_empty",
					},
				},
			},
			"section-2": {
				Name: "Section 2",
				Controls: map[string]controlConfig{
					"control-2.1": {
						Name:        "New Control 2.1",
						Description: "New control 2.1 description",
						Rules:       "local.rule_set_empty",
					},
					"control-2.2": {
						Name:        "New Control 2.2",
						Description: "New control 2.2 description",
						Rules:       "local.rule_set_alt_single",
					},
				},
			},
		},
	}

	// Test 3: Delete controls and sections
	deleteConfig := completeFrameworkConfig{
		Name:        "Test Framework Comprehensive CRUD",
		Description: "Framework to test comprehensive CRUD operations",
		Sections: map[string]sectionConfig{
			// section-1 deleted entirely
			"section-2": {
				Name: "Section 2",
				Controls: map[string]controlConfig{
					// control-2.1 deleted
					"control-2.2": {
						Name:        "New Control 2.2",
						Description: "New control 2.2 description",
						Rules:       "local.rule_set_alt_single",
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
		Sections: map[string]sectionConfig{
			"section-to-delete": {
				Name: "Section To Delete",
				Controls: map[string]controlConfig{
					"control-to-delete": {
						Name:        "Control To Delete",
						Description: "Control that will be deleted",
					},
				},
			},
			"section-to-rename": {
				Name: "Section To Rename",
				Controls: map[string]controlConfig{
					"control-to-rename": {
						Name:        "Control To Rename",
						Description: "Control that will be renamed",
					},
					"control-to-delete-2": {
						Name:        "Another Control To Delete",
						Description: "Another control that will be deleted",
					},
				},
			},
		},
	}

	// Test: Delete one section while renaming another, and delete/rename controls
	mixedOperationsConfig := completeFrameworkConfig{
		Name:        "Test Framework Mixed Operations",
		Description: "Framework to test mixed operations",
		Sections: map[string]sectionConfig{
			// "section-to-delete" - deleted entirely
			"section-to-rename": {
				Name: "Renamed Section",
				Controls: map[string]controlConfig{
					"control-to-rename": {
						Name:        "Renamed Control",
						Description: "Control that will be renamed",
						Rules:       "local.rule_set_single",
					},
					// "control-to-delete-2" - deleted
					"new-control": {
						Name:        "New Control",
						Description: "New control added during mixed operations",
						Rules:       "local.rule_set_mixed",
					},
				},
			},
			"new-section": {
				Name: "New Section",
				Controls: map[string]controlConfig{
					"new-section-control": {
						Name:        "New Section Control",
						Description: "Control in new section",
						Rules:       "local.rule_set_empty",
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
