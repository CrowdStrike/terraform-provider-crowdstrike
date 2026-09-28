package fusionsoar_test

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	fusionsoar "github.com/crowdstrike/terraform-provider-crowdstrike/internal/fusion_soar"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/testconfig"
	tfjson "github.com/hashicorp/terraform-json"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"gopkg.in/yaml.v3"
)

const resourceName = "crowdstrike_fusion_soar_workflow.test"

// sleepActivityID is the built-in Sleep action, which needs no plugin,
// subscription, or tenant-specific configuration.
const sleepActivityID = "4f1af1ae4c13dc1e3bcd725f8dc0f63b"

func TestAccFusionWorkflow_basic(t *testing.T) {
	rName := acctest.RandomResourceName()
	definition := testAccFusionWorkflowDefinition_basic(rName, "1m")

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFusionWorkflowDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccFusionWorkflowConfig_basic(definition),
				ConfigStateChecks: []statecheck.StateCheck{
					testAccCheckFusionWorkflowRemote(rName, false),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					// The configured text is kept even though the API returns it reformatted.
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("definition"), knownvalue.StringExact(definition)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
				},
			},
			testAccFusionWorkflowImportStep(),
		},
	})
}

func TestAccFusionWorkflow_update(t *testing.T) {
	rName := acctest.RandomResourceName()
	renamed := rName + "-renamed"
	full := testAccFusionWorkflowDefinition_full(rName)
	updated := testAccFusionWorkflowDefinition_basic(renamed, "2m")
	basic := testAccFusionWorkflowDefinition_basic(rName, "1m")

	idUnchanged := statecheck.CompareValue(compare.ValuesSame())

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFusionWorkflowDestroy,
		Steps: []resource.TestStep{
			{
				// Enabled at create, with a description and trigger inputs.
				Config: testAccFusionWorkflowConfig_enabled(full),
				ConfigStateChecks: []statecheck.StateCheck{
					testAccCheckFusionWorkflowRemote(rName, true),
					idUnchanged.AddStateValue(resourceName, tfjsonpath.New("id")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("definition"), knownvalue.StringExact(full)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
				},
			},
			testAccFusionWorkflowImportStep(),
			{
				// Rename, change an action property, and drop the description and
				// trigger inputs. All in place.
				Config: testAccFusionWorkflowConfig_enabled(updated),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					testAccCheckFusionWorkflowRemote(renamed, true),
					idUnchanged.AddStateValue(resourceName, tfjsonpath.New("id")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("definition"), knownvalue.StringExact(updated)),
				},
			},
			{
				// The same definition written with yamlencode: the content is
				// unchanged, and the configured text is kept in state.
				Config: testAccFusionWorkflowConfig_yamlencode(renamed, "2m"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					testAccCheckFusionWorkflowRemote(renamed, true),
					idUnchanged.AddStateValue(resourceName, tfjsonpath.New("id")),
				},
			},
			{
				// enabled removed from config returns to its default.
				Config: testAccFusionWorkflowConfig_basic(basic),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					testAccCheckFusionWorkflowRemote(rName, false),
					idUnchanged.AddStateValue(resourceName, tfjsonpath.New("id")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("definition"), knownvalue.StringExact(basic)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
				},
			},
		},
	})
}

func TestAccFusionWorkflow_drift(t *testing.T) {
	rName := acctest.RandomResourceName()
	definition := testAccFusionWorkflowDefinition_basic(rName, "1m")
	var workflowID string

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFusionWorkflowDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccFusionWorkflowConfig_enabled(definition),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.StringFunc(func(v string) error {
						workflowID = v
						return nil
					})),
				},
			},
			{
				// A configured property changed and the workflow disabled outside
				// Terraform: refresh must notice both.
				PreConfig: func() {
					testAccChangeFusionWorkflowOutOfBand(t, workflowID, testAccFusionWorkflowDefinition_basic(rName, "5m"))
				},
				RefreshState: true,
				RefreshPlanChecks: resource.RefreshPlanChecks{
					PostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
				},
				ExpectNonEmptyPlan: true,
			},
			{
				// Applying converges; the empty final plan proves the API holds
				// the configured sleep_time again.
				Config: testAccFusionWorkflowConfig_enabled(definition),
				ConfigStateChecks: []statecheck.StateCheck{
					testAccCheckFusionWorkflowRemote(rName, true),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("definition"), knownvalue.StringExact(definition)),
				},
			},
		},
	})
}

func TestAccFusionWorkflow_disappears(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFusionWorkflowDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccFusionWorkflowConfig_basic(testAccFusionWorkflowDefinition_basic(rName, "1m")),
				ConfigStateChecks: []statecheck.StateCheck{
					testAccCheckFusionWorkflowRemote(rName, false),
					testAccCheckFusionWorkflowDisappears(),
				},
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccFusionWorkflow_apiOwnedFields covers the values the API replaces with
// its own: the trigger's name and each action's default_name. The apply must
// succeed and keep the configured text, and the refresh after it must be clean.
func TestAccFusionWorkflow_apiOwnedFields(t *testing.T) {
	rName := acctest.RandomResourceName()
	definition := testAccFusionWorkflowDefinition_apiOwnedFields(rName)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFusionWorkflowDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccFusionWorkflowConfig_basic(definition),
				ConfigStateChecks: []statecheck.StateCheck{
					testAccCheckFusionWorkflowRemote(rName, false),
					testAccCheckFusionWorkflowStoredValues(map[string]string{
						"trigger.name":               "Scheduled",
						"actions.Sleep.default_name": "Sleep",
					}),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("definition"), knownvalue.StringExact(definition)),
				},
			},
		},
	})
}

// TestAccFusionWorkflow_invalidYAML covers a definition that is not YAML: the
// provider passes it through and the apply fails with the API's error.
func TestAccFusionWorkflow_invalidYAML(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFusionWorkflowDestroy,
		Steps: []resource.TestStep{
			{
				Config:      testAccFusionWorkflowConfig_basic("name: [unclosed"),
				ExpectError: regexp.MustCompile(`import\s+file\s+must\s+be\s+a\s+valid\s+YAML\s+file`),
			},
		},
	})
}

// TestAccFusionWorkflow_unknownKey covers the API silently dropping a key it
// does not recognize: the apply must fail and name the dropped key rather than
// report an inconsistent result.
func TestAccFusionWorkflow_unknownKey(t *testing.T) {
	rName := acctest.RandomResourceName()
	definition := testAccFusionWorkflowDefinition_basic(rName, "1m") + "not_a_workflow_field: value\n"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFusionWorkflowDestroy,
		Steps: []resource.TestStep{
			{
				Config:      testAccFusionWorkflowConfig_basic(definition),
				ExpectError: regexp.MustCompile("(?s)definition not applied.*`not_a_workflow_field`"),
			},
		},
	})
}

// TestAccFusionWorkflow_enableInvalid covers enabling a workflow the API saved
// with validation errors: the enable call reports why on a 200 response.
func TestAccFusionWorkflow_enableInvalid(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFusionWorkflowDestroy,
		Steps: []resource.TestStep{
			{
				Config:      testAccFusionWorkflowConfig_enabled(testAccFusionWorkflowDefinition_missingProperties(rName)),
				ExpectError: regexp.MustCompile(`A value is required for the property\s+"sleep_time"`),
			},
		},
	})
}

// TestAccFusionWorkflow_validationErrors covers a disabled workflow the API
// saves with validation errors, which applies with a warning, and then
// enabling it, which fails.
func TestAccFusionWorkflow_validationErrors(t *testing.T) {
	rName := acctest.RandomResourceName()
	definition := testAccFusionWorkflowDefinition_missingProperties(rName)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFusionWorkflowDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccFusionWorkflowConfig_basic(definition),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("definition"), knownvalue.StringExact(definition)),
					testAccCheckFusionWorkflowRemote(rName, false),
				},
			},
			{
				Config:      testAccFusionWorkflowConfig_enabled(definition),
				ExpectError: regexp.MustCompile(`A value is required for the property\s+"sleep_time"`),
			},
		},
	})
}

// TestAccFusionWorkflow_updateUnknownActivity covers an update rejected because
// the definition references an activity that does not exist. The API answers
// 404, which must surface as a failed update with the API's message rather
// than as a missing workflow.
func TestAccFusionWorkflow_updateUnknownActivity(t *testing.T) {
	rName := acctest.RandomResourceName()
	unknownActivity := strings.Replace(
		testAccFusionWorkflowDefinition_basic(rName, "1m"),
		sleepActivityID,
		"ffffffffffffffffffffffffffffffff",
		1,
	)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFusionWorkflowDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccFusionWorkflowConfig_basic(testAccFusionWorkflowDefinition_basic(rName, "1m")),
			},
			{
				Config:      testAccFusionWorkflowConfig_basic(unknownActivity),
				ExpectError: regexp.MustCompile(`(?s)Failed to update.*activity not found for id: "ffffffffffffffffffffffffffffffff"`),
			},
		},
	})
}

// testAccFusionWorkflowImportStep imports the workflow with an import block.
// Import populates definition from the API's export, which reformats the YAML
// and adds keys such as default_name, so the plan after import updates
// definition in place. The plan check asserts that this is the only change
// and that the imported definition contains every configured value.
func testAccFusionWorkflowImportStep() resource.TestStep {
	return resource.TestStep{
		ResourceName:       resourceName,
		ImportState:        true,
		ImportStateKind:    resource.ImportBlockWithID,
		ExpectNonEmptyPlan: true,
		ImportPlanChecks: resource.ImportPlanChecks{
			PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
				importedDefinitionCheck{},
			},
		},
	}
}

type importedDefinitionCheck struct{}

func (c importedDefinitionCheck) CheckPlan(_ context.Context, req plancheck.CheckPlanRequest, resp *plancheck.CheckPlanResponse) {
	change, err := resourceChangeAtAddress(req.Plan, resourceName)
	if err != nil {
		resp.Error = err
		return
	}

	before, ok := change.Before.(map[string]any)
	if !ok {
		resp.Error = fmt.Errorf("%s: imported state is %T, want an object", resourceName, change.Before)
		return
	}
	after, ok := change.After.(map[string]any)
	if !ok {
		resp.Error = fmt.Errorf("%s: planned state is %T, want an object", resourceName, change.After)
		return
	}

	if before["enabled"] != after["enabled"] {
		resp.Error = fmt.Errorf("%s: imported enabled = %v, configured %v", resourceName, before["enabled"], after["enabled"])
		return
	}

	imported, _ := before["definition"].(string)
	configured, _ := after["definition"].(string)
	missing, _, err := fusionsoar.DefinitionDiff(configured, imported)
	if err != nil {
		resp.Error = fmt.Errorf("%s: comparing definitions: %w", resourceName, err)
		return
	}
	if missing != "" {
		resp.Error = fmt.Errorf("%s: imported definition differs from the configuration at %s:\n%s", resourceName, missing, imported)
	}
}

func resourceChangeAtAddress(plan *tfjson.Plan, address string) (*tfjson.Change, error) {
	if plan == nil {
		return nil, fmt.Errorf("no plan available")
	}
	for _, rc := range plan.ResourceChanges {
		if rc.Address == address && rc.Change != nil {
			return rc.Change, nil
		}
	}
	return nil, fmt.Errorf("no planned change for %s", address)
}

// fusionWorkflowCheck runs fn with the workflow ID from state.
func fusionWorkflowCheck(fn func(ctx context.Context, id string) error) statecheck.StateCheck {
	return statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.StringFunc(func(id string) error {
		return fn(context.Background(), id)
	}))
}

// testAccCheckFusionWorkflowRemote asserts the workflow exists in the API with
// the given name and enabled state.
func testAccCheckFusionWorkflowRemote(name string, enabled bool) statecheck.StateCheck {
	return fusionWorkflowCheck(func(ctx context.Context, id string) error {
		res, err := fusionsoar.QueryDefinitions(ctx, testconfig.GetTestClient(), fmt.Sprintf("id:'%s'", id))
		if err != nil {
			return fmt.Errorf("querying workflow %s: %w", id, err)
		}
		if len(res.Resources) != 1 {
			return fmt.Errorf("workflow %s not found via API", id)
		}

		workflow := res.Resources[0]
		if workflow.Name != name {
			return fmt.Errorf("workflow %s name = %q, want %q", id, workflow.Name, name)
		}
		if workflow.Enabled != enabled {
			return fmt.Errorf("workflow %s enabled = %t, want %t", id, workflow.Enabled, enabled)
		}
		return nil
	})
}

// testAccCheckFusionWorkflowStoredValues asserts values in the definition the
// API stores, keyed by dotted path.
func testAccCheckFusionWorkflowStoredValues(want map[string]string) statecheck.StateCheck {
	return fusionWorkflowCheck(func(ctx context.Context, id string) error {
		stored, err := fusionsoar.StoredDefinition(ctx, testconfig.GetTestClient(), id)
		if err != nil {
			return err
		}

		var doc map[string]any
		if err := yaml.Unmarshal([]byte(stored), &doc); err != nil {
			return fmt.Errorf("stored definition of workflow %s is not YAML: %w", id, err)
		}

		for path, value := range want {
			var got any = doc
			for _, key := range strings.Split(path, ".") {
				m, _ := got.(map[string]any)
				got = m[key]
			}
			if got != value {
				return fmt.Errorf("workflow %s stored %s = %v, want %q:\n%s", id, path, got, value, stored)
			}
		}
		return nil
	})
}

func testAccCheckFusionWorkflowDisappears() statecheck.StateCheck {
	return fusionWorkflowCheck(func(ctx context.Context, id string) error {
		if _, err := fusionsoar.DeleteWorkflow(ctx, testconfig.GetTestClient(), id); err != nil {
			return fmt.Errorf("deleting workflow %s out of band: %w", id, err)
		}
		return nil
	})
}

// testAccChangeFusionWorkflowOutOfBand replaces the workflow's definition and
// disables it through the API directly.
func testAccChangeFusionWorkflowOutOfBand(t *testing.T, id, definition string) {
	t.Helper()

	if err := fusionsoar.ReplaceDefinitionAndDisable(context.Background(), testconfig.GetTestClient(), id, definition); err != nil {
		t.Fatalf("changing workflow %s out of band: %s", id, err)
	}
}

func testAccCheckFusionWorkflowDestroy(s *terraform.State) error {
	ctx := context.Background()

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "crowdstrike_fusion_soar_workflow" {
			continue
		}

		// The combined endpoint returns an empty result, not a 404, for a
		// deleted workflow, so an error here means the check itself failed.
		res, err := fusionsoar.QueryDefinitions(ctx, testconfig.GetTestClient(), fmt.Sprintf("id:'%s'", rs.Primary.ID))
		if err != nil {
			return fmt.Errorf("checking workflow %s: %w", rs.Primary.ID, err)
		}
		if len(res.Resources) > 0 {
			return fmt.Errorf("workflow %s still exists", rs.Primary.ID)
		}
	}

	return nil
}

// testAccFusionWorkflowDefinition_basic is an on-demand workflow with a single
// Sleep action.
func testAccFusionWorkflowDefinition_basic(name, sleepTime string) string {
	return fmt.Sprintf(`name: %[1]s
trigger:
  next:
    - Sleep
  name: On demand
  type: On demand
actions:
  Sleep:
    id: %[2]s
    properties:
      sleep_time: %[3]s
    version_constraint: ~1
`, name, sleepActivityID, sleepTime)
}

// testAccFusionWorkflowDefinition_apiOwnedFields sets values the API replaces:
// a scheduled trigger named with an older label, which the API stores as
// "Scheduled", and a default_name the API resets to the activity's name.
func testAccFusionWorkflowDefinition_apiOwnedFields(name string) string {
	return fmt.Sprintf(`name: %[1]s
trigger:
  next:
    - Sleep
  event: Schedule
  name: Scheduled workflow
  schedule:
    time_cycle: 20 17 * * 1
    start_date: ''
    end_date: ''
    tz: America/Chicago
    skip_concurrent: false
  type: Scheduled
actions:
  Sleep:
    id: %[2]s
    default_name: not the activity name
    properties:
      sleep_time: 1m
    version_constraint: ~1
`, name, sleepActivityID)
}

// testAccFusionWorkflowDefinition_missingProperties omits the Sleep action's
// required sleep_time property. The API saves it but refuses to enable it.
func testAccFusionWorkflowDefinition_missingProperties(name string) string {
	return fmt.Sprintf(`name: %[1]s
trigger:
  next:
    - Sleep
  name: On demand
  type: On demand
actions:
  Sleep:
    id: %[2]s
    version_constraint: ~1
`, name, sleepActivityID)
}

// testAccFusionWorkflowDefinition_full adds a description and trigger inputs,
// which the API returns as an object the generated gofalcon model cannot decode.
func testAccFusionWorkflowDefinition_full(name string) string {
	return fmt.Sprintf(`name: %[1]s
description: managed by terraform acceptance tests
trigger:
  next:
    - Sleep
  name: On demand
  type: On demand
  parameters:
    type: object
    properties:
      reason:
        type: string
    required:
      - reason
actions:
  Sleep:
    id: %[2]s
    properties:
      sleep_time: 1m
    version_constraint: ~1
`, name, sleepActivityID)
}

func testAccFusionWorkflowConfig_basic(definition string) string {
	return fmt.Sprintf(`
resource "crowdstrike_fusion_soar_workflow" "test" {
  definition = %[1]q
}
`, definition)
}

func testAccFusionWorkflowConfig_enabled(definition string) string {
	return fmt.Sprintf(`
resource "crowdstrike_fusion_soar_workflow" "test" {
  definition = %[1]q
  enabled    = true
}
`, definition)
}

// testAccFusionWorkflowConfig_yamlencode builds the same workflow as
// testAccFusionWorkflowDefinition_basic with yamlencode, enabled.
func testAccFusionWorkflowConfig_yamlencode(name, sleepTime string) string {
	return fmt.Sprintf(`
resource "crowdstrike_fusion_soar_workflow" "test" {
  enabled = true
  definition = yamlencode({
    name = %[1]q
    trigger = {
      next = ["Sleep"]
      name = "On demand"
      type = "On demand"
    }
    actions = {
      Sleep = {
        id                 = %[2]q
        properties         = { sleep_time = %[3]q }
        version_constraint = "~1"
      }
    }
  })
}
`, name, sleepActivityID, sleepTime)
}
