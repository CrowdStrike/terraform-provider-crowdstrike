package correlationrules_test

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const (
	resourceName = "crowdstrike_correlation_rule.test"
	baseFilter   = `#repo="base_sensor" #event_simpleName=ProcessRollup2`
)

var (
	futureStartOn = time.Now().UTC().Add(1 * time.Hour).Format(time.RFC3339)
	stopOnEarly   = time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339)
	stopOnLate    = time.Now().UTC().Add(60 * 24 * time.Hour).Format(time.RFC3339)
)

func TestAccCorrelationRuleResource_basic(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCorrelationRuleConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cid"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.StringExact("medium")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("status"), knownvalue.StringExact("inactive")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("comment"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("mitre_attack"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("search").AtMapKey("filter"), knownvalue.StringExact(baseFilter)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("search").AtMapKey("lookback"), knownvalue.StringExact("1h0m")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("search").AtMapKey("trigger_mode"), knownvalue.StringExact("verbose")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("search").AtMapKey("create_case"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("search").AtMapKey("use_ingest_time"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("search").AtMapKey("execution_mode"), knownvalue.StringExact("scheduled")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("search").AtMapKey("case_template_id"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("schedule").AtMapKey("interval"), knownvalue.StringExact("1h0m")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("schedule").AtMapKey("start_on"), knownvalue.StringExact(futureStartOn)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("schedule").AtMapKey("stop_on"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("notifications"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.ObjectExact(map[string]knownvalue.Check{
							"type":         knownvalue.StringExact("email"),
							"is_guardrail": knownvalue.Bool(true),
							"recipients": knownvalue.ListExact([]knownvalue.Check{
								knownvalue.StringExact("acc-tests@crowdstrike.com"),
							}),
							"plugin_id": knownvalue.Null(),
							"config_id": knownvalue.Null(),
							"severity":  knownvalue.Null(),
						}),
					})),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccCorrelationRuleResource_update(t *testing.T) {
	rName := acctest.RandomResourceName()
	updatedName := rName + "-updated"

	basicChecks := []statecheck.StateCheck{
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cid"), knownvalue.NotNull()),
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.StringExact("medium")),
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("status"), knownvalue.StringExact("inactive")),
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.Null()),
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("comment"), knownvalue.Null()),
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("mitre_attack"), knownvalue.Null()),
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("search").AtMapKey("filter"), knownvalue.StringExact(baseFilter)),
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("search").AtMapKey("lookback"), knownvalue.StringExact("1h0m")),
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("search").AtMapKey("trigger_mode"), knownvalue.StringExact("verbose")),
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("search").AtMapKey("create_case"), knownvalue.Bool(false)),
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("search").AtMapKey("use_ingest_time"), knownvalue.Bool(false)),
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("search").AtMapKey("execution_mode"), knownvalue.StringExact("scheduled")),
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("search").AtMapKey("case_template_id"), knownvalue.Null()),
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("schedule").AtMapKey("interval"), knownvalue.StringExact("1h0m")),
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("schedule").AtMapKey("start_on"), knownvalue.StringExact(futureStartOn)),
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("schedule").AtMapKey("stop_on"), knownvalue.Null()),
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("notifications"), knownvalue.SetExact([]knownvalue.Check{
			knownvalue.ObjectExact(map[string]knownvalue.Check{
				"type":         knownvalue.StringExact("email"),
				"is_guardrail": knownvalue.Bool(true),
				"recipients": knownvalue.ListExact([]knownvalue.Check{
					knownvalue.StringExact("acc-tests@crowdstrike.com"),
				}),
				"plugin_id": knownvalue.Null(),
				"config_id": knownvalue.Null(),
				"severity":  knownvalue.Null(),
			}),
		})),
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:            testAccCorrelationRuleConfig_basic(rName),
				ConfigStateChecks: basicChecks,
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccCorrelationRuleConfig_full(updatedName, "high", "active"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cid"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(updatedName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.StringExact("high")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("status"), knownvalue.StringExact("active")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("updated description")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("comment"), knownvalue.StringExact("updated comment")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("mitre_attack"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("mitre_attack").AtSliceIndex(0).AtMapKey("tactic_id"), knownvalue.StringExact("TA0001")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("mitre_attack").AtSliceIndex(0).AtMapKey("technique_id"), knownvalue.StringExact("T1078")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("search").AtMapKey("filter"), knownvalue.StringExact(baseFilter)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("search").AtMapKey("create_case"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("search").AtMapKey("use_ingest_time"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("search").AtMapKey("lookback"), knownvalue.StringExact("2h0m")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("search").AtMapKey("trigger_mode"), knownvalue.StringExact("summary")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("search").AtMapKey("execution_mode"), knownvalue.StringExact("scheduled")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("search").AtMapKey("case_template_id"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("schedule").AtMapKey("interval"), knownvalue.StringExact("2h0m")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("schedule").AtMapKey("start_on"), knownvalue.StringExact(futureStartOn)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("schedule").AtMapKey("stop_on"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("notifications"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.ObjectExact(map[string]knownvalue.Check{
							"type":         knownvalue.StringExact("email"),
							"is_guardrail": knownvalue.Bool(true),
							"recipients": knownvalue.ListExact([]knownvalue.Check{
								knownvalue.StringExact("acc-tests@crowdstrike.com"),
							}),
							"plugin_id": knownvalue.Null(),
							"config_id": knownvalue.Null(),
							"severity":  knownvalue.StringExact("high"),
						}),
					})),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config:            testAccCorrelationRuleConfig_basic(rName),
				ConfigStateChecks: basicChecks,
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccCorrelationRuleResource_mitreAttack(t *testing.T) {
	rName := acctest.RandomResourceName()

	entries := []mitreEntry{
		{tacticID: "TA0001", techniqueID: "T1078"},
		{tacticID: "TA0004", techniqueID: "T1548"},
	}

	mitreChecks := func(severity string) []statecheck.StateCheck {
		return []statecheck.StateCheck{
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.StringExact(severity)),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("mitre_attack"), knownvalue.ListSizeExact(2)),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("mitre_attack").AtSliceIndex(0).AtMapKey("tactic_id"), knownvalue.StringExact("TA0001")),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("mitre_attack").AtSliceIndex(0).AtMapKey("technique_id"), knownvalue.StringExact("T1078")),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("mitre_attack").AtSliceIndex(1).AtMapKey("tactic_id"), knownvalue.StringExact("TA0004")),
			statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("mitre_attack").AtSliceIndex(1).AtMapKey("technique_id"), knownvalue.StringExact("T1548")),
		}
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:            testAccCorrelationRuleConfig_mitre(rName, "medium", entries),
				ConfigStateChecks: mitreChecks("medium"),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccCorrelationRuleConfig_mitre(rName, "high", entries),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
				},
				ConfigStateChecks: mitreChecks("high"),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccCorrelationRuleResource_notifications(t *testing.T) {
	rName := acctest.RandomResourceName()

	emailGuardrail := `
  notifications = [
    {
      type         = "email"
      is_guardrail = true
      recipients   = ["acc-tests@crowdstrike.com"]
    },
  ]
`
	slackGuardrail := `
  notifications = [
    {
      type         = "slack"
      is_guardrail = true
      plugin_id    = "slack.incoming_webhook"
      config_id    = "plg-xyz-999"
    },
  ]
`
	mixed := `
  notifications = [
    {
      type         = "email"
      is_guardrail = true
      recipients   = ["acc-tests@crowdstrike.com"]
    },
    {
      type      = "webhook"
      config_id = "cfg-abc-123"
    },
  ]
`

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCorrelationRuleConfig_notifications(rName, emailGuardrail),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("notifications"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.ObjectExact(map[string]knownvalue.Check{
							"type":         knownvalue.StringExact("email"),
							"is_guardrail": knownvalue.Bool(true),
							"recipients": knownvalue.ListExact([]knownvalue.Check{
								knownvalue.StringExact("acc-tests@crowdstrike.com"),
							}),
							"plugin_id": knownvalue.Null(),
							"config_id": knownvalue.Null(),
							"severity":  knownvalue.Null(),
						}),
					})),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccCorrelationRuleConfig_notifications(rName, slackGuardrail),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("notifications"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.ObjectExact(map[string]knownvalue.Check{
							"type":         knownvalue.StringExact("slack"),
							"is_guardrail": knownvalue.Bool(true),
							"recipients":   knownvalue.Null(),
							"plugin_id":    knownvalue.StringExact("slack.incoming_webhook"),
							"config_id":    knownvalue.StringExact("plg-xyz-999"),
							"severity":     knownvalue.Null(),
						}),
					})),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccCorrelationRuleConfig_notifications(rName, mixed),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("notifications"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.ObjectExact(map[string]knownvalue.Check{
							"type":         knownvalue.StringExact("email"),
							"is_guardrail": knownvalue.Bool(true),
							"recipients": knownvalue.ListExact([]knownvalue.Check{
								knownvalue.StringExact("acc-tests@crowdstrike.com"),
							}),
							"plugin_id": knownvalue.Null(),
							"config_id": knownvalue.Null(),
							"severity":  knownvalue.Null(),
						}),
						knownvalue.ObjectExact(map[string]knownvalue.Check{
							"type":         knownvalue.StringExact("webhook"),
							"is_guardrail": knownvalue.Bool(false),
							"recipients":   knownvalue.Null(),
							"plugin_id":    knownvalue.Null(),
							"config_id":    knownvalue.StringExact("cfg-abc-123"),
							"severity":     knownvalue.Null(),
						}),
					})),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccCorrelationRuleResource_stopOn(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCorrelationRuleConfig_stopOn(rName, stopOnEarly),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("schedule").AtMapKey("stop_on"), knownvalue.StringExact(stopOnEarly)),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccCorrelationRuleConfig_stopOn(rName, stopOnLate),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("schedule").AtMapKey("stop_on"), knownvalue.StringExact(stopOnLate)),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccCorrelationRuleConfig_basic(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("schedule").AtMapKey("stop_on"), knownvalue.Null()),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccCorrelationRuleResource_startOnInPast(t *testing.T) {
	rName := acctest.RandomResourceName()
	pastTime := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccCorrelationRuleConfig_startOn(rName, pastTime),
				ExpectError: regexp.MustCompile(`Invalid start_on time`),
				PlanOnly:    true,
			},
		},
	})
}

func TestAccCorrelationRuleResource_ValidatorErrors(t *testing.T) {
	rName := acctest.RandomResourceName()
	cid := "e82676877a894c809bc56d0a08568e54"

	emailWithPluginID := `
  notifications = [
    {
      type         = "email"
      is_guardrail = true
      recipients   = ["acc-tests@crowdstrike.com"]
      plugin_id    = "should-not-be-set"
    },
  ]
`
	slackMissingIntegration := `
  notifications = [
    {
      type         = "slack"
      is_guardrail = true
    },
  ]
`
	missingGuardrail := `
  notifications = [
    {
      type       = "email"
      recipients = ["acc-tests@crowdstrike.com"]
    },
  ]
`
	validEmail := `
  notifications = [
    {
      type         = "email"
      is_guardrail = true
      recipients   = ["acc-tests@crowdstrike.com"]
    },
  ]
`

	cases := []struct {
		name        string
		config      string
		expectError *regexp.Regexp
	}{
		{
			name:        "email with plugin_id",
			config:      testAccCorrelationRuleConfig_validatorCase(rName, cid, emailWithPluginID),
			expectError: regexp.MustCompile(`plugin_id must not be set when type is email`),
		},
		{
			name:        "slack missing plugin_id and config_id",
			config:      testAccCorrelationRuleConfig_validatorCase(rName, cid, slackMissingIntegration),
			expectError: regexp.MustCompile(`at least one of plugin_id or config_id is required when type is "slack"`),
		},
		{
			name:        "missing guardrail notification",
			config:      testAccCorrelationRuleConfig_validatorCase(rName, cid, missingGuardrail),
			expectError: regexp.MustCompile(`Missing guardrail notification`),
		},
		{
			name:        "cid malformed",
			config:      testAccCorrelationRuleConfig_validatorCase(rName, "not-a-cid", validEmail),
			expectError: regexp.MustCompile(`Invalid cid`),
		},
		{
			name:        "lookback exceeds maximum",
			config:      testAccCorrelationRuleConfig_durationCase(rName, "169h0m", "1h0m"),
			expectError: regexp.MustCompile(`lookback must be at most`),
		},
		{
			name:        "schedule interval below minimum",
			config:      testAccCorrelationRuleConfig_durationCase(rName, "1h0m", "1m0s"),
			expectError: regexp.MustCompile(`schedule interval must be at least`),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resource.ParallelTest(t, resource.TestCase{
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config:      tc.config,
						ExpectError: tc.expectError,
						PlanOnly:    true,
					},
				},
			})
		})
	}
}

type mitreEntry struct {
	tacticID    string
	techniqueID string
}

func testAccCorrelationRuleConfig_basic(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
data "crowdstrike_cid" "test" {}

resource "crowdstrike_correlation_rule" "test" {
  name     = %[1]q
  cid      = data.crowdstrike_cid.test.cid
  severity = "medium"
  status   = "inactive"

  search = {
    filter       = "#repo=\"base_sensor\" #event_simpleName=ProcessRollup2"
    lookback     = "1h0m"
    trigger_mode = "verbose"
  }

  schedule = {
    interval = "1h0m"
    start_on = %[2]q
  }

  notifications = [
    {
      type         = "email"
      is_guardrail = true
      recipients   = ["acc-tests@crowdstrike.com"]
    },
  ]
}
`, rName, futureStartOn)
}

func testAccCorrelationRuleConfig_full(rName, severity, status string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
data "crowdstrike_cid" "test" {}

resource "crowdstrike_correlation_rule" "test" {
  name        = %[1]q
  cid         = data.crowdstrike_cid.test.cid
  description = "updated description"
  comment     = "updated comment"
  severity    = %[2]q
  status      = %[3]q

  search = {
    filter          = "#repo=\"base_sensor\" #event_simpleName=ProcessRollup2"
    lookback        = "2h0m"
    trigger_mode    = "summary"
    create_case     = true
    use_ingest_time = true
  }

  schedule = {
    interval = "2h0m"
    start_on = %[4]q
  }

  mitre_attack = [
    {
      tactic_id    = "TA0001"
      technique_id = "T1078"
    },
  ]

  notifications = [
    {
      type         = "email"
      is_guardrail = true
      recipients   = ["acc-tests@crowdstrike.com"]
      severity     = "high"
    },
  ]
}
`, rName, severity, status, futureStartOn)
}

func testAccCorrelationRuleConfig_mitre(rName, severity string, entries []mitreEntry) string {
	mitreItems := ""
	for _, e := range entries {
		mitreItems += fmt.Sprintf(`
    {
      tactic_id    = %q
      technique_id = %q
    },`, e.tacticID, e.techniqueID)
	}
	return acctest.ProviderConfig + fmt.Sprintf(`
data "crowdstrike_cid" "test" {}

resource "crowdstrike_correlation_rule" "test" {
  name     = %[1]q
  cid      = data.crowdstrike_cid.test.cid
  severity = %[2]q
  status   = "inactive"

  search = {
    filter       = "#repo=\"base_sensor\" #event_simpleName=ProcessRollup2"
    lookback     = "1h0m"
    trigger_mode = "verbose"
  }

  schedule = {
    interval = "1h0m"
    start_on = %[4]q
  }

  mitre_attack = [%[3]s
  ]

  notifications = [
    {
      type         = "email"
      is_guardrail = true
      recipients   = ["acc-tests@crowdstrike.com"]
    },
  ]
}
`, rName, severity, mitreItems, futureStartOn)
}

func testAccCorrelationRuleConfig_notifications(rName, notificationsBlock string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
data "crowdstrike_cid" "test" {}

resource "crowdstrike_correlation_rule" "test" {
  name     = %[1]q
  cid      = data.crowdstrike_cid.test.cid
  severity = "medium"
  status   = "inactive"

  search = {
    filter       = "#repo=\"base_sensor\" #event_simpleName=ProcessRollup2"
    lookback     = "1h0m"
    trigger_mode = "verbose"
  }

  schedule = {
    interval = "1h0m"
    start_on = %[3]q
  }
%[2]s
}
`, rName, notificationsBlock, futureStartOn)
}

func testAccCorrelationRuleConfig_stopOn(rName, stopOn string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
data "crowdstrike_cid" "test" {}

resource "crowdstrike_correlation_rule" "test" {
  name     = %[1]q
  cid      = data.crowdstrike_cid.test.cid
  severity = "medium"
  status   = "inactive"

  search = {
    filter       = "#repo=\"base_sensor\" #event_simpleName=ProcessRollup2"
    lookback     = "1h0m"
    trigger_mode = "verbose"
  }

  schedule = {
    interval = "1h0m"
    start_on = %[2]q
    stop_on  = %[3]q
  }

  notifications = [
    {
      type         = "email"
      is_guardrail = true
      recipients   = ["acc-tests@crowdstrike.com"]
    },
  ]
}
`, rName, futureStartOn, stopOn)
}

func testAccCorrelationRuleConfig_startOn(rName, startOn string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
data "crowdstrike_cid" "test" {}

resource "crowdstrike_correlation_rule" "test" {
  name     = %[1]q
  cid      = data.crowdstrike_cid.test.cid
  severity = "medium"
  status   = "inactive"

  search = {
    filter       = "#repo=\"base_sensor\" #event_simpleName=ProcessRollup2"
    lookback     = "1h0m"
    trigger_mode = "verbose"
  }

  schedule = {
    interval = "1h0m"
    start_on = %[2]q
  }

  notifications = [
    {
      type         = "email"
      is_guardrail = true
      recipients   = ["acc-tests@crowdstrike.com"]
    },
  ]
}
`, rName, startOn)
}

func testAccCorrelationRuleConfig_validatorCase(rName, cid, notificationsBlock string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_correlation_rule" "test" {
  name     = %[1]q
  cid      = %[2]q
  severity = "medium"
  status   = "inactive"

  search = {
    filter       = "#repo=\"base_sensor\" #event_simpleName=ProcessRollup2"
    lookback     = "1h0m"
    trigger_mode = "verbose"
  }

  schedule = {
    interval = "1h0m"
    start_on = %[4]q
  }
%[3]s
}
`, rName, cid, notificationsBlock, futureStartOn)
}

func testAccCorrelationRuleConfig_durationCase(rName, lookback, interval string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_correlation_rule" "test" {
  name     = %[1]q
  cid      = "e82676877a894c809bc56d0a08568e54"
  severity = "medium"
  status   = "inactive"

  search = {
    filter       = "#repo=\"base_sensor\" #event_simpleName=ProcessRollup2"
    lookback     = %[2]q
    trigger_mode = "verbose"
  }

  schedule = {
    interval = %[3]q
    start_on = %[4]q
  }

  notifications = [
    {
      type         = "email"
      is_guardrail = true
      recipients   = ["acc-tests@crowdstrike.com"]
    },
  ]
}
`, rName, lookback, interval, futureStartOn)
}
