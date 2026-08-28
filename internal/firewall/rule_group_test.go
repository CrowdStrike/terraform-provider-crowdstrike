package firewall_test

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// The acceptance suite for crowdstrike_firewall_rule_group. One test per
// independently configurable attribute, plus the whole-resource lifecycles that
// no single attribute owns.
//
// Two guarantees run through nearly every test, because a naive implementation
// breaks both silently:
//
//  1. Precedence. Rule precedence is the order of the list, so the configured
//     order must equal the order in Terraform state and the order of the group's
//     rule_ids array in the API. rule_ids is the only authority: the rules
//     endpoint returns rules in a nondeterministic order and can never be used to
//     assert ordering. wantAPIPrecedence() asserts this on every apply step that
//     configures rules, so an unrelated edit cannot quietly corrupt it.
//
//  2. Rule identity. rules[*].id is a rule's stable identity. A rule that is only
//     moved, or left untouched by an edit elsewhere in the group, must keep its
//     id. Recreating rules the user did not change churns firewall state and, when
//     it goes wrong, silently reassigns attributes between rules.
//
// Fixtures live in rule_group_acc_fixtures_test.go and render both the
// configuration and the complete expected state. Checks and out-of-band API
// helpers live in rule_group_acc_checks_test.go.

func TestAccFirewallRuleGroup_basic(t *testing.T) {
	rName := acctest.RandomResourceName()

	// Only the required attributes. Creating with enabled = false exercises the
	// Create path with the boolean zero value, and leaves the group disabled at
	// teardown so Delete takes the branch that skips the pre-delete disable call.
	g := newRuleGroupNoRules(rName).disabled()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFirewallRuleGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: g.hcl(),
				// wantGroup asserts description is null and rules is null, not an
				// empty list. Later tests depend on that distinction.
				ConfigStateChecks: append(wantGroup(g), wantGroupExistsInAPI()),
			},
			importVerify(),
		},
	})
}

func TestAccFirewallRuleGroup_disappears(t *testing.T) {
	rName := acctest.RandomResourceName()
	g := newRuleGroupNoRules(rName).disabled()

	var groupID string

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFirewallRuleGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config:            g.hcl(),
				ConfigStateChecks: append(wantGroup(g), wantGroupExistsInAPI(), captureGroupID(&groupID)),
			},
			{
				// Deleting the group behind Terraform's back must leave Read
				// removing it from state rather than returning a not-found error,
				// so the next plan proposes creating it again.
				PreConfig: func() {
					if groupID == "" {
						t.Fatal("group id was not captured")
					}
					if err := deleteAPIRuleGroup(context.Background(), groupID); err != nil {
						t.Fatalf("deleting rule group out of band: %s", err)
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
				RefreshPlanChecks: resource.RefreshPlanChecks{
					PostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionCreate),
					},
				},
			},
		},
	})
}

func TestAccFirewallRuleGroup_name(t *testing.T) {
	rName := acctest.RandomResourceName()
	renamed := rName + "-renamed"

	// One rule, so the rename also proves correcting a group-level attribute does
	// not churn the rules underneath it.
	rule := newTCPRule("Rule A")
	rule.RemotePort = []portFixture{port(8443)}

	before := newRuleGroup(rName, rule)
	after := newRuleGroup(renamed, rule)

	groupID := statecheck.CompareValue(compare.ValuesSame())
	ruleID := statecheck.CompareValue(compare.ValuesSame())

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFirewallRuleGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: before.hcl(),
				ConfigStateChecks: append(wantGroup(before),
					wantAPIPrecedence(),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
					ruleID.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
				),
			},
			{
				// basic already imports this required attribute, so no import here.
				Config: after.hcl(),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
					},
				},
				ConfigStateChecks: append(wantGroup(after),
					wantAPIPrecedence(),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
					ruleID.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
				),
			},
		},
	})
}

func TestAccFirewallRuleGroup_description(t *testing.T) {
	rName := acctest.RandomResourceName()

	rule := newTCPRule("Rule A")
	rule.RemotePort = []portFixture{port(8443)}

	withA := newRuleGroup(rName, rule)
	withA.Description = setVal("Description A")

	withB := newRuleGroup(rName, rule)
	withB.Description = setVal("Description B")

	// Description omitted entirely, which must read back as null.
	without := newRuleGroup(rName, rule)

	groupID := statecheck.CompareValue(compare.ValuesSame())
	ruleID := statecheck.CompareValue(compare.ValuesSame())

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFirewallRuleGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: withA.hcl(),
				ConfigStateChecks: append(wantGroup(withA),
					wantAPIPrecedence(),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
					ruleID.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
				),
			},
			importVerify(),
			{
				Config: withB.hcl(),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
					},
				},
				ConfigStateChecks: append(wantGroup(withB),
					wantAPIPrecedence(),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
					ruleID.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
				),
			},
			{
				Config: without.hcl(),
				ConfigStateChecks: append(wantGroup(without),
					wantAPIPrecedence(),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
					ruleID.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
				),
			},
		},
	})
}

func TestAccFirewallRuleGroup_platform(t *testing.T) {
	rName := acctest.RandomResourceName()

	// platform requires replacement, and this test also owns platform-dependent
	// rule field construction. A rule's fields array carries the executable path
	// as windows_path on Windows and unix_path on Mac and Linux, and the
	// service_name entry exists only on Windows, so those branches are only
	// reachable by applying a group on each platform.
	windowsRule := newTCPRule("Rule A")
	windowsRule.ExecutablePath = setVal(`C:\Windows\System32\svchost.exe`)
	windowsRule.ServiceName = setVal("TestService")

	// Mac keeps the executable path, which is the suite's only populated
	// unix_path, but must drop service_name.
	macRule := newTCPRule("Rule A")
	macRule.ExecutablePath = setVal("/usr/bin/curl")

	// Linux rejects executable_path as well, and only ANY is valid for
	// network_location there.
	linuxRule := newTCPRule("Rule A")

	windows := newRuleGroup(rName, windowsRule)
	mac := newRuleGroup(rName, macRule).on("Mac")
	linux := newRuleGroup(rName, linuxRule).on("Linux")

	// Both comparers walk consecutive pairs, so one tracker spans all three steps.
	groupID := statecheck.CompareValue(compare.ValuesDiffer())

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFirewallRuleGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: windows.hcl(),
				ConfigStateChecks: append(wantGroup(windows),
					wantAPIPrecedence(),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
				),
			},
			{
				Config: mac.hcl(),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
				ConfigStateChecks: append(wantGroup(mac),
					wantAPIPrecedence(),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
				),
			},
			// The only import of a non-Windows rule, so the only one that proves an
			// executable path stored as unix_path reads back, with no service_name
			// entry present at all.
			importVerify(),
			{
				// Linux is applied rather than only validated: it otherwise
				// appears only in configurations rejected at plan time, so the
				// Linux branch of field construction would never run.
				Config: linux.hcl(),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
				ConfigStateChecks: append(wantGroup(linux),
					wantAPIPrecedence(),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
				),
			},
		},
	})
}

func TestAccFirewallRuleGroup_enabled(t *testing.T) {
	rName := acctest.RandomResourceName()

	// basic proves Create works with false. This proves the zero value also works
	// on Update, in both directions, and ends disabled so teardown takes the
	// skip-the-disable branch.
	on := newRuleGroupNoRules(rName)
	off := newRuleGroupNoRules(rName).disabled()

	groupID := statecheck.CompareValue(compare.ValuesSame())

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFirewallRuleGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: on.hcl(),
				ConfigStateChecks: append(wantGroup(on),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
				),
			},
			{
				Config: off.hcl(),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
					},
				},
				ConfigStateChecks: append(wantGroup(off),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
				),
			},
			{
				Config: on.hcl(),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
					},
				},
				ConfigStateChecks: append(wantGroup(on),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
				),
			},
			{
				Config: off.hcl(),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
					},
				},
				ConfigStateChecks: append(wantGroup(off),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
				),
			},
		},
	})
}

func TestAccFirewallRuleGroup_rules(t *testing.T) {
	rName := acctest.RandomResourceName()

	// Rule A is minimal, so its expected state is almost entirely defaults.
	ruleA := newTCPRule("Rule A")

	// Rule B populates meaningful optional state on every axis at once, so an
	// unrelated edit elsewhere in the group cannot quietly drop any of it.
	ruleB := newTCPRule("Rule B")
	ruleB.Description = setVal("Rich rule")
	ruleB.Enabled = setVal(false)
	ruleB.LocalAddress = []addrFixture{addr("192.168.10.0", 24), addr("10.1.0.0", 16)}
	ruleB.RemoteAddress = []addrFixture{addr("172.16.0.0", 12), addr("10.2.0.1")}
	ruleB.LocalPort = []portFixture{port(6000, 6100), port(7000)}
	ruleB.RemotePort = []portFixture{port(8000, 8100), port(9000)}
	ruleB.NetworkLocation = setVal("PUBLIC")
	ruleB.ExecutablePath = setVal(`C:\Windows\System32\svchost.exe`)
	ruleB.ServiceName = setVal("TestService")
	ruleB.WatchMode = setVal(true)

	// Rule C is an FQDN rule, so an FQDN-bearing rule is proven to survive
	// unrelated changes elsewhere in the group.
	ruleC := newRule("Rule C", "ALLOW", "OUT", "TCP")
	ruleC.Fqdn = setVal("example.com")

	// B' changes one ordinary content setting and nothing else, so its identity
	// must survive.
	ruleBEdited := ruleB
	ruleBEdited.Action = "DENY"

	// X and Y differ by more than their names on purpose. A rule whose settings
	// are all unchanged is a rename, which preserves identity by contract, so two
	// rules differing only in name could never express a delete plus an add.
	ruleX := newTCPRule("Rule X")
	ruleX.RemotePort = []portFixture{port(9001)}
	ruleY := newTCPRule("Rule Y")
	ruleY.RemotePort = []portFixture{port(9002)}

	created := newRuleGroup(rName, ruleA, ruleB, ruleC)
	inserted := newRuleGroup(rName, ruleA, ruleX, ruleBEdited, ruleC)
	reordered := newRuleGroup(rName, ruleC, ruleA, ruleX, ruleBEdited)
	swapped := newRuleGroup(rName, ruleC, ruleA, ruleY, ruleBEdited)
	trimmed := newRuleGroup(rName, ruleA, ruleY, ruleBEdited)
	emptied := newRuleGroup(rName)
	omitted := newRuleGroupNoRules(rName)

	groupID := statecheck.CompareValue(compare.ValuesSame())
	// One comparer per logical rule, fed the position that rule holds in each step.
	idA := statecheck.CompareValue(compare.ValuesSame())
	idB := statecheck.CompareValue(compare.ValuesSame())
	idC := statecheck.CompareValue(compare.ValuesSame())
	idX := statecheck.CompareValue(compare.ValuesSame())
	idY := statecheck.CompareValue(compare.ValuesSame())

	var afterCreate, afterReorder, afterSwap ruleIDs

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFirewallRuleGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: created.hcl(),
				ConfigStateChecks: append(wantGroup(created),
					wantAPIPrecedence(), wantRuleIDsUsable(), captureRuleIDs(&afterCreate),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
					idA.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
					idB.AddStateValue(ruleGroupResourceName, ruleIDPath(1)),
					idC.AddStateValue(ruleGroupResourceName, ruleIDPath(2)),
				),
			},
			// Proves Read reconstructs multiple rule families, ordering, computed
			// ids, defaults, rich nested values and FQDN state.
			importVerify(),
			{
				// Insert in the middle and edit B in the same apply. A and C are
				// untouched and must be unaffected by either.
				Config: inserted.hcl(),
				ConfigStateChecks: append(wantGroup(inserted),
					wantAPIPrecedence(), wantRuleIDsUsable(),
					wantRuleIDsNew(&afterCreate, 1),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
					idA.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
					idX.AddStateValue(ruleGroupResourceName, ruleIDPath(1)),
					idB.AddStateValue(ruleGroupResourceName, ruleIDPath(2)),
					idC.AddStateValue(ruleGroupResourceName, ruleIDPath(3)),
				),
			},
			{
				// Pure reorder: no content changes, so every identity survives. All
				// four rules are tracked by position here, and wantGroup pins the
				// list to exactly four, so no rule can have been recreated.
				Config: reordered.hcl(),
				ConfigStateChecks: append(wantGroup(reordered),
					wantAPIPrecedence(), wantRuleIDsUsable(),
					captureRuleIDs(&afterReorder),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
					idC.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
					idA.AddStateValue(ruleGroupResourceName, ruleIDPath(1)),
					idX.AddStateValue(ruleGroupResourceName, ruleIDPath(2)),
					idB.AddStateValue(ruleGroupResourceName, ruleIDPath(3)),
				),
			},
			{
				// Remove X and add Y in one apply, after precedence and creation
				// order have diverged. The delete is only correct if the group's
				// rules array is kept in rule_ids order, and the index arithmetic
				// has to hold with a removal and an addition both in flight.
				Config: swapped.hcl(),
				ConfigStateChecks: append(wantGroup(swapped),
					wantAPIPrecedence(), wantRuleIDsUsable(), captureRuleIDs(&afterSwap),
					wantRuleIDsAbsent(&afterReorder, 2),
					wantRuleIDsNew(&afterReorder, 2),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
					idC.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
					idA.AddStateValue(ruleGroupResourceName, ruleIDPath(1)),
					idB.AddStateValue(ruleGroupResourceName, ruleIDPath(3)),
					idY.AddStateValue(ruleGroupResourceName, ruleIDPath(2)),
				),
			},
			{
				// Delete the leading rule, shifting every remaining index.
				Config: trimmed.hcl(),
				ConfigStateChecks: append(wantGroup(trimmed),
					wantAPIPrecedence(), wantRuleIDsUsable(),
					wantRuleIDsAbsent(&afterSwap, 0),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
					idA.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
					idY.AddStateValue(ruleGroupResourceName, ruleIDPath(1)),
					idB.AddStateValue(ruleGroupResourceName, ruleIDPath(2)),
				),
			},
			{
				// An explicit empty list. The rules attribute carries no minimum
				// size validator, unlike the nested address and port lists.
				Config: emptied.hcl(),
				ConfigStateChecks: append(wantGroup(emptied),
					wantAPIRuleIDCount(0),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
				),
			},
			{
				// Omitting the attribute is a different state from an empty list.
				Config: omitted.hcl(),
				ConfigStateChecks: append(wantGroup(omitted),
					wantAPIRuleIDCount(0),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
				),
			},
		},
	})
}

// largeRuleGroupSize is deliberately above the 100-id ceiling of the rules
// endpoint, which is also the provider's read batch size.
const largeRuleGroupSize = 120

func TestAccFirewallRuleGroup_rules_largeGroup(t *testing.T) {
	rName := acctest.RandomResourceName()

	rules := make([]ruleFixture, 0, largeRuleGroupSize)
	for i := range largeRuleGroupSize {
		// Minimal but distinguishable. Ordinary rule-field semantics are covered
		// elsewhere; this test exists for the batched read path.
		r := newTCPRule(fmt.Sprintf("Rule %03d", i))
		r.RemotePort = []portFixture{port(int64(10000 + i))}
		rules = append(rules, r)
	}

	g := newRuleGroup(rName, rules...)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFirewallRuleGroupDestroy,
		Steps: []resource.TestStep{
			{
				// The post-apply refresh has to succeed and converge, which is
				// what exercises reading a group across the batching boundary.
				Config: g.hcl(),
				ConfigStateChecks: append(wantGroup(g),
					wantAPIPrecedence(), wantRuleIDsUsable(),
					wantAPIRuleIDCount(largeRuleGroupSize),
				),
			},
			// Independently reconstructs all 120 rules, in order, through Read.
			importVerify(),
		},
	})
}

func TestAccFirewallRuleGroup_rules_name(t *testing.T) {
	rName := acctest.RandomResourceName()

	ruleA := newTCPRule("Rule A")
	ruleA.RemotePort = []portFixture{port(8081)}
	ruleB := newTCPRule("Rule B")
	ruleB.RemotePort = []portFixture{port(8082)}
	ruleC := newTCPRule("Rule C")
	ruleC.RemotePort = []portFixture{port(8083)}

	// A rename on its own preserves the rule's identity.
	ruleBRenamed := ruleB
	ruleBRenamed.Name = "Rule B renamed"

	// Two rules may share a name. They are still distinct rules with distinct
	// identities, which proves name is not being used as rule identity.
	twinOne := newTCPRule("Shared Name")
	twinOne.RemotePort = []portFixture{port(9091)}
	twinTwo := newTCPRule("Shared Name")
	twinTwo.RemotePort = []portFixture{port(9092)}

	twinOneEdited := twinOne
	twinOneEdited.Action = "DENY"

	// A rename together with a settings change in the same apply is documented to
	// replace the rule, which assigns a new identifier. Both have to change
	// relative to the previous step: a rename on its own preserves the identity.
	twinOneRenamedAndChanged := twinOneEdited
	twinOneRenamedAndChanged.Name = "Renamed And Changed"
	twinOneRenamedAndChanged.RemotePort = []portFixture{port(9191)}

	created := newRuleGroup(rName, ruleA, ruleB, ruleC)
	renamed := newRuleGroup(rName, ruleA, ruleBRenamed, ruleC)
	twinned := newRuleGroup(rName, twinOne, twinTwo, ruleC)
	twinEdited := newRuleGroup(rName, twinOneEdited, twinTwo, ruleC)
	twinReplaced := newRuleGroup(rName, twinOneRenamedAndChanged, twinTwo, ruleC)

	groupID := statecheck.CompareValue(compare.ValuesSame())
	idA := statecheck.CompareValue(compare.ValuesSame())
	idB := statecheck.CompareValue(compare.ValuesSame())
	// The twins are tracked separately so an edit landing on the wrong one fails.
	idTwinOne := statecheck.CompareValue(compare.ValuesSame())
	idTwinTwo := statecheck.CompareValue(compare.ValuesSame())
	// The one rule whose identity must change: a rename plus a settings change in
	// one apply replaces it.
	idReplaced := statecheck.CompareValue(compare.ValuesDiffer())

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFirewallRuleGroupDestroy,
		Steps: []resource.TestStep{
			{
				// No import: the populated rules import in the rules test already
				// covers reading names back.
				Config: created.hcl(),
				ConfigStateChecks: append(wantGroup(created),
					wantAPIPrecedence(), wantRuleIDsUsable(),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
					idA.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
					idB.AddStateValue(ruleGroupResourceName, ruleIDPath(1)),
				),
			},
			{
				Config: renamed.hcl(),
				ConfigStateChecks: append(wantGroup(renamed),
					wantAPIPrecedence(), wantRuleIDsUsable(),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
					idA.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
					idB.AddStateValue(ruleGroupResourceName, ruleIDPath(1)),
				),
			},
			{
				Config: twinned.hcl(),
				ConfigStateChecks: append(wantGroup(twinned),
					wantAPIPrecedence(), wantRuleIDsUsable(),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
					idTwinOne.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
					idTwinTwo.AddStateValue(ruleGroupResourceName, ruleIDPath(1)),
				),
			},
			{
				// Change only the first twin. The second must come back byte for
				// byte identical, with its own identity intact.
				Config: twinEdited.hcl(),
				ConfigStateChecks: append(wantGroup(twinEdited),
					wantAPIPrecedence(), wantRuleIDsUsable(),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
					idTwinOne.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
					idTwinTwo.AddStateValue(ruleGroupResourceName, ruleIDPath(1)),
					idReplaced.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
				),
			},
			{
				// Rename and change a setting in one apply: the group stays in
				// place but this rule gets a new identifier, and the untouched
				// rules keep theirs.
				Config: twinReplaced.hcl(),
				ConfigStateChecks: append(wantGroup(twinReplaced),
					wantAPIPrecedence(), wantRuleIDsUsable(),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
					idTwinTwo.AddStateValue(ruleGroupResourceName, ruleIDPath(1)),
					idReplaced.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
				),
			},
		},
	})
}

func TestAccFirewallRuleGroup_rules_description(t *testing.T) {
	rName := acctest.RandomResourceName()

	withA := newTCPRule("Rule A")
	withA.Description = setVal("Description A")
	withB := withA
	withB.Description = setVal("Description B")
	without := newTCPRule("Rule A")

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFirewallRuleGroupDestroy,
		Steps:                    lifecycleSteps(rName, withA, withB, without),
	})
}

func TestAccFirewallRuleGroup_rules_enabled(t *testing.T) {
	rName := acctest.RandomResourceName()

	// Optional and computed, defaulting to true, so the interesting create is the
	// zero value and the interesting update is restoring the default.
	disabled := newTCPRule("Rule A")
	disabled.Enabled = setVal(false)
	omitted := newTCPRule("Rule A")

	off := newRuleGroup(rName, disabled)
	on := newRuleGroup(rName, omitted)

	groupID := statecheck.CompareValue(compare.ValuesSame())
	ruleID := statecheck.CompareValue(compare.ValuesSame())

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFirewallRuleGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: off.hcl(),
				// A disabled rule must not disable the group, which wantGroup
				// asserts by expecting enabled = true on the group itself.
				ConfigStateChecks: append(wantGroup(off),
					wantAPIPrecedence(),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
					ruleID.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
				),
			},
			importVerify(),
			{
				// Removing the explicit value restores the documented default.
				Config: on.hcl(),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
					},
				},
				ConfigStateChecks: append(wantGroup(on),
					wantAPIPrecedence(),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
					ruleID.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
				),
			},
			{
				// And back, so the zero value is proven on update in both
				// directions.
				Config: off.hcl(),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
					},
				},
				ConfigStateChecks: append(wantGroup(off),
					wantAPIPrecedence(),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
					ruleID.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
				),
			},
		},
	})
}

func TestAccFirewallRuleGroup_rules_action(t *testing.T) {
	rName := acctest.RandomResourceName()

	allow := newTCPRule("Rule A")
	allow.RemotePort = []portFixture{port(8443)}
	deny := newRule("Rule A", "DENY", "OUT", "TCP")
	deny.RemotePort = []portFixture{port(8443)}

	allowed := newRuleGroup(rName, allow)
	denied := newRuleGroup(rName, deny)

	groupID := statecheck.CompareValue(compare.ValuesSame())
	ruleID := statecheck.CompareValue(compare.ValuesSame())

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFirewallRuleGroupDestroy,
		Steps: []resource.TestStep{
			{
				// No import: the populated rules import covers reading action back.
				Config: allowed.hcl(),
				ConfigStateChecks: append(wantGroup(allowed),
					wantAPIPrecedence(),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
					ruleID.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
				),
			},
			{
				Config: denied.hcl(),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
					},
				},
				ConfigStateChecks: append(wantGroup(denied),
					wantAPIPrecedence(),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
					ruleID.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
				),
			},
		},
	})
}

func TestAccFirewallRuleGroup_rules_direction(t *testing.T) {
	rName := acctest.RandomResourceName()

	// FQDN-specific OUT behavior belongs to rules_fqdn and validation.
	inbound := newRule("Rule A", "ALLOW", "IN", "TCP")
	inbound.RemotePort = []portFixture{port(8443)}
	both := inbound
	both.Direction = "BOTH"

	in := newRuleGroup(rName, inbound)
	bidirectional := newRuleGroup(rName, both)

	groupID := statecheck.CompareValue(compare.ValuesSame())
	ruleID := statecheck.CompareValue(compare.ValuesSame())

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFirewallRuleGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: in.hcl(),
				ConfigStateChecks: append(wantGroup(in),
					wantAPIPrecedence(),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
					ruleID.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
				),
			},
			{
				Config: bidirectional.hcl(),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
					},
				},
				ConfigStateChecks: append(wantGroup(bidirectional),
					wantAPIPrecedence(),
					groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
					ruleID.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
				),
			},
		},
	})
}

func TestAccFirewallRuleGroup_rules_protocol(t *testing.T) {
	rName := acctest.RandomResourceName()

	// This walks the real applicability families rather than swapping two named
	// protocols, because each transition has to ship the protocol change and the
	// now-invalid attributes in a single request.
	tcp := newTCPRule("Rule A")
	tcp.LocalPort = []portFixture{port(6000, 6100)}
	tcp.RemotePort = []portFixture{port(8443)}

	// ANY forbids ports, so they go in the same apply as the protocol change.
	anyProtocol := newRule("Rule A", "ALLOW", "OUT", "ANY")

	// ICMP with type and code omitted, which the plan modifier fills with the
	// wildcard. A live round trip is required for both ICMP families: the unit
	// tests cannot prove protocol mapping or API acceptance.
	//
	// ICMPV6 also needs an IPv6 address family. The API rejects IPv4 with ICMPv6
	// ("Address family IPv4 is not allowed with protocol ICMPv6"), which
	// ruleAttributeApplicability now rejects at validate time, so the default IP4
	// would never reach the API.
	icmpV4 := newRule("Rule A", "ALLOW", "OUT", "ICMPV4")
	icmpV6 := newRule("Rule A", "ALLOW", "OUT", "ICMPV6")
	icmpV6.AddressFamily = setVal("IP6")

	groupID := statecheck.CompareValue(compare.ValuesSame())
	ruleID := statecheck.CompareValue(compare.ValuesSame())

	withRule := func(r ruleFixture) ruleGroupFixture { return newRuleGroup(rName, r) }

	step := func(r ruleFixture, plan resource.ConfigPlanChecks) resource.TestStep {
		g := withRule(r)

		return resource.TestStep{
			Config:           g.hcl(),
			ConfigPlanChecks: plan,
			ConfigStateChecks: append(wantGroup(g),
				wantAPIPrecedence(),
				groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
				ruleID.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
			),
		}
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFirewallRuleGroupDestroy,
		Steps: []resource.TestStep{
			step(tcp, resource.ConfigPlanChecks{}),
			importVerify(),
			step(anyProtocol, resource.ConfigPlanChecks{
				PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
				},
			}),
			step(icmpV4, resource.ConfigPlanChecks{
				PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
				},
			}),
			step(icmpV6, resource.ConfigPlanChecks{
				PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
				},
			}),
			step(tcp, resource.ConfigPlanChecks{
				PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
				},
			}),
		},
	})
}

func TestAccFirewallRuleGroup_rules_addressFamily(t *testing.T) {
	rName := acctest.RandomResourceName()

	ip4 := newTCPRule("Rule A")
	ip4.AddressFamily = setVal("IP4")
	ip4.LocalAddress = []addrFixture{addr("192.168.1.0", 24)}
	ip4.RemoteAddress = []addrFixture{addr("10.0.0.0", 8)}

	// ANY cannot name specific addresses, so both lists are dropped in the same
	// apply as the family change and revert to the wildcard default.
	anyFamily := newTCPRule("Rule A")
	anyFamily.AddressFamily = setVal("ANY")

	ip6 := newTCPRule("Rule A")
	ip6.AddressFamily = setVal("IP6")
	ip6.LocalAddress = []addrFixture{addr("2001:db8::", 32)}
	ip6.RemoteAddress = []addrFixture{addr("2001:db8:1::", 48)}

	// Family omitted returns to the IP4 default with wildcard addresses.
	omitted := newTCPRule("Rule A")

	groupID := statecheck.CompareValue(compare.ValuesSame())
	ruleID := statecheck.CompareValue(compare.ValuesSame())

	step := func(r ruleFixture, plan resource.ConfigPlanChecks) resource.TestStep {
		g := newRuleGroup(rName, r)

		return resource.TestStep{
			Config:           g.hcl(),
			ConfigPlanChecks: plan,
			ConfigStateChecks: append(wantGroup(g),
				wantAPIPrecedence(),
				groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
				ruleID.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
			),
		}
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFirewallRuleGroupDestroy,
		Steps: []resource.TestStep{
			step(ip4, resource.ConfigPlanChecks{}),
			importVerify(),
			step(anyFamily, resource.ConfigPlanChecks{
				PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
				},
			}),
			step(ip6, resource.ConfigPlanChecks{
				PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
				},
			}),
			step(omitted, resource.ConfigPlanChecks{
				PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
				},
			}),
		},
	})
}

// lifecycleSteps is the create, import, change, remove shape shared by the
// attribute tests whose whole story is one optional value appearing, changing and
// going away again. Each step asserts the complete rule object, the group's
// identity and live precedence.
func lifecycleSteps(name string, create, change, remove ruleFixture) []resource.TestStep {
	groupID := statecheck.CompareValue(compare.ValuesSame())
	ruleID := statecheck.CompareValue(compare.ValuesSame())

	step := func(r ruleFixture, plan resource.ConfigPlanChecks) resource.TestStep {
		g := newRuleGroup(name, r)

		return resource.TestStep{
			Config:           g.hcl(),
			ConfigPlanChecks: plan,
			ConfigStateChecks: append(wantGroup(g),
				wantAPIPrecedence(),
				groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
				ruleID.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
			),
		}
	}

	return []resource.TestStep{
		step(create, resource.ConfigPlanChecks{}),
		importVerify(),
		step(change, resource.ConfigPlanChecks{
			PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
			},
		}),
		step(remove, resource.ConfigPlanChecks{
			PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
			},
		}),
	}
}

// addressLifecycleSteps is the ordered nested-list lifecycle both address
// attributes own. Steps 5 and 6 are the wildcard spelling equivalences: an
// omitted list and a single explicit "*" entry are one value, so flipping between
// them must plan nothing.
func addressLifecycleSteps(name string, set func(*ruleFixture, []addrFixture)) []resource.TestStep {
	groupID := statecheck.CompareValue(compare.ValuesSame())
	ruleID := statecheck.CompareValue(compare.ValuesSame())

	step := func(addrs []addrFixture, plan resource.ConfigPlanChecks) resource.TestStep {
		r := newTCPRule("Rule A")
		set(&r, addrs)
		g := newRuleGroup(name, r)

		return resource.TestStep{
			Config:           g.hcl(),
			ConfigPlanChecks: plan,
			ConfigStateChecks: append(wantGroup(g),
				wantAPIPrecedence(),
				groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
				ruleID.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
			),
		}
	}

	return []resource.TestStep{
		// Three ordered entries: an omitted netmask defaulting to 0, an explicit
		// non-zero netmask, and another distinct value.
		step([]addrFixture{addr("172.16.0.0", 12), addr("192.168.1.1"), addr("10.0.0.0", 8)},
			resource.ConfigPlanChecks{}),
		importVerify(),
		// One transition that modifies an entry, removes one, adds one, reorders
		// the rest and takes a non-zero netmask to 0.
		step([]addrFixture{addr("10.0.0.0", 0), addr("172.16.5.0", 24), addr("203.0.113.7")},
			resource.ConfigPlanChecks{
				PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
				},
			}),
		// The explicit wildcard representation.
		step([]addrFixture{addr("*", 0)}, resource.ConfigPlanChecks{
			PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
			},
		}),
		// Explicit wildcard to omitted: same value, different spelling.
		step(nil, resource.ConfigPlanChecks{
			PreApply: []plancheck.PlanCheck{
				plancheck.ExpectEmptyPlan(),
			},
		}),
		// And back again.
		step([]addrFixture{addr("*", 0)}, resource.ConfigPlanChecks{
			PreApply: []plancheck.PlanCheck{
				plancheck.ExpectEmptyPlan(),
			},
		}),
		// Finish omitted, which must still be the wildcard representation.
		step(nil, resource.ConfigPlanChecks{
			PreApply: []plancheck.PlanCheck{
				plancheck.ExpectEmptyPlan(),
			},
		}),
	}
}

// portLifecycleSteps is the ordered nested-list lifecycle both port attributes
// own. Ports only apply to TCP and UDP, so the protocol is a parameter.
func portLifecycleSteps(name, protocol string, set func(*ruleFixture, []portFixture)) []resource.TestStep {
	groupID := statecheck.CompareValue(compare.ValuesSame())
	ruleID := statecheck.CompareValue(compare.ValuesSame())

	step := func(ports []portFixture, plan resource.ConfigPlanChecks) resource.TestStep {
		r := newRule("Rule A", "ALLOW", "OUT", protocol)
		set(&r, ports)
		g := newRuleGroup(name, r)

		return resource.TestStep{
			Config:           g.hcl(),
			ConfigPlanChecks: plan,
			ConfigStateChecks: append(wantGroup(g),
				wantAPIPrecedence(),
				groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
				ruleID.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
			),
		}
	}

	return []resource.TestStep{
		// A single port with end omitted, a real range, and another distinct entry.
		step([]portFixture{port(443), port(8000, 9000), port(6000, 6100)},
			resource.ConfigPlanChecks{}),
		importVerify(),
		// One transition that modifies an entry, removes one, adds one, reorders
		// the rest and takes a non-zero end to 0.
		step([]portFixture{port(8000, 0), port(6000, 6200), port(9443)},
			resource.ConfigPlanChecks{
				PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
				},
			}),
		// Removing the attribute leaves it null, never an empty list.
		step(nil, resource.ConfigPlanChecks{
			PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
			},
		}),
	}
}

func TestAccFirewallRuleGroup_rules_localAddress(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFirewallRuleGroupDestroy,
		Steps: addressLifecycleSteps(rName,
			func(r *ruleFixture, addrs []addrFixture) { r.LocalAddress = addrs }),
	})
}

func TestAccFirewallRuleGroup_rules_remoteAddress(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFirewallRuleGroupDestroy,
		Steps: addressLifecycleSteps(rName,
			func(r *ruleFixture, addrs []addrFixture) { r.RemoteAddress = addrs }),
	})
}

func TestAccFirewallRuleGroup_rules_localPort(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFirewallRuleGroupDestroy,
		Steps: portLifecycleSteps(rName, "TCP",
			func(r *ruleFixture, ports []portFixture) { r.LocalPort = ports }),
	})
}

func TestAccFirewallRuleGroup_rules_remotePort(t *testing.T) {
	rName := acctest.RandomResourceName()

	// UDP, so the suite applies a UDP rule against the live API somewhere. Every
	// other protocol test walks TCP, ANY and the two ICMP families.
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFirewallRuleGroupDestroy,
		Steps: portLifecycleSteps(rName, "UDP",
			func(r *ruleFixture, ports []portFixture) { r.RemotePort = ports }),
	})
}

func TestAccFirewallRuleGroup_rules_fqdn(t *testing.T) {
	rName := acctest.RandomResourceName()

	// FQDN rules are Windows, outbound, and cannot name a specific remote address.
	plain := newRule("Rule A", "ALLOW", "OUT", "TCP")
	plain.Fqdn = setVal("example.com")

	wildcard := newRule("Rule A", "ALLOW", "OUT", "TCP")
	wildcard.Fqdn = setVal("*.example.com")

	// Removing the FQDN turns the rule back into an IP address rule. The API
	// cannot erase the stored domain, so the provider disables it instead; from
	// Terraform's side the attribute must read back null.
	byAddress := newRule("Rule A", "ALLOW", "OUT", "TCP")
	byAddress.RemoteAddress = []addrFixture{addr("203.0.113.0", 24)}

	groupID := statecheck.CompareValue(compare.ValuesSame())
	ruleID := statecheck.CompareValue(compare.ValuesSame())

	step := func(r ruleFixture, plan resource.ConfigPlanChecks) resource.TestStep {
		g := newRuleGroup(rName, r)

		return resource.TestStep{
			Config:           g.hcl(),
			ConfigPlanChecks: plan,
			ConfigStateChecks: append(wantGroup(g),
				wantAPIPrecedence(),
				groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
				ruleID.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
			),
		}
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFirewallRuleGroupDestroy,
		Steps: []resource.TestStep{
			step(plain, resource.ConfigPlanChecks{}),
			// The import is what proves a disabled FQDN reads back as unset.
			importVerify(),
			step(wildcard, resource.ConfigPlanChecks{
				PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
				},
			}),
			// FQDN to IP in one apply.
			step(byAddress, resource.ConfigPlanChecks{
				PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
				},
			}),
			// And back, which must return remote_address to the wildcard default.
			step(wildcard, resource.ConfigPlanChecks{
				PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
				},
			}),
		},
	})
}

func TestAccFirewallRuleGroup_rules_networkLocation(t *testing.T) {
	rName := acctest.RandomResourceName()

	// Kept minimal on purpose. network_location shares an API array with
	// executable_path and service_name, and rules_executablePath owns the
	// coverage for their interaction.
	public := newTCPRule("Rule A")
	public.NetworkLocation = setVal("PUBLIC")
	private := newTCPRule("Rule A")
	private.NetworkLocation = setVal("PRIVATE")
	omitted := newTCPRule("Rule A")

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFirewallRuleGroupDestroy,
		Steps:                    lifecycleSteps(rName, public, private, omitted),
	})
}

func TestAccFirewallRuleGroup_rules_executablePath(t *testing.T) {
	rName := acctest.RandomResourceName()

	// This rule is deliberately not minimal. network_location, executable_path and
	// service_name are three named entries in one API fields array, and a rule
	// update rewrites that whole array whenever any of the three changes, so
	// correctness depends on the rewrite re-emitting the entries the user did not
	// touch. With the other two unset the array is trivial and there is nothing to
	// lose, and the failure mode is silent.
	base := newTCPRule("Rule A")
	base.ExecutablePath = setVal(`C:\Windows\System32\svchost.exe`)
	base.ServiceName = setVal("TestService")
	base.NetworkLocation = setVal("PUBLIC")
	base.WatchMode = setVal(true)
	base.LocalAddress = []addrFixture{addr("192.168.1.0", 24)}
	base.LocalPort = []portFixture{port(5000, 5100)}
	base.RemotePort = []portFixture{port(6000, 6100)}

	// Change one of the three and leave the others alone.
	changed := base
	changed.ExecutablePath = setVal(`C:\Windows\System32\curl.exe`)

	// Clear one while its siblings stay populated, which is the transition most
	// likely to take the others with it.
	cleared := changed
	cleared.ExecutablePath = opt[string]{}

	// Every optional value dropped in a single apply: the fields array goes all
	// empty, the monitor object is replaced with null, the address list returns to
	// the wildcard and both port lists are removed at once.
	stripped := newTCPRule("Rule A")

	groupID := statecheck.CompareValue(compare.ValuesSame())
	ruleID := statecheck.CompareValue(compare.ValuesSame())

	step := func(r ruleFixture, plan resource.ConfigPlanChecks) resource.TestStep {
		g := newRuleGroup(rName, r)

		return resource.TestStep{
			Config:           g.hcl(),
			ConfigPlanChecks: plan,
			ConfigStateChecks: append(wantGroup(g),
				wantAPIPrecedence(),
				groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
				ruleID.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
			),
		}
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFirewallRuleGroupDestroy,
		Steps: []resource.TestStep{
			step(base, resource.ConfigPlanChecks{}),
			// The only import of a rule carrying all three fields-backed values.
			importVerify(),
			step(changed, resource.ConfigPlanChecks{
				PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
				},
			}),
			step(cleared, resource.ConfigPlanChecks{
				PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
				},
			}),
			step(stripped, resource.ConfigPlanChecks{
				PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
				},
			}),
		},
	})
}

func TestAccFirewallRuleGroup_rules_serviceName(t *testing.T) {
	rName := acctest.RandomResourceName()

	// Minimal: rules_executablePath owns the shared fields array coverage.
	serviceA := newTCPRule("Rule A")
	serviceA.ServiceName = setVal("TestServiceA")
	serviceB := newTCPRule("Rule A")
	serviceB.ServiceName = setVal("TestServiceB")
	omitted := newTCPRule("Rule A")

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFirewallRuleGroupDestroy,
		Steps:                    lifecycleSteps(rName, serviceA, serviceB, omitted),
	})
}

func TestAccFirewallRuleGroup_rules_icmpType(t *testing.T) {
	rName := acctest.RandomResourceName()

	// An explicit non-wildcard type with the code omitted, so the code defaults.
	explicit := newRule("Rule A", "ALLOW", "IN", "ICMPV4")
	explicit.IcmpType = setVal("8")

	// Removing it returns the wildcard, not null, because the rule is still ICMP.
	omitted := newRule("Rule A", "ALLOW", "IN", "ICMPV4")

	// Writing the wildcard out means the same thing as omitting it.
	spelled := newRule("Rule A", "ALLOW", "IN", "ICMPV4")
	spelled.IcmpType = setVal("*")
	spelled.IcmpCode = setVal("*")

	groupID := statecheck.CompareValue(compare.ValuesSame())
	ruleID := statecheck.CompareValue(compare.ValuesSame())

	step := func(r ruleFixture, plan resource.ConfigPlanChecks) resource.TestStep {
		g := newRuleGroup(rName, r)

		return resource.TestStep{
			Config:           g.hcl(),
			ConfigPlanChecks: plan,
			ConfigStateChecks: append(wantGroup(g),
				wantAPIPrecedence(),
				groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
				ruleID.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
			),
		}
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFirewallRuleGroupDestroy,
		Steps: []resource.TestStep{
			step(explicit, resource.ConfigPlanChecks{}),
			importVerify(),
			step(omitted, resource.ConfigPlanChecks{
				PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
				},
			}),
			step(spelled, resource.ConfigPlanChecks{
				PreApply: []plancheck.PlanCheck{
					plancheck.ExpectEmptyPlan(),
				},
			}),
		},
	})
}

func TestAccFirewallRuleGroup_rules_icmpCode(t *testing.T) {
	rName := acctest.RandomResourceName()

	// An explicit code with the type omitted, the mirror of rules_icmpType.
	explicit := newRule("Rule A", "ALLOW", "IN", "ICMPV4")
	explicit.IcmpCode = setVal("0")

	omitted := newRule("Rule A", "ALLOW", "IN", "ICMPV4")

	spelled := newRule("Rule A", "ALLOW", "IN", "ICMPV4")
	spelled.IcmpType = setVal("*")
	spelled.IcmpCode = setVal("*")

	groupID := statecheck.CompareValue(compare.ValuesSame())
	ruleID := statecheck.CompareValue(compare.ValuesSame())

	step := func(r ruleFixture, plan resource.ConfigPlanChecks) resource.TestStep {
		g := newRuleGroup(rName, r)

		return resource.TestStep{
			Config:           g.hcl(),
			ConfigPlanChecks: plan,
			ConfigStateChecks: append(wantGroup(g),
				wantAPIPrecedence(),
				groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
				ruleID.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
			),
		}
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFirewallRuleGroupDestroy,
		Steps: []resource.TestStep{
			step(explicit, resource.ConfigPlanChecks{}),
			importVerify(),
			step(omitted, resource.ConfigPlanChecks{
				PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
				},
			}),
			step(spelled, resource.ConfigPlanChecks{
				PreApply: []plancheck.PlanCheck{
					plancheck.ExpectEmptyPlan(),
				},
			}),
		},
	})
}

func TestAccFirewallRuleGroup_rules_watchMode(t *testing.T) {
	rName := acctest.RandomResourceName()

	watching := newTCPRule("Rule A")
	watching.WatchMode = setVal(true)
	// Explicitly false and omitted are the same value, so the last step must plan
	// nothing rather than an update.
	enforcing := newTCPRule("Rule A")
	enforcing.WatchMode = setVal(false)
	omitted := newTCPRule("Rule A")

	groupID := statecheck.CompareValue(compare.ValuesSame())
	ruleID := statecheck.CompareValue(compare.ValuesSame())

	step := func(r ruleFixture, plan resource.ConfigPlanChecks) resource.TestStep {
		g := newRuleGroup(rName, r)

		return resource.TestStep{
			Config:           g.hcl(),
			ConfigPlanChecks: plan,
			ConfigStateChecks: append(wantGroup(g),
				wantAPIPrecedence(),
				groupID.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
				ruleID.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
			),
		}
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFirewallRuleGroupDestroy,
		Steps: []resource.TestStep{
			step(watching, resource.ConfigPlanChecks{}),
			importVerify(),
			// Turning it off is a real change.
			step(enforcing, resource.ConfigPlanChecks{
				PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
				},
			}),
			// Removing the explicit false is not.
			step(omitted, resource.ConfigPlanChecks{
				PreApply: []plancheck.PlanCheck{
					plancheck.ExpectEmptyPlan(),
				},
			}),
		},
	})
}

func TestAccFirewallRuleGroup_drift(t *testing.T) {
	rName := acctest.RandomResourceName()

	// This test is separate because every scenario needs an out-of-band mutation
	// followed by a refresh. It covers drift to the group's own attributes as well
	// as to its rules, which is why it is not named rules_drift.
	ruleA := newTCPRule("Rule A")
	ruleA.RemotePort = []portFixture{port(8081)}

	ruleB := newTCPRule("Rule B")
	ruleB.Description = setVal("Configured description")
	ruleB.RemotePort = []portFixture{port(8082)}
	ruleB.NetworkLocation = setVal("PUBLIC")
	ruleB.LocalAddress = []addrFixture{addr("192.168.10.0", 24), addr("10.1.0.0", 16)}
	ruleB.LocalPort = []portFixture{port(6000, 6100), port(7000)}
	ruleB.WatchMode = setVal(true)

	ruleC := newTCPRule("Rule C")
	ruleC.RemotePort = []portFixture{port(8083)}

	g := newRuleGroup(rName, ruleA, ruleB, ruleC)
	g.Description = setVal("Configured group description")

	var groupID string
	var ids ruleIDs

	groupIdentity := statecheck.CompareValue(compare.ValuesSame())
	// A and C are never the target of a mutation, so they must survive every
	// scenario with their identities intact.
	idA := statecheck.CompareValue(compare.ValuesSame())
	idC := statecheck.CompareValue(compare.ValuesSame())

	ctx := context.Background()

	requireGroupID := func() {
		if groupID == "" {
			t.Fatal("group id was not captured")
		}
	}

	// reconcile reapplies the original configuration and asserts the whole group
	// came back, including the rules that were never touched.
	reconcile := func() resource.TestStep {
		return resource.TestStep{
			Config: g.hcl(),
			ConfigStateChecks: append(wantGroup(g),
				wantAPIPrecedence(), wantRuleIDsUsable(), captureRuleIDs(&ids),
				groupIdentity.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
				idA.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
				idC.AddStateValue(ruleGroupResourceName, ruleIDPath(2)),
			),
		}
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFirewallRuleGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: g.hcl(),
				ConfigStateChecks: append(wantGroup(g),
					wantAPIPrecedence(), wantRuleIDsUsable(),
					captureGroupID(&groupID), captureRuleIDs(&ids),
					groupIdentity.AddStateValue(ruleGroupResourceName, tfjsonpath.New("id")),
					idA.AddStateValue(ruleGroupResourceName, ruleIDPath(0)),
					idC.AddStateValue(ruleGroupResourceName, ruleIDPath(2)),
				),
			},

			// Scenario A, group scalar drift. Simplest, and it establishes the
			// fixture the rule scenarios then mutate. Correcting the group must not
			// churn its rules, which is what the reconcile assertions are for.
			refreshExpectingUpdate(func() {
				requireGroupID()
				if err := editAPIRuleGroupScalars(ctx, groupID, map[string]any{
					"name":        rName + "-drifted",
					"description": "Changed outside Terraform",
					"enabled":     false,
				}); err != nil {
					t.Fatalf("drifting group scalars: %s", err)
				}
			}),
			reconcile(),

			// Scenario B, same-identity external content edit. Only scalars can be
			// replaced in place; a list, the fields array and the monitor object
			// cannot, which is why the numeric protocol rides along here and the
			// rest belongs to scenario C.
			refreshExpectingUpdate(func() {
				requireGroupID()
				before, after, err := editAPIRuleFieldsInPlace(ctx, groupID, 1, map[string]any{
					"name":        "Rule B drifted",
					"description": "Changed outside Terraform",
					"enabled":     false,
					"action":      "DENY",
					"direction":   "IN",
					// The IANA number for UDP. Reading it back has to map to the
					// named protocol the configuration uses.
					"protocol": "17",
				})
				if err != nil {
					t.Fatalf("drifting rule B in place: %s", err)
				}
				// The premise of this scenario is that the identity survived, so
				// that detection has to come from comparing contents. If the API
				// starts replacing the rule for this mutation, fail rather than
				// silently changing what the scenario proves.
				if before != after {
					t.Fatalf("in-place edit replaced rule B (%s -> %s); this scenario needs an identity-preserving mutation", before, after)
				}
			}),
			reconcile(),

			// Scenario C, nested list drift plus the values only a remove-and-add
			// can set. This mutation mints a new identity for B, so it makes no
			// claim about preserving one; what it proves is that the fields array,
			// the monitor object and a numeric protocol all read back correctly and
			// are then corrected.
			refreshExpectingUpdate(func() {
				requireGroupID()
				if err := replaceAPIRule(ctx, groupID, 1, apiRulePayload{
					name:        "Rule B replaced",
					description: "Replaced outside Terraform",
					enabled:     false,
					action:      "DENY",
					direction:   "IN",
					protocol:    "17",
					remotePort:  9999,
					localAddress: []apiAddress{
						{address: "10.9.9.0", netmask: 24},
						{address: "172.31.0.0", netmask: 16},
					},
					watchMode:       false,
					networkLocation: "PRIVATE",
				}); err != nil {
					t.Fatalf("replacing rule B out of band: %s", err)
				}
			}),
			reconcile(),

			// Scenario D, the middle rule deleted remotely. It has to come back at
			// its configured position with a new identity, without disturbing its
			// neighbours.
			refreshExpectingUpdate(func() {
				requireGroupID()
				if err := deleteAPIRule(ctx, groupID, 1); err != nil {
					t.Fatalf("deleting rule B out of band: %s", err)
				}
			}),
			reconcile(),

			// Scenario E, an unmanaged rule inserted between A and B. It has to be
			// removed without the configured rules losing their identities.
			refreshExpectingUpdate(func() {
				requireGroupID()
				if err := insertAPIRule(ctx, groupID, 1, apiRulePayload{
					name:       "Unmanaged X",
					enabled:    true,
					action:     "ALLOW",
					direction:  "OUT",
					protocol:   "6",
					remotePort: 9100,
				}); err != nil {
					t.Fatalf("inserting an unmanaged rule: %s", err)
				}
			}),
			reconcile(),

			// Scenario F, precedence reordered remotely with no content change.
			// This must be detected rather than absorbed by sorting the API's rules
			// into state's order.
			refreshExpectingUpdate(func() {
				requireGroupID()
				if err := rotateAPIRuleOrder(ctx, groupID); err != nil {
					t.Fatalf("reordering rule_ids out of band: %s", err)
				}
			}),
			reconcile(),
		},
	})
}

// The validation test builds its configurations from raw HCL rather than from the
// fixtures: it needs invalid values, and a fixture that could express an invalid
// state would be a fixture that could produce one by accident.

// validRuleBody is a minimal valid rule, for appending one invalid attribute to.
const validRuleBody = `      name = "Rule A"
      action = "ALLOW"
      direction = "OUT"
      protocol = "TCP"`

// icmpRuleBody is a minimal valid ICMP rule, so an invalid icmp_type or icmp_code
// is rejected by its own validator rather than by applicability.
const icmpRuleBody = `      name = "Rule A"
      action = "ALLOW"
      direction = "IN"
      protocol = "ICMPV4"`

// rawRuleGroupHCL renders a group with at most one rule, both given as raw HCL.
// An empty ruleBody omits the rules attribute entirely.
func rawRuleGroupHCL(name, platform, extraGroupAttrs, ruleBody string) string {
	attrs := fmt.Sprintf("  name = %q\n  platform = %q\n  enabled = true", name, platform)
	if extraGroupAttrs != "" {
		attrs += "\n" + extraGroupAttrs
	}

	rules := ""
	if ruleBody != "" {
		rules = fmt.Sprintf("\n\n  rules = [\n    {\n%s\n    }\n  ]", ruleBody)
	}

	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
%s%s
}
`, attrs, rules)
}

func TestAccFirewallRuleGroup_validation(t *testing.T) {
	rName := acctest.RandomResourceName()

	// Every case is rejected at plan time, so nothing reaches the API and there is
	// no CheckDestroy. The point is to prove validation is wired to the right
	// schema paths; exhaustive value-level coverage lives in the unit tests.
	//
	// Each case carries only its own delta from a valid Windows group.
	cases := []struct {
		name string
		// groupName is the resource's name attribute; empty means a valid random one.
		groupName string
		// platform empty means Windows.
		platform string
		// groupAttrs is raw HCL appended to the group's own attributes.
		groupAttrs string
		// rule is a raw HCL rule body; empty omits the rules attribute.
		rule string
		err  *regexp.Regexp
	}{
		// Group-level schema validators.
		{
			name:      "group name too long",
			groupName: strings.Repeat("a", 256),
			err:       regexp.MustCompile(`string length must be between 1 and 255`),
		},
		{
			name:       "group description too long",
			groupAttrs: fmt.Sprintf("  description = %q", strings.Repeat("a", 501)),
			err:        regexp.MustCompile(`string length must be at most 500`),
		},
		{
			name:       "group description whitespace only",
			groupAttrs: `  description = " "`,
			err:        regexp.MustCompile(`(?i)whitespace`),
		},
		{
			name:     "invalid platform",
			platform: "Solaris",
			err:      regexp.MustCompile(`value must be one of`),
		},

		// Rule-level schema validators.
		{
			name: "rule name empty",
			rule: `      name = ""
      action = "ALLOW"
      direction = "OUT"
      protocol = "TCP"`,
			err: regexp.MustCompile(`string length must be between 1 and 255`),
		},
		{
			name: "rule description whitespace only",
			rule: validRuleBody + "\n" + `      description = "   "`,
			err:  regexp.MustCompile(`(?i)whitespace`),
		},
		{
			name: "invalid action",
			rule: `      name = "Rule A"
      action = "MAYBE"
      direction = "OUT"
      protocol = "TCP"`,
			err: regexp.MustCompile(`value must be one of`),
		},
		{
			name: "invalid direction",
			rule: `      name = "Rule A"
      action = "ALLOW"
      direction = "SIDEWAYS"
      protocol = "TCP"`,
			err: regexp.MustCompile(`value must be one of`),
		},
		{
			name: "invalid protocol",
			rule: `      name = "Rule A"
      action = "ALLOW"
      direction = "OUT"
      protocol = "CARRIER PIGEON"`,
			err: regexp.MustCompile(`value must be one of`),
		},
		{
			name: "invalid address family",
			rule: validRuleBody + "\n" + `      address_family = "IP5"`,
			err:  regexp.MustCompile(`value must be one of`),
		},
		{
			name: "empty local address list",
			rule: validRuleBody + "\n" + `      local_address = []`,
			err:  regexp.MustCompile(`list must contain at least 1 elements`),
		},
		{
			name: "empty remote address list",
			rule: validRuleBody + "\n" + `      remote_address = []`,
			err:  regexp.MustCompile(`list must contain at least 1 elements`),
		},
		{
			name: "empty local port list",
			rule: validRuleBody + "\n" + `      local_port = []`,
			err:  regexp.MustCompile(`list must contain at least 1 elements`),
		},
		{
			name: "empty remote port list",
			rule: validRuleBody + "\n" + `      remote_port = []`,
			err:  regexp.MustCompile(`list must contain at least 1 elements`),
		},
		{
			name: "empty icmp type",
			rule: icmpRuleBody + "\n" + `      icmp_type = ""`,
			err:  regexp.MustCompile(`string length must be at least 1`),
		},
		{
			name: "empty icmp code",
			rule: icmpRuleBody + "\n" + `      icmp_code = ""`,
			err:  regexp.MustCompile(`string length must be at least 1`),
		},
		{
			name: "empty nested address",
			rule: validRuleBody + "\n" + `      local_address = [{ address = "" }]`,
			err:  regexp.MustCompile(`string length must be at least 1`),
		},
		{
			name: "netmask out of range",
			rule: validRuleBody + "\n" + `      local_address = [{ address = "10.0.0.0", netmask = 129 }]`,
			err:  regexp.MustCompile(`value must be between 0 and 128`),
		},
		{
			name: "port start out of range",
			rule: validRuleBody + "\n" + `      local_port = [{ start = 0 }]`,
			err:  regexp.MustCompile(`value must be between 1 and 65535`),
		},
		{
			name: "port end out of range",
			rule: validRuleBody + "\n" + `      local_port = [{ start = 443, end = 70000 }]`,
			err:  regexp.MustCompile(`value must be between 0 and 65535`),
		},

		// ruleAttributeApplicability wiring.
		{
			name: "icmp type on a non-icmp protocol",
			rule: validRuleBody + "\n" + `      icmp_type = "8"`,
			err:  regexp.MustCompile(`icmp_type is only valid for ICMPV4 or ICMPV6 protocols`),
		},
		{
			name: "icmp code on a non-icmp protocol",
			rule: validRuleBody + "\n" + `      icmp_code = "0"`,
			err:  regexp.MustCompile(`icmp_code is only valid for ICMPV4 or ICMPV6 protocols`),
		},
		{
			// A wildcard is still ICMP data: the payload builder sends no icmp
			// object at all for a non-ICMP rule, so this cannot round trip.
			name: "wildcard icmp type on a non-icmp protocol",
			rule: validRuleBody + "\n" + `      icmp_type = "*"`,
			err:  regexp.MustCompile(`icmp_type is only valid for ICMPV4 or ICMPV6 protocols`),
		},
		{
			name: "wildcard icmp code on a non-icmp protocol",
			rule: validRuleBody + "\n" + `      icmp_code = "*"`,
			err:  regexp.MustCompile(`icmp_code is only valid for ICMPV4 or ICMPV6 protocols`),
		},
		{
			name: "specific local address with address family any",
			rule: validRuleBody + "\n" + `      address_family = "ANY"
      local_address = [{ address = "10.0.0.0", netmask = 8 }]`,
			err: regexp.MustCompile(`local_address cannot name specific addresses when address_family is 'ANY'`),
		},
		{
			// ICMPv6 runs only over IPv6, and address_family defaults to IP4, so the
			// bare ICMPV6 rule is the likeliest spelling of this mistake.
			name: "icmpv6 with the default address family",
			rule: `      name = "Rule A"
      action = "ALLOW"
      direction = "IN"
      protocol = "ICMPV6"`,
			err: regexp.MustCompile(`address_family defaults to 'IP4', which is not allowed with protocol ICMPV6`),
		},
		{
			name: "icmpv6 with address family ip4",
			rule: `      name = "Rule A"
      action = "ALLOW"
      direction = "IN"
      protocol = "ICMPV6"
      address_family = "IP4"`,
			err: regexp.MustCompile(`address_family 'IP4' is not allowed with protocol ICMPV6. Use 'IP6' or 'ANY'`),
		},
		{
			name: "icmpv4 with address family ip6",
			rule: icmpRuleBody + "\n" + `      address_family = "IP6"`,
			err:  regexp.MustCompile(`address_family 'IP6' is not allowed with protocol ICMPV4. Use 'IP4' or 'ANY'`),
		},
		{
			name: "specific remote address with address family any",
			rule: validRuleBody + "\n" + `      address_family = "ANY"
      remote_address = [{ address = "10.0.0.0", netmask = 8 }]`,
			err: regexp.MustCompile(`remote_address cannot name specific addresses when address_family is 'ANY'`),
		},
		{
			name: "netmask on the wildcard address",
			rule: validRuleBody + "\n" + `      local_address = [{ address = "*", netmask = 24 }]`,
			err:  regexp.MustCompile(`netmask must be 0, or omitted, on the '\*' address`),
		},
		{
			name: "port range end equal to start",
			rule: validRuleBody + "\n" + `      local_port = [{ start = 443, end = 443 }]`,
			err:  regexp.MustCompile(`end \(443\) must be greater than start \(443\)`),
		},
		{
			name: "port range end below start",
			rule: validRuleBody + "\n" + `      local_port = [{ start = 9000, end = 8000 }]`,
			err:  regexp.MustCompile(`end \(8000\) must be greater than start \(9000\)`),
		},

		// ValidateConfig wiring.
		{
			name: "fqdn with a non-outbound direction",
			rule: `      name = "Rule A"
      action = "ALLOW"
      direction = "IN"
      protocol = "TCP"
      fqdn = "example.com"`,
			err: regexp.MustCompile(`FQDN rules must have direction set to 'OUT'`),
		},
		{
			name: "fqdn with an explicit remote address",
			rule: validRuleBody + "\n" + `      fqdn = "example.com"
      remote_address = [{ address = "10.0.0.0", netmask = 8 }]`,
			err: regexp.MustCompile(`FQDN and remote_address cannot be used together`),
		},
		{
			name:     "fqdn on linux",
			platform: "Linux",
			rule:     validRuleBody + "\n" + `      fqdn = "example.com"`,
			err:      regexp.MustCompile(`FQDN is not supported on Linux platform`),
		},
		{
			name: "fqdn containing a subdirectory",
			rule: validRuleBody + "\n" + `      fqdn = "example.com/api"`,
			err:  regexp.MustCompile(`FQDN should not contain subdirectories`),
		},
		{
			name: "empty fqdn",
			rule: validRuleBody + "\n" + `      fqdn = ""`,
			err:  regexp.MustCompile(`(?i)whitespace`),
		},
		{
			name:     "service name outside windows",
			platform: "Mac",
			rule:     validRuleBody + "\n" + `      service_name = "TestService"`,
			err:      regexp.MustCompile(`service_name is only supported on Windows platform`),
		},
		{
			name: "empty service name",
			rule: validRuleBody + "\n" + `      service_name = ""`,
			err:  regexp.MustCompile(`(?i)whitespace`),
		},
		{
			name:     "executable path on linux",
			platform: "Linux",
			rule:     validRuleBody + "\n" + `      executable_path = "/usr/bin/curl"`,
			err:      regexp.MustCompile(`executable_path is not supported on Linux platform`),
		},
		{
			name: "empty executable path",
			rule: validRuleBody + "\n" + `      executable_path = ""`,
			err:  regexp.MustCompile(`(?i)whitespace`),
		},
		{
			// One representative unsupported protocol. The unit tests cover all
			// five without a live Terraform run each.
			name:     "unsupported protocol on linux",
			platform: "Linux",
			rule: `      name = "Rule A"
      action = "ALLOW"
      direction = "OUT"
      protocol = "GRE"`,
			err: regexp.MustCompile(`Protocol 'GRE' is not supported on Linux platform`),
		},
		{
			name:     "non-any network location on linux",
			platform: "Linux",
			rule:     validRuleBody + "\n" + `      network_location = "PUBLIC"`,
			err:      regexp.MustCompile(`network_location must be 'ANY' on Linux platform`),
		},
		{
			name: "local port on a protocol without ports",
			rule: `      name = "Rule A"
      action = "ALLOW"
      direction = "OUT"
      protocol = "ANY"
      local_port = [{ start = 443 }]`,
			err: regexp.MustCompile(`local_port is only valid for TCP or UDP protocols`),
		},
		{
			name: "remote port on a protocol without ports",
			rule: `      name = "Rule A"
      action = "ALLOW"
      direction = "OUT"
      protocol = "ANY"
      remote_port = [{ start = 443 }]`,
			err: regexp.MustCompile(`remote_port is only valid for TCP or UDP protocols`),
		},
	}

	for _, c := range cases {
		// One terraform run per case rather than one run of many steps, bought in
		// exchange for a failure that names the case instead of a step number.
		t.Run(c.name, func(t *testing.T) {
			groupName := c.groupName
			if groupName == "" {
				groupName = rName
			}
			platform := c.platform
			if platform == "" {
				platform = "Windows"
			}

			resource.ParallelTest(t, resource.TestCase{
				PreCheck:                 func() { acctest.PreCheck(t) },
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config:      rawRuleGroupHCL(groupName, platform, c.groupAttrs, c.rule),
						ExpectError: c.err,
					},
				},
			})
		})
	}
}
