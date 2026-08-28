package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/swag"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func fwRule(id, family, name string) *models.FwmgrFirewallRuleV1 {
	return &models.FwmgrFirewallRuleV1{
		ID:     &id,
		Family: &family,
		Name:   &name,
	}
}

// tfRule is a TCP rule with nothing restricted, as the provider records one: the
// address lists carry the wildcard the API keeps there and the schema defaults them
// to, and the ICMP values are null because the protocol is not ICMP.
func tfRule(id, name string) firewallRuleModel {
	return firewallRuleModel{
		ID:              types.StringValue(id),
		Name:            types.StringValue(name),
		Description:     types.StringNull(),
		Enabled:         types.BoolValue(true),
		Action:          types.StringValue("DENY"),
		Direction:       types.StringValue("OUT"),
		Protocol:        types.StringValue("TCP"),
		AddressFamily:   types.StringValue("IP4"),
		LocalAddress:    wildcardAddressList(),
		RemoteAddress:   wildcardAddressList(),
		LocalPort:       types.ListNull(types.ObjectType{AttrTypes: portRangeAttrTypes()}),
		RemotePort:      types.ListNull(types.ObjectType{AttrTypes: portRangeAttrTypes()}),
		Fqdn:            types.StringNull(),
		NetworkLocation: types.StringValue("ANY"),
		ExecutablePath:  types.StringNull(),
		ServiceName:     types.StringNull(),
		IcmpType:        types.StringNull(),
		IcmpCode:        types.StringNull(),
		WatchMode:       types.BoolValue(false),
	}
}

// planRule mirrors what the framework hands Update: a computed id inside a list
// element is unknown whenever the plan differs from state, so correlation may
// not depend on it.
func planRule(name string) firewallRuleModel {
	rule := tfRule("", name)
	rule.ID = types.StringUnknown()
	return rule
}

// withAllowAction returns rule with its action flipped to ALLOW, the smallest
// content change a test can make to a rule.
func withAllowAction(rule firewallRuleModel) firewallRuleModel {
	rule.Action = types.StringValue("ALLOW")
	return rule
}

// stateRuleFamilies is the rule_ids array a group holds for these state rules.
// buildDiffOperations requires the two to agree, element for element, so the
// cases below derive it rather than restate it.
func stateRuleFamilies(rules []firewallRuleModel) []string {
	families := make([]string, 0, len(rules))
	for _, rule := range rules {
		families = append(families, rule.ID.ValueString())
	}
	return families
}

// tfList builds the object list the schema uses for a nested attribute. It panics
// rather than reporting diagnostics, in the manner of types.ListValueMust: the
// elements are static literals, so a conversion failure is a bug in the test
// itself rather than an outcome worth asserting on.
func tfList[T any](attrTypes map[string]attr.Type, elems []T) types.List {
	list, diags := types.ListValueFrom(
		context.Background(),
		types.ObjectType{AttrTypes: attrTypes},
		elems,
	)
	if diags.HasError() {
		panic(fmt.Sprintf("building a list of %T: %v", elems, diags))
	}
	return list
}

func addressRangeList(address string, netmask int64) types.List {
	return tfList(addressRangeAttrTypes(), []addressRangeModel{{
		Address: types.StringValue(address),
		Netmask: types.Int64Value(netmask),
	}})
}

func portRangeList(start, end int64) types.List {
	return tfList(portRangeAttrTypes(), []portRangeModel{{
		Start: types.Int64Value(start),
		End:   types.Int64Value(end),
	}})
}

// diagSummaries and diagDetails render diagnostics for assertions that care about
// one half of the message: the summary classifies the failure, the detail carries
// the wording a practitioner reads.
func diagSummaries(diags diag.Diagnostics) []string {
	summaries := make([]string, 0, diags.ErrorsCount())
	for _, d := range diags.Errors() {
		summaries = append(summaries, d.Summary())
	}
	return summaries
}

func diagDetails(diags diag.Diagnostics) []string {
	details := make([]string, 0, diags.ErrorsCount())
	for _, d := range diags.Errors() {
		details = append(details, d.Detail())
	}
	return details
}

// wrapOneRule runs the read path over a single API rule and returns the model it
// produced, which is what every read-path assertion below works from.
func wrapOneRule(t *testing.T, apiRule *models.FwmgrFirewallRuleV1) firewallRuleModel {
	t.Helper()

	list, diags := wrapRules(context.Background(), []*models.FwmgrFirewallRuleV1{apiRule})
	if diags.HasError() {
		t.Fatalf("wrapRules: %v", diags)
	}
	var rules []firewallRuleModel
	if diags := list.ElementsAs(context.Background(), &rules, false); diags.HasError() {
		t.Fatalf("reading wrapped rules: %v", diags)
	}
	if len(rules) != 1 {
		t.Fatalf("wrapRules returned %d rules, want 1", len(rules))
	}
	return rules[0]
}

func ruleNames(rules []*models.FwmgrFirewallRuleV1) []string {
	names := make([]string, 0, len(rules))
	for _, r := range rules {
		names = append(names, swag.StringValue(r.Name))
	}
	return names
}

// ruleGroupModel builds a resource model whose group-level attributes are fixed,
// so any diff operation produced comes from the rules alone unless a test
// deliberately changes one of them.
func ruleGroupModel(t *testing.T, rules []firewallRuleModel) firewallRuleGroupResourceModel {
	t.Helper()
	return firewallRuleGroupResourceModel{
		ID:          types.StringValue("group-id"),
		Name:        types.StringValue("group"),
		Description: types.StringNull(),
		Platform:    types.StringValue("Windows"),
		Enabled:     types.BoolValue(true),
		Rules:       tfList(firewallRuleModel{}.attrTypes(), rules),
	}
}

// opSummary renders operations as "op path" so tests can assert on the shape of
// the patch without reproducing whole rule payloads. Two extras keep the summary
// from hiding a wrong payload: an add of a rule also carries the rule name and
// temp_id it is sending, because two such adds share the "/rules/-" path and
// would otherwise be indistinguishable, and any other operation carrying a value
// shows it, because "replace /name" alone does not say which name was sent.
// Object and array values are rendered as JSON, whose key order is sorted, since
// Go's map formatting is not stable across runs.
func opSummary(t *testing.T, ops []*models.FwmgrAPIJSONDiff) []string {
	t.Helper()
	out := make([]string, 0, len(ops))
	for i, op := range ops {
		summary := fmt.Sprintf("%s %s", *op.Op, *op.Path)
		switch {
		case *op.Op == "add" && *op.Path == "/rules/-":
			payload, ok := op.Value.(buildRuleAddValue)
			if !ok {
				t.Fatalf("operations[%d]: add value is %T, want buildRuleAddValue", i, op.Value)
			}
			summary = fmt.Sprintf(
				"%s name=%v temp_id=%v",
				summary,
				swag.StringValue(payload.Name),
				swag.StringValue(payload.TempID),
			)
		case op.Value != nil:
			encoded, err := json.Marshal(op.Value)
			if err != nil {
				t.Fatalf("operations[%d]: encoding value %v: %v", i, op.Value, err)
			}
			summary = fmt.Sprintf("%s value=%s", summary, encoded)
		case *op.Op != "remove":
			// A deliberate null, which is how icmp and monitor are cleared. Only a
			// remove is allowed to carry no value at all.
			summary += " value=null"
		}
		out = append(out, summary)
	}
	return out
}

// TestBuildDiffOperations covers the update shapes a user can produce. Expected
// values come from the API's contract: rule_ids is the complete final list in
// precedence order, diff_operations carries only the deltas, and a rule that is
// merely moved keeps its family so its Terraform id stays stable.
func TestBuildDiffOperations(t *testing.T) {
	t.Parallel()

	ruleA, ruleB, ruleC := tfRule("fam-a", "rule-a"), tfRule("fam-b", "rule-b"), tfRule("fam-c", "rule-c")
	planA, planB, planC := planRule("rule-a"), planRule("rule-b"), planRule("rule-c")

	editedB := withAllowAction(planRule("rule-b"))
	editedC := withAllowAction(planRule("rule-c"))

	renamedA := planRule("rule-a-renamed")

	// unrelatedNew shares neither a name nor any setting with the rule it takes
	// the place of, which is what stops it from inheriting that rule's identity.
	unrelatedNew := planRule("rule-new")
	unrelatedNew.Direction = types.StringValue("IN")

	// The duplicate pair: two rules that share a name and are told apart only by
	// their action. editedDup is the second one after an edit.
	dupState := withAllowAction(tfRule("fam-dup2", "rule-a"))
	dupPlan := withAllowAction(planRule("rule-a"))
	editedDup := dupPlan
	editedDup.Direction = types.StringValue("IN")

	tests := []struct {
		name       string
		stateRules []firewallRuleModel
		planRules  []firewallRuleModel
		// mutateState and mutatePlan change the group-level attributes, which are
		// otherwise identical on both sides.
		mutateState func(*firewallRuleGroupResourceModel)
		mutatePlan  func(*firewallRuleGroupResourceModel)
		wantOps     []string
		wantRuleIDs []string
	}{
		{
			// Nothing changed, so nothing is sent and Update skips the call.
			name:        "no changes",
			stateRules:  []firewallRuleModel{ruleA, ruleB, ruleC},
			planRules:   []firewallRuleModel{planA, planB, planC},
			wantOps:     []string{},
			wantRuleIDs: []string{"fam-a", "fam-b", "fam-c"},
		},
		{
			// Precedence lives in rule_ids, so a reorder needs no operations at
			// all and must not recreate any rule.
			name:        "reorder only",
			stateRules:  []firewallRuleModel{ruleA, ruleB, ruleC},
			planRules:   []firewallRuleModel{planC, planB, planA},
			wantOps:     []string{},
			wantRuleIDs: []string{"fam-c", "fam-b", "fam-a"},
		},
		{
			// Inserting shifts every later rule to a new index. Those rules are
			// unchanged, so they keep their families and only the new rule is added.
			name:        "insert in the middle",
			stateRules:  []firewallRuleModel{ruleA, ruleB, ruleC},
			planRules:   []firewallRuleModel{planA, planRule("rule-new"), planB, planC},
			wantOps:     []string{"add /rules/- name=rule-new temp_id=temp_id:1"},
			wantRuleIDs: []string{"fam-a", "temp_id:1", "fam-b", "fam-c"},
		},
		{
			// Deleting the first rule shifts the survivors. They must keep their
			// families rather than being torn down and rebuilt.
			name:        "delete first rule",
			stateRules:  []firewallRuleModel{ruleA, ruleB, ruleC},
			planRules:   []firewallRuleModel{planB, planC},
			wantOps:     []string{"remove /rules/0"},
			wantRuleIDs: []string{"fam-b", "fam-c"},
		},
		{
			name:        "delete middle rule",
			stateRules:  []firewallRuleModel{ruleA, ruleB, ruleC},
			planRules:   []firewallRuleModel{planA, planC},
			wantOps:     []string{"remove /rules/1"},
			wantRuleIDs: []string{"fam-a", "fam-c"},
		},
		{
			// A content change is applied in place, so the rule keeps the Rule ID
			// the console records events against. Its neighbours are untouched.
			name:        "edit one rule",
			stateRules:  []firewallRuleModel{ruleA, ruleB, ruleC},
			planRules:   []firewallRuleModel{planA, editedB, planC},
			wantOps:     []string{"replace /rules/1/action value=\"ALLOW\""},
			wantRuleIDs: []string{"fam-a", "fam-b", "fam-c"},
		},
		{
			// A rename is a content change, but it is still the same rule, so it
			// is an edit rather than a rewrite. If name were left out of the
			// comparison the rename would produce no operations and be lost.
			name:        "rename a rule",
			stateRules:  []firewallRuleModel{ruleA, ruleB},
			planRules:   []firewallRuleModel{renamedA, planB},
			wantOps:     []string{"replace /rules/0/name value=\"rule-a-renamed\""},
			wantRuleIDs: []string{"fam-a", "fam-b"},
		},
		{
			// A rule that both changed its name and its settings is not
			// recognizable as the rule that was there, so it is created fresh
			// rather than inheriting an unrelated rule's identity.
			name:       "rename plus a settings change recreates the rule",
			stateRules: []firewallRuleModel{ruleA, ruleB},
			planRules:  []firewallRuleModel{withAllowAction(planRule("rule-a-renamed")), planB},
			wantOps: []string{
				"remove /rules/0",
				"add /rules/- name=rule-a-renamed temp_id=temp_id:1",
			},
			wantRuleIDs: []string{"temp_id:1", "fam-b"},
		},
		{
			// Edited and moved in the same apply. The same-position pass cannot
			// pair them, so the identity has to survive the fallback pass.
			name:        "edit and reorder together",
			stateRules:  []firewallRuleModel{ruleA, ruleB},
			planRules:   []firewallRuleModel{planB, withAllowAction(planRule("rule-a"))},
			wantOps:     []string{"replace /rules/0/action value=\"ALLOW\""},
			wantRuleIDs: []string{"fam-b", "fam-a"},
		},
		{
			// Removes must be emitted in descending index order, because each
			// remove shifts the indices of the operations that follow it.
			name:        "multiple deletes are descending",
			stateRules:  []firewallRuleModel{ruleA, ruleB, ruleC},
			planRules:   []firewallRuleModel{planB},
			wantOps:     []string{"remove /rules/2", "remove /rules/0"},
			wantRuleIDs: []string{"fam-b"},
		},
		{
			// Add, delete, reorder and edit together. rule-a is dropped, rule-new
			// is added in its place but shares nothing with it, rule-c is edited,
			// and rule-b only moves. The edit is at a higher index than the
			// delete, which is why every edit is emitted before any remove: once
			// /rules/0 is gone, /rules/2 is a different rule.
			name:       "combined add, delete, reorder and edit",
			stateRules: []firewallRuleModel{ruleA, ruleB, ruleC},
			planRules:  []firewallRuleModel{unrelatedNew, editedC, planB},
			wantOps: []string{
				"replace /rules/2/action value=\"ALLOW\"",
				"remove /rules/0",
				"add /rules/- name=rule-new temp_id=temp_id:1",
			},
			wantRuleIDs: []string{"temp_id:1", "fam-c", "fam-b"},
		},
		{
			// Duplicate names are legal in Falcon. Correlation is by content, so
			// same-named rules with different content stay distinct.
			name:        "duplicate names are not confused",
			stateRules:  []firewallRuleModel{ruleA, dupState},
			planRules:   []firewallRuleModel{planA, dupPlan},
			wantOps:     []string{},
			wantRuleIDs: []string{"fam-a", "fam-dup2"},
		},
		{
			// Editing one of two same-named rules must leave the other alone, and
			// must target the right index.
			name:        "editing one duplicate leaves the other alone",
			stateRules:  []firewallRuleModel{ruleA, dupState},
			planRules:   []firewallRuleModel{planA, editedDup},
			wantOps:     []string{"replace /rules/1/direction value=\"IN\""},
			wantRuleIDs: []string{"fam-a", "fam-dup2"},
		},
		{
			// Two fully identical rules are interchangeable, so reordering them
			// is a no-op rather than a rewrite.
			name:        "identical rules are interchangeable",
			stateRules:  []firewallRuleModel{tfRule("fam-1", "same"), tfRule("fam-2", "same")},
			planRules:   []firewallRuleModel{planRule("same"), planRule("same")},
			wantOps:     []string{},
			wantRuleIDs: []string{"fam-1", "fam-2"},
		},
		{
			name:        "all rules removed",
			stateRules:  []firewallRuleModel{ruleA, ruleB},
			planRules:   nil,
			wantOps:     []string{"remove /rules/1", "remove /rules/0"},
			wantRuleIDs: []string{},
		},
		{
			name:       "rules added to an empty group",
			stateRules: nil,
			planRules:  []firewallRuleModel{planA, planB},
			wantOps: []string{
				"add /rules/- name=rule-a temp_id=temp_id:1",
				"add /rules/- name=rule-b temp_id=temp_id:2",
			},
			wantRuleIDs: []string{"temp_id:1", "temp_id:2"},
		},
		{
			// Renaming the group is a group-level field change, independent of
			// the rules. Nothing else in the suite produces "replace /name".
			name:        "group renamed",
			stateRules:  []firewallRuleModel{ruleA, ruleB},
			planRules:   []firewallRuleModel{planA, planB},
			mutatePlan:  func(m *firewallRuleGroupResourceModel) { m.Name = types.StringValue("group-renamed") },
			wantOps:     []string{"replace /name value=\"group-renamed\""},
			wantRuleIDs: []string{"fam-a", "fam-b"},
		},
		{
			name:        "group description set",
			stateRules:  []firewallRuleModel{ruleA},
			planRules:   []firewallRuleModel{planA},
			mutatePlan:  func(m *firewallRuleGroupResourceModel) { m.Description = types.StringValue("a description") },
			wantOps:     []string{"replace /description value=\"a description\""},
			wantRuleIDs: []string{"fam-a"},
		},
		{
			// Clearing the description sends the empty string, which is how the
			// API spells "no description".
			name:        "group description cleared",
			stateRules:  []firewallRuleModel{ruleA},
			planRules:   []firewallRuleModel{planA},
			mutateState: func(m *firewallRuleGroupResourceModel) { m.Description = types.StringValue("a description") },
			wantOps:     []string{"replace /description value=\"\""},
			wantRuleIDs: []string{"fam-a"},
		},
		{
			name:        "group disabled",
			stateRules:  []firewallRuleModel{ruleA},
			planRules:   []firewallRuleModel{planA},
			mutatePlan:  func(m *firewallRuleGroupResourceModel) { m.Enabled = types.BoolValue(false) },
			wantOps:     []string{"replace /enabled value=false"},
			wantRuleIDs: []string{"fam-a"},
		},
		{
			// Group fields and rules change in the same apply. The group
			// operations come first, in schema order, and do not disturb the
			// rule indices the rule operations use.
			name:        "group fields and a rule change together",
			stateRules:  []firewallRuleModel{ruleA, ruleB, ruleC},
			planRules:   []firewallRuleModel{planA, editedB, planC},
			mutateState: func(m *firewallRuleGroupResourceModel) { m.Description = types.StringValue("old") },
			mutatePlan: func(m *firewallRuleGroupResourceModel) {
				m.Name = types.StringValue("group-renamed")
				m.Description = types.StringValue("new")
				m.Enabled = types.BoolValue(false)
			},
			wantOps: []string{
				"replace /name value=\"group-renamed\"",
				"replace /description value=\"new\"",
				"replace /enabled value=false",
				"replace /rules/1/action value=\"ALLOW\"",
			},
			wantRuleIDs: []string{"fam-a", "fam-b", "fam-c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			state := ruleGroupModel(t, tt.stateRules)
			plan := ruleGroupModel(t, tt.planRules)
			if tt.mutateState != nil {
				tt.mutateState(&state)
			}
			if tt.mutatePlan != nil {
				tt.mutatePlan(&plan)
			}
			ruleGroup := &models.FwmgrAPIRuleGroupV1{RuleIds: stateRuleFamilies(tt.stateRules)}

			ops, ruleIDs, versions, diags := buildDiffOperations(
				context.Background(), plan, state, ruleGroup,
			)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags)
			}

			if diff := cmp.Diff(tt.wantOps, opSummary(t, ops)); diff != "" {
				t.Errorf("operations (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantRuleIDs, ruleIDs); diff != "" {
				t.Errorf("rule_ids (-want +got):\n%s", diff)
			}
			// The API rejects a request whose rule_versions length differs from
			// rule_ids, whatever the values are.
			if len(versions) != len(ruleIDs) {
				t.Errorf("rule_versions has length %d, want %d", len(versions), len(ruleIDs))
			}
		})
	}
}

// TestBuildDiffOperationsRejectsMisalignedState guards the invariant the whole
// update path rests on. If state and rule_ids disagree, indices refer to the
// wrong rules and patching would silently corrupt the group.
func TestBuildDiffOperationsRejectsMisalignedState(t *testing.T) {
	t.Parallel()

	const wantSummary = "Firewall rule group state is out of sync"

	tests := []struct {
		name       string
		stateRules []firewallRuleModel
		ruleIDs    []string
	}{
		{
			name:       "fewer rules in state than rule_ids",
			stateRules: []firewallRuleModel{tfRule("fam-a", "rule-a")},
			ruleIDs:    []string{"fam-a", "fam-b"},
		},
		{
			// Reordered outside Terraform after the last refresh: the lengths
			// still agree, but every index now names a different rule.
			name:       "rule_ids reordered out of band",
			stateRules: []firewallRuleModel{tfRule("fam-a", "rule-a"), tfRule("fam-b", "rule-b")},
			ruleIDs:    []string{"fam-b", "fam-a"},
		},
		{
			// A rule replaced out of band keeps the count but not the identity.
			name:       "unknown family in rule_ids",
			stateRules: []firewallRuleModel{tfRule("fam-a", "rule-a")},
			ruleIDs:    []string{"fam-z"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			state := ruleGroupModel(t, tt.stateRules)
			plan := ruleGroupModel(t, []firewallRuleModel{planRule("rule-a")})
			ruleGroup := &models.FwmgrAPIRuleGroupV1{RuleIds: tt.ruleIDs}

			_, _, _, diags := buildDiffOperations(
				context.Background(), plan, state, ruleGroup,
			)
			if !diags.HasError() {
				t.Fatal("expected an error when state rules and rule_ids disagree")
			}
			// Assert the summary, not just that something failed: any other
			// error in the function would otherwise satisfy this test.
			if summaries := diagSummaries(diags); !slices.Contains(summaries, wantSummary) {
				t.Errorf("diagnostics %v, want one summarized %q", summaries, wantSummary)
			}
		})
	}
}

// TestRuleEditOps pins the operation and path for every attribute, and the order
// they are emitted in. Order is a correctness property: every remove of a list
// element has to precede every add, or the API's wildcard placeholder for an
// empty address list survives into the rebuilt list and silently widens the rule
// to match any address.
func TestRuleEditOps(t *testing.T) {
	t.Parallel()

	// icmpState makes the rule an ICMPV4 rule that restricts its type, which is the
	// starting point for every case whose subject is the icmp object.
	icmpState := func(rule *firewallRuleModel) {
		rule.Protocol = types.StringValue("ICMPV4")
		rule.IcmpType = types.StringValue("8")
	}

	tests := []struct {
		name string
		// mutateState may be nil; the base rule is the state rule otherwise.
		mutateState func(*firewallRuleModel)
		mutatePlan  func(*firewallRuleModel)
		platform    string
		wantOps     []string
	}{
		{
			name:       "name",
			mutatePlan: func(r *firewallRuleModel) { r.Name = types.StringValue("renamed") },
			wantOps:    []string{`replace /rules/2/name value="renamed"`},
		},
		{
			name:       "description set",
			mutatePlan: func(r *firewallRuleModel) { r.Description = types.StringValue("why") },
			wantOps:    []string{`replace /rules/2/description value="why"`},
		},
		{
			// The API spells "no description" as the empty string, and the read
			// maps it back to null.
			name:        "description cleared",
			mutateState: func(r *firewallRuleModel) { r.Description = types.StringValue("why") },
			wantOps:     []string{`replace /rules/2/description value=""`},
		},
		{
			name:       "enabled",
			mutatePlan: func(r *firewallRuleModel) { r.Enabled = types.BoolValue(false) },
			wantOps:    []string{"replace /rules/2/enabled value=false"},
		},
		{
			name:       "action",
			mutatePlan: func(r *firewallRuleModel) { r.Action = types.StringValue("ALLOW") },
			wantOps:    []string{`replace /rules/2/action value="ALLOW"`},
		},
		{
			name:       "direction",
			mutatePlan: func(r *firewallRuleModel) { r.Direction = types.StringValue("IN") },
			wantOps:    []string{`replace /rules/2/direction value="IN"`},
		},
		{
			// Protocols go out as IANA numbers.
			name:       "protocol",
			mutatePlan: func(r *firewallRuleModel) { r.Protocol = types.StringValue("UDP") },
			wantOps:    []string{`replace /rules/2/protocol value="17"`},
		},
		{
			name:       "protocol ANY",
			mutatePlan: func(r *firewallRuleModel) { r.Protocol = types.StringValue("ANY") },
			wantOps:    []string{`replace /rules/2/protocol value="*"`},
		},
		{
			// icmp follows protocol even though neither icmp attribute changed:
			// becoming an ICMP rule means gaining the object.
			name: "protocol becomes ICMP",
			mutatePlan: func(r *firewallRuleModel) {
				r.Protocol = types.StringValue("ICMPV4")
			},
			wantOps: []string{
				`replace /rules/2/protocol value="1"`,
				`replace /rules/2/icmp value={"icmp_code":"*","icmp_type":"*"}`,
			},
		},
		{
			// And leaving ICMP means losing it.
			name:        "protocol leaves ICMP",
			mutateState: icmpState,
			wantOps: []string{
				`replace /rules/2/protocol value="6"`,
				"replace /rules/2/icmp value=null",
			},
		},
		{
			name:        "icmp code added to an ICMP rule",
			mutateState: icmpState,
			mutatePlan: func(r *firewallRuleModel) {
				icmpState(r)
				r.IcmpCode = types.StringValue("0")
			},
			wantOps: []string{`replace /rules/2/icmp value={"icmp_code":"0","icmp_type":"8"}`},
		},
		{
			// icmp_type changing on its own, with the protocol untouched. The whole
			// icmp object is rewritten because the API takes it as one value.
			name:        "icmp type changed on an ICMP rule",
			mutateState: icmpState,
			mutatePlan: func(r *firewallRuleModel) {
				icmpState(r)
				r.IcmpType = types.StringValue("3")
			},
			wantOps: []string{`replace /rules/2/icmp value={"icmp_code":"*","icmp_type":"3"}`},
		},
		{
			name:       "address family",
			mutatePlan: func(r *firewallRuleModel) { r.AddressFamily = types.StringValue("ANY") },
			wantOps:    []string{`replace /rules/2/address_family value="NONE"`},
		},
		{
			name:       "watch mode on",
			mutatePlan: func(r *firewallRuleModel) { r.WatchMode = types.BoolValue(true) },
			wantOps:    []string{`replace /rules/2/monitor value={"count":"1","period_ms":"3600000"}`},
		},
		{
			// The whole monitor object is replaced, never its count leaf, which
			// the API accepts and ignores.
			name:        "watch mode off",
			mutateState: func(r *firewallRuleModel) { r.WatchMode = types.BoolValue(true) },
			wantOps:     []string{"replace /rules/2/monitor value=null"},
		},
		{
			// fqdn goes out with its flag, and the flag comes first.
			name:       "fqdn set",
			mutatePlan: func(r *firewallRuleModel) { r.Fqdn = types.StringValue("example.com") },
			wantOps: []string{
				"replace /rules/2/fqdn_enabled value=true",
				`replace /rules/2/fqdn value="example.com"`,
			},
		},
		{
			// The API rejects an empty fqdn, so clearing one is the flag alone.
			name:        "fqdn cleared",
			mutateState: func(r *firewallRuleModel) { r.Fqdn = types.StringValue("example.com") },
			wantOps:     []string{"replace /rules/2/fqdn_enabled value=false"},
		},
		{
			// The three fields-backed attributes share one operation, and the
			// array is always complete: the API merges fields by name, so an
			// omitted entry preserves the old value instead of clearing it.
			name:       "executable path set",
			mutatePlan: func(r *firewallRuleModel) { r.ExecutablePath = types.StringValue(`C:\curl.exe`) },
			wantOps: []string{
				`replace /rules/2/fields value=[{"name":"network_location","type":"set","values":["ANY"]},` +
					`{"name":"image_name","type":"windows_path","value":"C:\\curl.exe"},` +
					`{"name":"service_name","type":"string","value":""}]`,
			},
		},
		{
			// Clearing is the entry present with an empty value, which is the one
			// idiom the API honours: removing the entry is a silent no-op.
			name: "executable path and service name cleared",
			mutateState: func(r *firewallRuleModel) {
				r.ExecutablePath = types.StringValue(`C:\curl.exe`)
				r.ServiceName = types.StringValue("Service")
			},
			wantOps: []string{
				`replace /rules/2/fields value=[{"name":"network_location","type":"set","values":["ANY"]},` +
					`{"name":"image_name","type":"windows_path","value":""},` +
					`{"name":"service_name","type":"string","value":""}]`,
			},
		},
		{
			// service_name changing on its own still sends the complete fields
			// array, for the same reason: the API merges entries by name, so an
			// omitted one preserves the old value rather than clearing it.
			name:       "service name set",
			mutatePlan: func(r *firewallRuleModel) { r.ServiceName = types.StringValue("Service") },
			wantOps: []string{
				`replace /rules/2/fields value=[{"name":"network_location","type":"set","values":["ANY"]},` +
					`{"name":"image_name","type":"windows_path","value":""},` +
					`{"name":"service_name","type":"string","value":"Service"}]`,
			},
		},
		{
			// Mac and Linux have no service_name entry and a unix path type.
			name:       "network location on Mac",
			platform:   "Mac",
			mutatePlan: func(r *firewallRuleModel) { r.NetworkLocation = types.StringValue("PUBLIC") },
			wantOps: []string{
				`replace /rules/2/fields value=[{"name":"network_location","type":"set","values":["PUBLIC"]},` +
					`{"name":"image_name","type":"unix_path","value":""}]`,
			},
		},
		{
			// A port list Terraform holds as null is empty server-side, so
			// populating it is adds only.
			name: "port list populated",
			mutatePlan: func(r *firewallRuleModel) {
				r.LocalPort = portRangeList(443, 0)
			},
			wantOps: []string{`add /rules/2/local_port/0 value={"end":0,"start":443}`},
		},
		{
			name: "port list cleared",
			mutateState: func(r *firewallRuleModel) {
				r.LocalPort = portRangeList(443, 0)
			},
			wantOps: []string{"remove /rules/2/local_port/0"},
		},
		{
			// An unrestricted address list is the wildcard entry, on both sides, so
			// restricting the rule has to remove that entry before adding anything.
			// An implementation that treated "any" as zero elements would leave the
			// wildcard in place and the rule would keep matching every address.
			name: "address list populated from the wildcard",
			mutatePlan: func(r *firewallRuleModel) {
				r.LocalAddress = addressRangeList("10.0.0.0", 8)
			},
			wantOps: []string{
				"remove /rules/2/local_address/0",
				`add /rules/2/local_address/0 value={"address":"10.0.0.0","netmask":8}`,
			},
		},
		{
			// Going back to "any" is the same rebuild in reverse: the wildcard is a
			// value like any other, so it is removed and re-added rather than left to
			// the API to re-materialize.
			name: "address list cleared back to the wildcard",
			mutateState: func(r *firewallRuleModel) {
				r.LocalAddress = addressRangeList("10.0.0.0", 8)
			},
			wantOps: []string{
				"remove /rules/2/local_address/0",
				`add /rules/2/local_address/0 value={"address":"*","netmask":0}`,
			},
		},
		{
			// Removes descend so each index is still the last element when its
			// operation runs; adds then ascend into an empty array.
			name: "address list grown",
			mutateState: func(r *firewallRuleModel) {
				r.RemoteAddress = addressRangeList("10.0.0.0", 8)
			},
			mutatePlan: func(r *firewallRuleModel) {
				r.RemoteAddress = tfList(addressRangeAttrTypes(), []addressRangeModel{
					{Address: types.StringValue("10.0.0.0"), Netmask: types.Int64Value(8)},
					{Address: types.StringValue("172.16.0.0"), Netmask: types.Int64Value(12)},
				})
			},
			wantOps: []string{
				"remove /rules/2/remote_address/0",
				`add /rules/2/remote_address/0 value={"address":"10.0.0.0","netmask":8}`,
				`add /rules/2/remote_address/1 value={"address":"172.16.0.0","netmask":12}`,
			},
		},
		{
			// Two lists changing at once: all removes, then the scalar, then all
			// adds. A remove interleaved after an add would address the wrong
			// element.
			name: "several lists and a scalar together",
			mutateState: func(r *firewallRuleModel) {
				r.LocalPort = portRangeList(80, 0)
				r.LocalAddress = addressRangeList("10.0.0.0", 8)
			},
			mutatePlan: func(r *firewallRuleModel) {
				r.LocalPort = portRangeList(8080, 8090)
				r.Action = types.StringValue("ALLOW")
			},
			wantOps: []string{
				"remove /rules/2/local_address/0",
				"remove /rules/2/local_port/0",
				`replace /rules/2/action value="ALLOW"`,
				`add /rules/2/local_address/0 value={"address":"*","netmask":0}`,
				`add /rules/2/local_port/0 value={"end":8090,"start":8080}`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			state, plan := tfRule("fam-a", "rule"), planRule("rule")
			if tt.mutateState != nil {
				tt.mutateState(&state)
			}
			if tt.mutatePlan != nil {
				tt.mutatePlan(&plan)
			}
			platform := tt.platform
			if platform == "" {
				platform = "Windows"
			}

			// Index 2 rather than 0, so a path built from the wrong index shows up.
			got := opSummary(t, ruleEditOps(2, plan, state, platform))
			if diff := cmp.Diff(tt.wantOps, got); diff != "" {
				t.Errorf("operations (-want +got):\n%s", diff)
			}
		})
	}

	t.Run("an unchanged rule emits nothing", func(t *testing.T) {
		t.Parallel()
		if got := ruleEditOps(0, planRule("rule"), tfRule("fam-a", "rule"), "Windows"); len(got) != 0 {
			t.Errorf("operations %v, want none", opSummary(t, got))
		}
	})
}

// TestAPIListLen pins the element count the rebuild in ruleEditOps removes before
// adding the planned elements. If it and the read path ever disagree the rebuild
// leaves a stale element behind.
func TestAPIListLen(t *testing.T) {
	t.Parallel()

	addressType := types.ObjectType{AttrTypes: addressRangeAttrTypes()}
	portType := types.ObjectType{AttrTypes: portRangeAttrTypes()}

	tests := []struct {
		name string
		list types.List
		// isAddress marks the two lists whose empty form the API materializes as a
		// wildcard entry.
		isAddress bool
		want      int
	}{
		{
			// The value the read path stores for a rule that restricts no address,
			// which is the wildcard entry the API keeps there.
			name:      "the wildcard list is one element",
			list:      wildcardAddressList(),
			isAddress: true,
			want:      1,
		},
		{
			// A null or empty address list still means "any", and the API holds the
			// wildcard entry for it, so counting zero would skip the remove and leave
			// that entry in the rebuilt list, widening the rule to match any address.
			name:      "a null address list still counts as the wildcard",
			list:      types.ListNull(addressType),
			isAddress: true,
			want:      1,
		},
		{
			name:      "an empty address list still counts as the wildcard",
			list:      types.ListValueMust(addressType, []attr.Value{}),
			isAddress: true,
			want:      1,
		},
		{
			name:      "an unknown address list still counts as the wildcard",
			list:      types.ListUnknown(addressType),
			isAddress: true,
			want:      1,
		},
		{
			name:      "a populated address list is its own length",
			list:      addressRangeList("10.0.0.0", 8),
			isAddress: true,
			want:      1,
		},
		{
			name: "a multi-element address list is its own length",
			list: tfList(addressRangeAttrTypes(), []addressRangeModel{
				{Address: types.StringValue("10.0.0.0"), Netmask: types.Int64Value(8)},
				{Address: types.StringValue("172.16.0.0"), Netmask: types.Int64Value(12)},
			}),
			isAddress: true,
			want:      2,
		},
		{
			// Port lists have no wildcard placeholder, so state's length is the API's.
			name: "a null port list is zero elements",
			list: types.ListNull(portType),
			want: 0,
		},
		{
			name: "an unknown port list is zero elements",
			list: types.ListUnknown(portType),
			want: 0,
		},
		{
			name: "a populated port list is its own length",
			list: portRangeList(443, 0),
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := apiListLen(tt.list, tt.isAddress); got != tt.want {
				t.Errorf("apiListLen of %s is %d, want %d", tt.list, got, tt.want)
			}
		})
	}
}

// TestWrapMalformedRangesError covers the responses the read path must refuse.
// A skipped entry would leave state's element indices out of step with the API's,
// and ruleEditOps addresses list elements by index, so a later apply would rebuild
// the wrong length and leave a stale element on the rule.
func TestWrapMalformedRangesError(t *testing.T) {
	t.Parallel()

	const wantSummary = "Unexpected firewall rule response"

	tests := []struct {
		name string
		wrap func(*diag.Diagnostics) types.List
	}{
		{
			name: "nil address entry",
			wrap: func(diags *diag.Diagnostics) types.List {
				return wrapFirewallAddressRanges(
					context.Background(),
					[]*models.FwmgrFirewallAddressRange{
						{Address: swag.String("10.0.0.0"), Netmask: 8},
						nil,
					},
					"fam-a",
					"local_address",
					diags,
				)
			},
		},
		{
			name: "address entry with no address",
			wrap: func(diags *diag.Diagnostics) types.List {
				return wrapFirewallAddressRanges(
					context.Background(),
					[]*models.FwmgrFirewallAddressRange{
						{Address: swag.String("10.0.0.0"), Netmask: 8},
						{Netmask: 12},
					},
					"fam-a",
					"local_address",
					diags,
				)
			},
		},
		{
			name: "nil port entry",
			wrap: func(diags *diag.Diagnostics) types.List {
				return wrapFirewallPortRanges(
					context.Background(),
					[]*models.FwmgrFirewallPortRange{{Start: swag.Int64(80)}, nil},
					"fam-a",
					"local_port",
					diags,
				)
			},
		},
		{
			name: "port entry with no start",
			wrap: func(diags *diag.Diagnostics) types.List {
				return wrapFirewallPortRanges(
					context.Background(),
					[]*models.FwmgrFirewallPortRange{{Start: swag.Int64(80)}, {End: swag.Int64(90)}},
					"fam-a",
					"local_port",
					diags,
				)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var diags diag.Diagnostics
			tt.wrap(&diags)
			if !diags.HasError() {
				t.Fatal("expected an error for a malformed range entry")
			}
			if summaries := diagSummaries(diags); !slices.Contains(summaries, wantSummary) {
				t.Errorf("diagnostics %v, want one summarized %q", summaries, wantSummary)
			}
		})
	}
}

// TestRuleIsContinuation covers the predicate that decides whether a changed rule
// at a position is the rule that was there, edited, or a different rule that
// replaced it. Getting it wrong in the permissive direction hands a new rule an
// existing rule's Rule ID, which fuses two rules' firewall event histories under
// one identifier and is invisible from Terraform state.
func TestRuleIsContinuation(t *testing.T) {
	t.Parallel()
	state := tfRule("fam-a", "rule-a")

	tests := []struct {
		name string
		plan firewallRuleModel
		want bool
	}{
		{
			name: "same name, changed settings",
			plan: withAllowAction(planRule("rule-a")),
			want: true,
		},
		{
			name: "renamed, same settings",
			plan: planRule("rule-a-renamed"),
			want: true,
		},
		{
			name: "renamed and changed settings",
			plan: withAllowAction(planRule("rule-a-renamed")),
			want: false,
		},
		{
			name: "identical",
			plan: planRule("rule-a"),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ruleIsContinuation(tt.plan, state); got != tt.want {
				t.Errorf("ruleIsContinuation is %v, want %v", got, tt.want)
			}
		})
	}
}

// TestBuildRulePayloadForDiff asserts on the JSON an "add /rules/-" operation
// actually sends, not on an intermediate Go value. The payload embeds the typed
// create request and shadows only its fields array, so marshalling is where that
// shadowing either works or silently emits the array twice.
func TestBuildRulePayloadForDiff(t *testing.T) {
	t.Parallel()

	baseRule := func() firewallRuleModel { return tfRule("rule-1", "rule") }

	icmpRule := baseRule()
	icmpRule.Protocol = types.StringValue("ICMPV4")
	icmpRule.IcmpType = types.StringValue("8")
	icmpRule.IcmpCode = types.StringValue("0")

	fqdnRule := baseRule()
	fqdnRule.Fqdn = types.StringValue("example.com")
	fqdnRule.ExecutablePath = types.StringValue("/usr/bin/curl")

	windowsRule := baseRule()
	windowsRule.ExecutablePath = types.StringValue(`C:\Windows\curl.exe`)
	windowsRule.ServiceName = types.StringValue("Service")
	windowsRule.NetworkLocation = types.StringValue("PUBLIC")

	greRule := baseRule()
	greRule.Protocol = types.StringValue("GRE")

	tests := []struct {
		name     string
		rule     firewallRuleModel
		platform string
		want     string
	}{
		{
			// image_name and service_name are sent with an empty value rather than
			// omitted, which is the whole reason fields is re-encoded: the generated
			// model tags Value omitempty, and the API merges fields by name, so an
			// absent value would leave whatever the rule already held.
			name:     "a rule with nothing set on Windows",
			rule:     baseRule(),
			platform: "Windows",
			want: `{"action":"DENY","address_family":"IP4","description":"","direction":"OUT","enabled":true,` +
				`"fqdn":"","fqdn_enabled":false,"icmp":null,"local_address":[{"address":"*"}],"local_port":[],` +
				`"log":false,"monitor":null,"name":"rule","protocol":"6","remote_address":[{"address":"*"}],` +
				`"remote_port":[],"temp_id":"temp_id:1","fields":[` +
				`{"name":"network_location","type":"set","values":["ANY"]},` +
				`{"name":"image_name","type":"windows_path","value":""},` +
				`{"name":"service_name","type":"string","value":""}]}`,
		},
		{
			// Mac takes the unix path type and has no service_name entry at all.
			name:     "fqdn and executable path on Mac",
			rule:     fqdnRule,
			platform: "Mac",
			want: `{"action":"DENY","address_family":"IP4","description":"","direction":"OUT","enabled":true,` +
				`"fqdn":"example.com","fqdn_enabled":true,"icmp":null,"local_address":[{"address":"*"}],"local_port":[],` +
				`"log":false,"monitor":null,"name":"rule","protocol":"6","remote_address":[{"address":"*"}],` +
				`"remote_port":[],"temp_id":"temp_id:1","fields":[` +
				`{"name":"network_location","type":"set","values":["ANY"]},` +
				`{"name":"image_name","type":"unix_path","value":"/usr/bin/curl"}]}`,
		},
		{
			// An ICMP rule carries the icmp object and no FQDN, and fqdn_enabled has
			// to say so or the API keeps matching on a domain the rule no longer names.
			name:     "icmp criteria",
			rule:     icmpRule,
			platform: "Mac",
			want: `{"action":"DENY","address_family":"IP4","description":"","direction":"OUT","enabled":true,` +
				`"fqdn":"","fqdn_enabled":false,"icmp":{"icmp_code":"0","icmp_type":"8"},` +
				`"local_address":[{"address":"*"}],"local_port":[],` +
				`"log":false,"monitor":null,"name":"rule","protocol":"1","remote_address":[{"address":"*"}],` +
				`"remote_port":[],"temp_id":"temp_id:1","fields":[` +
				`{"name":"network_location","type":"set","values":["ANY"]},` +
				`{"name":"image_name","type":"unix_path","value":""}]}`,
		},
		{
			name:     "executable path, service name and network location on Windows",
			rule:     windowsRule,
			platform: "Windows",
			want: `{"action":"DENY","address_family":"IP4","description":"","direction":"OUT","enabled":true,` +
				`"fqdn":"","fqdn_enabled":false,"icmp":null,"local_address":[{"address":"*"}],"local_port":[],` +
				`"log":false,"monitor":null,"name":"rule","protocol":"6","remote_address":[{"address":"*"}],` +
				`"remote_port":[],"temp_id":"temp_id:1","fields":[` +
				`{"name":"network_location","type":"set","values":["PUBLIC"]},` +
				`{"name":"image_name","type":"windows_path","value":"C:\\Windows\\curl.exe"},` +
				`{"name":"service_name","type":"string","value":"Service"}]}`,
		},
		{
			// The protocol goes out as its IANA number, 47 for GRE.
			name:     "protocol is sent as its IANA number",
			rule:     greRule,
			platform: "Windows",
			want: `{"action":"DENY","address_family":"IP4","description":"","direction":"OUT","enabled":true,` +
				`"fqdn":"","fqdn_enabled":false,"icmp":null,"local_address":[{"address":"*"}],"local_port":[],` +
				`"log":false,"monitor":null,"name":"rule","protocol":"47","remote_address":[{"address":"*"}],` +
				`"remote_port":[],"temp_id":"temp_id:1","fields":[` +
				`{"name":"network_location","type":"set","values":["ANY"]},` +
				`{"name":"image_name","type":"windows_path","value":""},` +
				`{"name":"service_name","type":"string","value":""}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var diags diag.Diagnostics
			encoded, err := json.Marshal(buildRulePayloadForDiff(
				context.Background(), tt.rule, tt.platform, "temp_id:1", &diags,
			))
			if err != nil {
				t.Fatalf("encoding the add payload: %v", err)
			}
			if diags.HasError() {
				t.Fatalf("building the add payload: %v", diags)
			}

			// The embedded struct also has a fields tag. If the shadowing ever stops
			// working, encoding/json drops both and the rule's fields go unset.
			if got := strings.Count(string(encoded), `"fields":`); got != 1 {
				t.Errorf(`payload has %d "fields" keys, want 1: %s`, got, encoded)
			}
			if diff := cmp.Diff(tt.want, string(encoded)); diff != "" {
				t.Errorf("add payload (-want +got):\n%s", diff)
			}
		})
	}
}

// TestProtocolMappingRoundTrip pins every protocol the schema accepts to its
// IANA number and back. A wrong number, a duplicate, or a broken
// reverseProtocolMapping would leave a rule permanently drifting: the value read
// back would never be the value configured.
func TestProtocolMappingRoundTrip(t *testing.T) {
	t.Parallel()

	// The schema's validator is the list of names a user can write, so the
	// mapping has to cover exactly it.
	wantNames := []string{
		"ANY", "ESP", "GRE", "ICMPV4", "ICMPV6", "IGMP",
		"IP-IN-IP", "IPV6 ENCAPSULATION", "TCP", "UDP",
	}
	if got := slices.Sorted(maps.Keys(protocolMapping)); !slices.Equal(got, wantNames) {
		t.Errorf("protocolMapping covers %v, want %v", got, wantNames)
	}

	seen := make(map[string]string, len(protocolMapping))
	for _, name := range slices.Sorted(maps.Keys(protocolMapping)) {
		number := protocolMapping[name]
		if other, dup := seen[number]; dup {
			t.Errorf("%s and %s both map to %q, so one of them cannot round-trip", name, other, number)
			continue
		}
		seen[number] = name

		if got := reverseProtocolMapping(number); got != name {
			t.Errorf("reverseProtocolMapping(%q) is %q, want %q", number, got, name)
		}
	}

	// Any number the mapping does not know falls back to ANY rather than
	// writing a value the schema would reject.
	if got := reverseProtocolMapping("132"); got != "ANY" {
		t.Errorf("reverseProtocolMapping of an unmapped number is %q, want ANY", got)
	}
}

// TestWrapRulesNormalization covers the read path's normalizations. Each is a
// place where the API's spelling of a value differs from the schema's, and
// getting one wrong produces a permanent diff rather than an error.
func TestWrapRulesNormalization(t *testing.T) {
	t.Parallel()

	// baseAPIRule is a minimal TCP rule; each case adjusts only what it tests.
	baseAPIRule := func() *models.FwmgrFirewallRuleV1 {
		rule := fwRule("101", "fam-a", "rule-a")
		rule.Enabled = swag.Bool(true)
		rule.Action = swag.String("ALLOW")
		rule.Direction = swag.String("OUT")
		rule.Protocol = swag.String(protocolMapping["TCP"])
		rule.AddressFamily = swag.String("IP4")
		return rule
	}

	tests := []struct {
		name string
		// adjust may be nil, for the cases whose subject is what baseAPIRule
		// already does not set.
		adjust func(*models.FwmgrFirewallRuleV1)
		// get and want are the shape for a case about one attribute; check is for
		// the few whose subject is a pair of attributes that only mean something
		// together. Exactly one of get and check is set.
		get   func(firewallRuleModel) attr.Value
		want  attr.Value
		check func(*testing.T, firewallRuleModel)
	}{
		{
			// The API reports "any address" as a single wildcard entry, which is the
			// value the schema defaults an omitted list to, so it is stored as itself.
			name: "single wildcard address is stored as the wildcard",
			adjust: func(r *models.FwmgrFirewallRuleV1) {
				r.RemoteAddress = []*models.FwmgrFirewallAddressRange{
					{Address: swag.String("*"), Netmask: 0},
				}
			},
			get:  func(rule firewallRuleModel) attr.Value { return rule.RemoteAddress },
			want: wildcardAddressList(),
		},
		{
			// The API does not report an empty address list, but reporting the
			// wildcard for one keeps the read total: there is no response the
			// schema default cannot match.
			name: "an empty address list reads back as the wildcard",
			adjust: func(r *models.FwmgrFirewallRuleV1) {
				r.RemoteAddress = []*models.FwmgrFirewallAddressRange{}
			},
			get:  func(rule firewallRuleModel) attr.Value { return rule.RemoteAddress },
			want: wildcardAddressList(),
		},
		{
			// A wildcard entry's netmask is pinned to 0 rather than passed through,
			// so a response that started reporting one could not desync state from
			// the value the default plans.
			name: "a wildcard netmask is normalized to zero",
			adjust: func(r *models.FwmgrFirewallRuleV1) {
				r.RemoteAddress = []*models.FwmgrFirewallAddressRange{
					{Address: swag.String("*"), Netmask: 128},
				}
			},
			get:  func(rule firewallRuleModel) attr.Value { return rule.RemoteAddress },
			want: wildcardAddressList(),
		},
		{
			// The read keys off the protocol, not the presence of the object, so a
			// non-ICMP rule reports null however the API answers. That is what the
			// schema plans for one.
			name: "an icmp object on a TCP rule is ignored",
			adjust: func(r *models.FwmgrFirewallRuleV1) {
				r.Icmp = &models.FwmgrFirewallICMP{
					IcmpType: swag.String("8"),
					IcmpCode: swag.String("0"),
				}
			},
			check: func(t *testing.T, rule firewallRuleModel) {
				if !rule.IcmpType.IsNull() || !rule.IcmpCode.IsNull() {
					t.Errorf("icmp_type %s and icmp_code %s, want both null", rule.IcmpType, rule.IcmpCode)
				}
			},
		},
		{
			// The API synthesizes the object for an ICMP rule that sends none, so a
			// missing one means the same as two wildcards. Reporting null instead
			// would not match what the plan holds for an ICMP rule.
			name: "an ICMP rule with no icmp object reads back as wildcards",
			adjust: func(r *models.FwmgrFirewallRuleV1) {
				r.Protocol = swag.String(protocolMapping["ICMPV4"])
				r.Icmp = nil
			},
			check: wantICMPWildcards,
		},
		{
			// The API stores the wildcard for a value submitted empty, so an empty
			// value read back is the same "any".
			name: "empty ICMP values read back as wildcards",
			adjust: func(r *models.FwmgrFirewallRuleV1) {
				r.Protocol = swag.String(protocolMapping["ICMPV6"])
				r.Icmp = &models.FwmgrFirewallICMP{
					IcmpType: swag.String(""),
					IcmpCode: swag.String(""),
				}
			},
			check: wantICMPWildcards,
		},
		{
			// A real address list is kept as written, wildcard entries and all. Only
			// a list that is nothing but the wildcard is normalized.
			name: "real addresses are preserved",
			adjust: func(r *models.FwmgrFirewallRuleV1) {
				r.RemoteAddress = []*models.FwmgrFirewallAddressRange{
					{Address: swag.String("10.0.0.0"), Netmask: 8},
					{Address: swag.String("*"), Netmask: 0},
				}
			},
			get: func(rule firewallRuleModel) attr.Value { return rule.RemoteAddress },
			want: tfList(addressRangeAttrTypes(), []addressRangeModel{
				{Address: types.StringValue("10.0.0.0"), Netmask: types.Int64Value(8)},
				{Address: types.StringValue("*"), Netmask: types.Int64Value(0)},
			}),
		},
		{
			// network_location "ANY" is the schema default, so the fields entry
			// for it reads back as the default rather than a distinct value.
			name: "network_location ANY reads back as the default",
			adjust: func(r *models.FwmgrFirewallRuleV1) {
				r.Fields = []*models.FwmgrFirewallFieldValue{
					{Name: swag.String("network_location"), Values: []string{"ANY"}},
				}
			},
			get:  func(rule firewallRuleModel) attr.Value { return rule.NetworkLocation },
			want: types.StringValue("ANY"),
		},
		{
			name: "network_location value is read from fields",
			adjust: func(r *models.FwmgrFirewallRuleV1) {
				r.Fields = []*models.FwmgrFirewallFieldValue{
					{Name: swag.String("network_location"), Values: []string{"PUBLIC"}},
				}
			},
			get:  func(rule firewallRuleModel) attr.Value { return rule.NetworkLocation },
			want: types.StringValue("PUBLIC"),
		},
		{
			// image_name and service_name are always sent, empty when unset, so
			// an empty value has to read back as null and not as "".
			name: "empty image_name and service_name read back as null",
			adjust: func(r *models.FwmgrFirewallRuleV1) {
				r.Fields = []*models.FwmgrFirewallFieldValue{
					{Name: swag.String("image_name"), Value: swag.String("")},
					{Name: swag.String("service_name"), Value: swag.String("")},
				}
			},
			check: wantFieldsUnset,
		},
		{
			name: "image_name and service_name values are read from fields",
			adjust: func(r *models.FwmgrFirewallRuleV1) {
				r.Fields = []*models.FwmgrFirewallFieldValue{
					{Name: swag.String("image_name"), Value: swag.String(`C:\curl.exe`)},
					{Name: swag.String("service_name"), Value: swag.String("Service")},
				}
			},
			check: func(t *testing.T, rule firewallRuleModel) {
				if !rule.ExecutablePath.Equal(types.StringValue(`C:\curl.exe`)) ||
					!rule.ServiceName.Equal(types.StringValue("Service")) {
					t.Errorf(
						`executable_path %s and service_name %s, want C:\curl.exe and Service`,
						rule.ExecutablePath, rule.ServiceName,
					)
				}
			},
		},
		{
			// A fields entry with no name would panic a naive loop.
			name: "unnamed and unknown fields entries are skipped",
			adjust: func(r *models.FwmgrFirewallRuleV1) {
				r.Fields = []*models.FwmgrFirewallFieldValue{
					{Name: nil, Value: swag.String("ignored")},
					{Name: swag.String("something_else"), Value: swag.String("ignored")},
				}
			},
			check: wantFieldsUnset,
		},
		{
			// The API has no watch_mode flag; the presence of Monitor is it.
			name: "monitor presence is watch_mode",
			adjust: func(r *models.FwmgrFirewallRuleV1) {
				r.Monitor = &models.FwmgrFirewallMonitoring{
					Count:    swag.String("1"),
					PeriodMs: swag.String("3600000"),
				}
			},
			get:  func(rule firewallRuleModel) attr.Value { return rule.WatchMode },
			want: types.BoolValue(true),
		},
		{
			// baseAPIRule sets no monitor, so this is the unadjusted rule.
			name: "no monitor is watch_mode false",
			get:  func(rule firewallRuleModel) attr.Value { return rule.WatchMode },
			want: types.BoolValue(false),
		},
		{
			// An FQDN the API still stores but has disabled is not in effect, so
			// reporting it would claim a match criterion the rule does not have.
			name: "disabled fqdn reads back as unset",
			adjust: func(r *models.FwmgrFirewallRuleV1) {
				r.Fqdn = swag.String("example.com")
				r.FqdnEnabled = swag.Bool(false)
			},
			get:  func(rule firewallRuleModel) attr.Value { return rule.Fqdn },
			want: types.StringNull(),
		},
		{
			name: "enabled fqdn is read",
			adjust: func(r *models.FwmgrFirewallRuleV1) {
				r.Fqdn = swag.String("example.com")
				r.FqdnEnabled = swag.Bool(true)
			},
			get:  func(rule firewallRuleModel) attr.Value { return rule.Fqdn },
			want: types.StringValue("example.com"),
		},
		{
			// "NONE" is how the API spells the console's "Any" address family.
			name:   "address family NONE reads back as ANY",
			adjust: func(r *models.FwmgrFirewallRuleV1) { r.AddressFamily = swag.String("NONE") },
			get:    func(rule firewallRuleModel) attr.Value { return rule.AddressFamily },
			want:   types.StringValue("ANY"),
		},
		{
			// The wildcard protocol is ANY, and so is anything unrecognized.
			name:   "wildcard protocol reads back as ANY",
			adjust: func(r *models.FwmgrFirewallRuleV1) { r.Protocol = swag.String("*") },
			get:    func(rule firewallRuleModel) attr.Value { return rule.Protocol },
			want:   types.StringValue("ANY"),
		},
		{
			// A rule's Terraform id is its family, the identity it keeps for its
			// lifetime, never the per-version ID.
			name: "id is the rule family",
			get:  func(rule firewallRuleModel) attr.Value { return rule.ID },
			want: types.StringValue("fam-a"),
		},
		{
			// The API reports 0 for a single port, which is what the schema
			// means by 0, so it is stored verbatim.
			name: "a single port keeps end 0",
			adjust: func(r *models.FwmgrFirewallRuleV1) {
				r.RemotePort = []*models.FwmgrFirewallPortRange{
					{Start: swag.Int64(443), End: swag.Int64(0)},
				}
			},
			get:  func(rule firewallRuleModel) attr.Value { return rule.RemotePort },
			want: portRangeList(443, 0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			apiRule := baseAPIRule()
			if tt.adjust != nil {
				tt.adjust(apiRule)
			}

			rule := wrapOneRule(t, apiRule)
			switch {
			case tt.get != nil:
				if got := tt.get(rule); !got.Equal(tt.want) {
					t.Errorf("read back as %s, want %s", got, tt.want)
				}
			case tt.check != nil:
				tt.check(t, rule)
			default:
				t.Fatal("case asserts nothing: set either get and want, or check")
			}
		})
	}
}

// wantICMPWildcards and wantFieldsUnset are the two multi-attribute expectations
// several normalization cases share: an ICMP rule always carries both a type and
// a code, and the two fields-backed string attributes are unset together.
func wantICMPWildcards(t *testing.T, rule firewallRuleModel) {
	t.Helper()
	wildcard := types.StringValue(apiWildcard)
	if !rule.IcmpType.Equal(wildcard) || !rule.IcmpCode.Equal(wildcard) {
		t.Errorf(
			"icmp_type %s and icmp_code %s, want both %s",
			rule.IcmpType, rule.IcmpCode, wildcard,
		)
	}
}

func wantFieldsUnset(t *testing.T, rule firewallRuleModel) {
	t.Helper()
	if !rule.ExecutablePath.IsNull() || !rule.ServiceName.IsNull() {
		t.Errorf(
			"executable_path %s and service_name %s, want both null",
			rule.ExecutablePath, rule.ServiceName,
		)
	}
}

// TestICMPValueRoundTrip covers both spellings of "any ICMP type or code" the resource
// accepts. The API stores the wildcard for a value submitted empty and reports it back,
// so the wildcard is what an omitted value round-trips as, and writing it out means the
// same thing; a rule that names a type but no code is the mixed case.
func TestICMPValueRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		icmpType types.String
		icmpCode types.String
		// wantSentType and wantSentCode are asserted on the way out and then fed
		// back in as the API's stored values, which is what closes the round trip:
		// what the API reports is what it was sent, so these are also what the two
		// attributes have to read back as.
		wantSentType string
		wantSentCode string
	}{
		{
			// Unset never reaches the payload builder in practice: the plan modifier
			// fills the wildcard first. It is covered because the builder is what
			// makes that substitution safe if it ever does.
			name:         "both unset",
			icmpType:     types.StringNull(),
			icmpCode:     types.StringNull(),
			wantSentType: "*",
			wantSentCode: "*",
		},
		{
			// The wildcard written out explicitly, which is what the plan holds for
			// an omitted value, and it has to survive unchanged.
			name:         "both wildcarded",
			icmpType:     types.StringValue("*"),
			icmpCode:     types.StringValue("*"),
			wantSentType: "*",
			wantSentCode: "*",
		},
		{
			name:         "type set, code wildcarded",
			icmpType:     types.StringValue("8"),
			icmpCode:     types.StringValue("*"),
			wantSentType: "8",
			wantSentCode: "*",
		},
		{
			name:         "type set, code unset",
			icmpType:     types.StringValue("8"),
			icmpCode:     types.StringNull(),
			wantSentType: "8",
			wantSentCode: "*",
		},
		{
			name:         "both set",
			icmpType:     types.StringValue("8"),
			icmpCode:     types.StringValue("0"),
			wantSentType: "8",
			wantSentCode: "0",
		},
		{
			// Code 0 is a real code, not an absent one.
			name:         "zero code",
			icmpType:     types.StringNull(),
			icmpCode:     types.StringValue("0"),
			wantSentType: "*",
			wantSentCode: "0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := icmpValueToAPI(tt.icmpType); got != tt.wantSentType {
				t.Errorf("icmp_type sent to API is %q, want %q", got, tt.wantSentType)
			}
			if got := icmpValueToAPI(tt.icmpCode); got != tt.wantSentCode {
				t.Errorf("icmp_code sent to API is %q, want %q", got, tt.wantSentCode)
			}

			apiRule := fwRule("101", "fam-a", "rule-a")
			apiRule.Protocol = swag.String(protocolMapping["ICMPV4"])
			apiRule.Icmp = &models.FwmgrFirewallICMP{
				IcmpType: swag.String(tt.wantSentType),
				IcmpCode: swag.String(tt.wantSentCode),
			}

			rule := wrapOneRule(t, apiRule)
			if want := types.StringValue(tt.wantSentType); !rule.IcmpType.Equal(want) {
				t.Errorf("icmp_type read back as %s, want %s", rule.IcmpType, want)
			}
			if want := types.StringValue(tt.wantSentCode); !rule.IcmpCode.Equal(want) {
				t.Errorf("icmp_code read back as %s, want %s", rule.IcmpCode, want)
			}
		})
	}
}

func TestOrderRulesByRuleIDs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		byFamily map[string]*models.FwmgrFirewallRuleV1
		ruleIDs  []string
		want     []string
	}{
		{
			// The rules endpoint returns an arbitrary order that ignores the
			// requested id order; rule_ids is the group's precedence order.
			name: "orders by family",
			byFamily: map[string]*models.FwmgrFirewallRuleV1{
				"fam-c": fwRule("103", "fam-c", "rule-c"),
				"fam-a": fwRule("101", "fam-a", "rule-a"),
				"fam-b": fwRule("102", "fam-b", "rule-b"),
			},
			ruleIDs: []string{"fam-a", "fam-b", "fam-c"},
			want:    []string{"rule-a", "rule-b", "rule-c"},
		},
		{
			// rule_ids holds families, never per-version ids, so a version id
			// matches nothing. The caller treats a short result as an error.
			name: "does not match per-version ids",
			byFamily: map[string]*models.FwmgrFirewallRuleV1{
				"fam-b": fwRule("102", "fam-b", "rule-b"),
				"fam-a": fwRule("101", "fam-a", "rule-a"),
			},
			ruleIDs: []string{"101", "102"},
			want:    []string{},
		},
		{
			// Only rules the group references are part of its order.
			name: "drops rules the group does not reference",
			byFamily: map[string]*models.FwmgrFirewallRuleV1{
				"fam-c": fwRule("103", "fam-c", "rule-c"),
				"fam-b": fwRule("102", "fam-b", "rule-b"),
				"fam-a": fwRule("101", "fam-a", "rule-a"),
			},
			ruleIDs: []string{"fam-a"},
			want:    []string{"rule-a"},
		},
		{
			name:     "no rules",
			byFamily: nil,
			ruleIDs:  []string{"fam-a"},
			want:     []string{},
		},
		{
			name:     "no rule ids",
			byFamily: map[string]*models.FwmgrFirewallRuleV1{"fam-a": fwRule("101", "fam-a", "rule-a")},
			ruleIDs:  nil,
			want:     []string{},
		},
		{
			// A family mapped to a nil rule is skipped rather than dereferenced, so
			// the result is shorter than rule_ids. readRuleGroupState turns that
			// mismatch into an error rather than storing a list whose indices no
			// longer name the rules rule_ids refers to.
			name: "skips a nil rule, producing a short result",
			byFamily: map[string]*models.FwmgrFirewallRuleV1{
				"fam-a": fwRule("101", "fam-a", "rule-a"),
				"fam-b": fwRule("102", "fam-b", "rule-b"),
				"fam-c": nil,
			},
			ruleIDs: []string{"fam-b", "fam-c", "fam-b", "fam-a"},
			want:    []string{"rule-b", "rule-b", "rule-a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := ruleNames(orderRulesByFamily(tt.byFamily, tt.ruleIDs))
			if !slices.Equal(got, tt.want) {
				t.Fatalf("expected order %v, got %v", tt.want, got)
			}
		})
	}
}

// TestNormalizePlatform covers the API's lowercase platform values, which the
// schema's validator only accepts in title case.
func TestNormalizePlatform(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want string
	}{
		{in: "windows", want: "Windows"},
		{in: "mac", want: "Mac"},
		{in: "linux", want: "Linux"},
		{in: "Windows", want: "Windows"},
		// An unrecognized value is passed through rather than guessed at, so a
		// new platform surfaces as a validation error naming the real value.
		{in: "ios", want: "ios"},
		{in: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.in), func(t *testing.T) {
			t.Parallel()
			if got := normalizePlatform(tt.in); got != tt.want {
				t.Errorf("normalizePlatform(%q) is %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestAddressFamilyAPIRoundTrip covers the one value whose Terraform and API
// spellings differ. If the two directions ever disagree, a rule using it would
// drift on every plan.
func TestAddressFamilyAPIRoundTrip(t *testing.T) {
	t.Parallel()

	for _, family := range []string{"IP4", "IP6", "ANY"} {
		t.Run(family, func(t *testing.T) {
			t.Parallel()
			if got := addressFamilyFromAPI(addressFamilyToAPI(family)); got != family {
				t.Errorf("%s round-tripped to %q", family, got)
			}
		})
	}

	if got := addressFamilyToAPI("ANY"); got != "NONE" {
		t.Errorf("ANY is sent to the API as %q, want NONE", got)
	}
}
