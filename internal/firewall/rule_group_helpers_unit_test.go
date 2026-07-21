package firewall

import (
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
)

func fwRule(id, family, name string) *models.FwmgrFirewallRuleV1 {
	return &models.FwmgrFirewallRuleV1{
		ID:     &id,
		Family: &family,
		Name:   &name,
	}
}

func ruleNames(rules []*models.FwmgrFirewallRuleV1) []string {
	names := make([]string, 0, len(rules))
	for _, r := range rules {
		names = append(names, *r.Name)
	}
	return names
}

func assertOrder(t *testing.T, got []*models.FwmgrFirewallRuleV1, want []string) {
	t.Helper()
	gotNames := ruleNames(got)
	if len(gotNames) != len(want) {
		t.Fatalf("expected %d rules, got %d (%v)", len(want), len(gotNames), gotNames)
	}
	for i := range want {
		if gotNames[i] != want[i] {
			t.Fatalf("expected order %v, got %v", want, gotNames)
		}
	}
}

func TestOrderRulesByRuleIDs_ordersByFamily(t *testing.T) {
	// API response order is nondeterministic; rule_ids reference rule families.
	apiRules := []*models.FwmgrFirewallRuleV1{
		fwRule("103", "fam-c", "rule-c"),
		fwRule("101", "fam-a", "rule-a"),
		fwRule("102", "fam-b", "rule-b"),
	}
	ruleIDs := []string{"fam-a", "fam-b", "fam-c"}

	assertOrder(t, orderRulesByRuleIDs(apiRules, ruleIDs), []string{"rule-a", "rule-b", "rule-c"})
}

func TestOrderRulesByRuleIDs_fallsBackToID(t *testing.T) {
	apiRules := []*models.FwmgrFirewallRuleV1{
		fwRule("102", "fam-b", "rule-b"),
		fwRule("101", "fam-a", "rule-a"),
	}
	ruleIDs := []string{"101", "102"}

	assertOrder(t, orderRulesByRuleIDs(apiRules, ruleIDs), []string{"rule-a", "rule-b"})
}

func TestOrderRulesByRuleIDs_appendsUnreferencedRules(t *testing.T) {
	apiRules := []*models.FwmgrFirewallRuleV1{
		fwRule("103", "fam-c", "rule-c"),
		fwRule("102", "fam-b", "rule-b"),
		fwRule("101", "fam-a", "rule-a"),
	}
	ruleIDs := []string{"fam-a"}

	// rule-a matched; rule-c and rule-b appended in response order.
	assertOrder(t, orderRulesByRuleIDs(apiRules, ruleIDs), []string{"rule-a", "rule-c", "rule-b"})
}

func TestOrderRulesByRuleIDs_emptyInputs(t *testing.T) {
	if got := orderRulesByRuleIDs(nil, []string{"fam-a"}); len(got) != 0 {
		t.Fatalf("expected empty result for nil rules, got %d", len(got))
	}

	apiRules := []*models.FwmgrFirewallRuleV1{fwRule("101", "fam-a", "rule-a")}
	assertOrder(t, orderRulesByRuleIDs(apiRules, nil), []string{"rule-a"})
}

func TestOrderRulesByRuleIDs_skipsNilAndDuplicateEntries(t *testing.T) {
	apiRules := []*models.FwmgrFirewallRuleV1{
		nil,
		fwRule("101", "fam-a", "rule-a"),
		fwRule("102", "fam-b", "rule-b"),
	}
	// Duplicate reference must not duplicate the rule in the result.
	ruleIDs := []string{"fam-b", "fam-b", "fam-a"}

	assertOrder(t, orderRulesByRuleIDs(apiRules, ruleIDs), []string{"rule-b", "rule-a"})
}
