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

func TestOrderRulesByRuleIDs(t *testing.T) {
	tests := []struct {
		name     string
		apiRules []*models.FwmgrFirewallRuleV1
		ruleIDs  []string
		want     []string
	}{
		{
			// API response order is nondeterministic; rule_ids reference rule families.
			name: "orders by family",
			apiRules: []*models.FwmgrFirewallRuleV1{
				fwRule("103", "fam-c", "rule-c"),
				fwRule("101", "fam-a", "rule-a"),
				fwRule("102", "fam-b", "rule-b"),
			},
			ruleIDs: []string{"fam-a", "fam-b", "fam-c"},
			want:    []string{"rule-a", "rule-b", "rule-c"},
		},
		{
			name: "falls back to id",
			apiRules: []*models.FwmgrFirewallRuleV1{
				fwRule("102", "fam-b", "rule-b"),
				fwRule("101", "fam-a", "rule-a"),
			},
			ruleIDs: []string{"101", "102"},
			want:    []string{"rule-a", "rule-b"},
		},
		{
			// rule-a matched; rule-c and rule-b appended in response order.
			name: "appends unreferenced rules in response order",
			apiRules: []*models.FwmgrFirewallRuleV1{
				fwRule("103", "fam-c", "rule-c"),
				fwRule("102", "fam-b", "rule-b"),
				fwRule("101", "fam-a", "rule-a"),
			},
			ruleIDs: []string{"fam-a"},
			want:    []string{"rule-a", "rule-c", "rule-b"},
		},
		{
			name:     "nil rules",
			apiRules: nil,
			ruleIDs:  []string{"fam-a"},
			want:     []string{},
		},
		{
			name:     "nil rule ids returns response order",
			apiRules: []*models.FwmgrFirewallRuleV1{fwRule("101", "fam-a", "rule-a")},
			ruleIDs:  nil,
			want:     []string{"rule-a"},
		},
		{
			// A nil rule is skipped, and a duplicate reference must not duplicate the rule.
			name: "skips nil rules and duplicate references",
			apiRules: []*models.FwmgrFirewallRuleV1{
				nil,
				fwRule("101", "fam-a", "rule-a"),
				fwRule("102", "fam-b", "rule-b"),
			},
			ruleIDs: []string{"fam-b", "fam-b", "fam-a"},
			want:    []string{"rule-b", "rule-a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ruleNames(orderRulesByRuleIDs(tt.apiRules, tt.ruleIDs))
			if len(got) != len(tt.want) {
				t.Fatalf("expected %d rules %v, got %d %v", len(tt.want), tt.want, len(got), got)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("expected order %v, got %v", tt.want, got)
				}
			}
		})
	}
}
