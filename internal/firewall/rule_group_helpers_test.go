package firewall

import (
	"context"
	"reflect"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func fwRule(id, family, name string) *models.FwmgrFirewallRuleV1 {
	return &models.FwmgrFirewallRuleV1{
		ID:     &id,
		Family: &family,
		Name:   &name,
	}
}

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
		LocalAddress:    types.ListNull(types.ObjectType{AttrTypes: addressRangeAttrTypes()}),
		RemoteAddress:   types.ListNull(types.ObjectType{AttrTypes: addressRangeAttrTypes()}),
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

func tfRuleList(t *testing.T, rules []firewallRuleModel) types.List {
	t.Helper()
	list, diags := types.ListValueFrom(
		context.Background(),
		types.ObjectType{AttrTypes: firewallRuleModel{}.attrTypes()},
		rules,
	)
	if diags.HasError() {
		t.Fatalf("failed to create rule list: %v", diags)
	}
	return list
}

func ruleNames(rules []*models.FwmgrFirewallRuleV1) []string {
	names := make([]string, 0, len(rules))
	for _, r := range rules {
		names = append(names, *r.Name)
	}
	return names
}

func TestOrderRulesByPlanNamesSupportsDuplicateNames(t *testing.T) {
	apiRules := []*models.FwmgrFirewallRuleV1{
		fwRule("rule-2", "family-2", "duplicate"),
		fwRule("rule-1", "family-1", "duplicate"),
	}
	planRules := tfRuleList(t, []firewallRuleModel{
		tfRule("rule-1", "duplicate"),
		tfRule("rule-2", "duplicate"),
	})

	got, diags := orderRulesByPlanNames(context.Background(), apiRules, planRules)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if got[0] != apiRules[1] || got[1] != apiRules[0] {
		t.Fatalf("expected duplicate names ordered by rule ID, got %v", ruleNames(got))
	}
}

func TestBuildDiffOperationsSupportsDuplicateNames(t *testing.T) {
	rules := []firewallRuleModel{
		tfRule("rule-1", "duplicate"),
		tfRule("rule-2", "duplicate"),
	}
	list := tfRuleList(t, rules)
	model := firewallRuleGroupResourceModel{
		ID:          types.StringValue("group-id"),
		Name:        types.StringValue("group"),
		Description: types.StringNull(),
		Platform:    types.StringValue("Mac"),
		Enabled:     types.BoolValue(true),
		Rules:       list,
	}
	ruleGroup := &models.FwmgrAPIRuleGroupV1{RuleIds: []string{"family-1", "family-2"}}

	diffs, ruleIDs, _, diags := (&firewallRuleGroupResource{}).buildDiffOperations(
		context.Background(), model, model, ruleGroup,
	)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if len(diffs) != 0 {
		t.Fatalf("expected no diff operations, got %v", diffs)
	}
	if !reflect.DeepEqual(ruleIDs, ruleGroup.RuleIds) {
		t.Fatalf("expected rule IDs %v, got %v", ruleGroup.RuleIds, ruleIDs)
	}
}

func TestBuildRulePayloadForDiffPreservesMatchCriteria(t *testing.T) {
	rule := tfRule("rule-1", "rule")
	rule.Fqdn = types.StringValue("example.com")
	rule.ExecutablePath = types.StringValue("/usr/bin/curl")

	payload := (&firewallRuleGroupResource{}).buildRulePayloadForDiff(rule, "Mac", "temp_id:1")
	if payload["fqdn"] != "example.com" || payload["fqdn_enabled"] != true {
		t.Fatalf("expected FQDN criteria, got %v", payload)
	}
	fields := payload["fields"].([]map[string]interface{})
	if fields[1]["type"] != "unix_path" {
		t.Fatalf("expected macOS executable to use unix_path, got %v", fields[1])
	}

	rule.Protocol = types.StringValue("ICMPV4")
	rule.Fqdn = types.StringNull()
	rule.IcmpType = types.StringValue("8")
	rule.IcmpCode = types.StringValue("0")
	payload = (&firewallRuleGroupResource{}).buildRulePayloadForDiff(rule, "Mac", "temp_id:2")
	if !reflect.DeepEqual(payload["icmp"], map[string]interface{}{
		"icmp_type": "8",
		"icmp_code": "0",
	}) {
		t.Fatalf("expected ICMP criteria, got %v", payload["icmp"])
	}
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
