package firewall

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// planWithRule builds a plan holding one rule, which is what an attribute plan
// modifier on a rules element reads its siblings from.
func planWithRule(t *testing.T, rule firewallRuleModel) tfsdk.Plan {
	t.Helper()
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	(&firewallRuleGroupResource{}).Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("building schema: %v", schemaResp.Diagnostics)
	}

	ruleObject, diags := types.ObjectValueFrom(ctx, firewallRuleModel{}.attrTypes(), rule)
	if diags.HasError() {
		t.Fatalf("wrapping rule: %v", diags)
	}
	rules, diags := types.ListValue(
		types.ObjectType{AttrTypes: firewallRuleModel{}.attrTypes()},
		[]attr.Value{ruleObject},
	)
	if diags.HasError() {
		t.Fatalf("wrapping rules: %v", diags)
	}

	plan := tfsdk.Plan{Schema: schemaResp.Schema}
	diags = plan.Set(ctx, firewallRuleGroupResourceModel{
		ID:          types.StringValue("group-a"),
		Name:        types.StringValue("group"),
		Description: types.StringNull(),
		Platform:    types.StringValue("Windows"),
		Enabled:     types.BoolValue(true),
		Rules:       rules,
	})
	if diags.HasError() {
		t.Fatalf("setting plan: %v", diags)
	}
	return plan
}

// TestICMPValueDefault covers the substitute for a schema Default on icmp_type and
// icmp_code. The value depends on the rule's protocol, and planning the wrong one is an
// inconsistent-result error after apply, so every combination of configured value and
// protocol is pinned here.
func TestICMPValueDefault(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		protocol    types.String
		configValue types.String
		want        types.String
	}{
		{
			// The wildcard is what the API reports for an ICMP rule that restricts
			// neither type nor code, so it is what an omitted value has to plan as.
			name:        "unconfigured on an ICMP rule is the wildcard",
			protocol:    types.StringValue("ICMPV4"),
			configValue: types.StringNull(),
			want:        types.StringValue(apiWildcard),
		},
		{
			name:        "unconfigured on an ICMPV6 rule is the wildcard",
			protocol:    types.StringValue("ICMPV6"),
			configValue: types.StringNull(),
			want:        types.StringValue(apiWildcard),
		},
		{
			// A non-ICMP rule carries no ICMP data and the API reports it as null,
			// so planning the wildcard here would never match the refreshed value.
			name:        "unconfigured on a TCP rule is null",
			protocol:    types.StringValue("TCP"),
			configValue: types.StringNull(),
			want:        types.StringNull(),
		},
		{
			name:        "unconfigured on an ANY rule is null",
			protocol:    types.StringValue("ANY"),
			configValue: types.StringNull(),
			want:        types.StringNull(),
		},
		{
			// Terraform forbids planning anything but the configured value, and
			// preserving it is what lets the wildcard be written out explicitly.
			name:        "a configured wildcard is preserved",
			protocol:    types.StringValue("ICMPV4"),
			configValue: types.StringValue(apiWildcard),
			want:        types.StringValue(apiWildcard),
		},
		{
			name:        "a configured value is preserved",
			protocol:    types.StringValue("ICMPV4"),
			configValue: types.StringValue("8"),
			want:        types.StringValue("8"),
		},
		{
			// An unresolved protocol cannot be classified, so the value is left for
			// the plan Terraform runs at apply time, by which point it is known.
			name:        "an unknown protocol leaves the value unknown",
			protocol:    types.StringUnknown(),
			configValue: types.StringNull(),
			want:        types.StringUnknown(),
		},
		{
			// A configured value that is still unresolved belongs to the expression
			// that produced it, so it is left alone the same way a known one is.
			name:        "a configured but unresolved value is left alone",
			protocol:    types.StringValue("ICMPV4"),
			configValue: types.StringUnknown(),
			want:        types.StringUnknown(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rule := tfRule("rule-a", "a rule")
			rule.Protocol = tt.protocol
			// An ICMP rule may not carry ports, and the plan the modifier reads has
			// to be a rule the schema would accept.
			rule.IcmpType = tt.configValue
			rule.IcmpCode = tt.configValue

			// What the framework hands the modifier: the configured value when there
			// is one, and unknown for an omitted Optional+Computed attribute with no
			// schema default, which the framework marks before modifiers run.
			planValue := tt.configValue
			if planValue.IsNull() {
				planValue = types.StringUnknown()
			}

			req := planmodifier.StringRequest{
				Path:        path.Root("rules").AtListIndex(0).AtName("icmp_type"),
				ConfigValue: tt.configValue,
				PlanValue:   planValue,
				Plan:        planWithRule(t, rule),
			}
			resp := &planmodifier.StringResponse{PlanValue: req.PlanValue}

			icmpValueDefault().PlanModifyString(context.Background(), req, resp)

			if resp.Diagnostics.HasError() {
				t.Fatalf("plan modifier: %v", resp.Diagnostics)
			}
			if !resp.PlanValue.Equal(tt.want) {
				t.Errorf("planned value is %s, want %s", resp.PlanValue, tt.want)
			}
		})
	}
}
