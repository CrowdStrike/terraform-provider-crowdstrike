package firewall

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the modifier satisfies the expected interface.
var _ planmodifier.String = icmpValueDefaultModifier{}

// icmpValueDefaultModifier supplies the canonical "any" for icmp_type and icmp_code.
//
// It exists because the correct value depends on the rule's protocol, which a schema
// Default cannot see: defaults.StringRequest carries only the attribute's path. An ICMP
// rule always carries a type and a code, and the API reports the wildcard for either one
// left unset, while a rule on any other protocol carries no ICMP data at all and the API
// reports it as null. Planning the wrong one of those is an inconsistent-result error
// after apply, so the value has to be chosen per rule.
type icmpValueDefaultModifier struct{}

// icmpValueDefault returns a plan modifier that fills an unconfigured ICMP type or code
// with the wildcard on ICMP rules, and leaves it null on every other protocol.
func icmpValueDefault() planmodifier.String {
	return icmpValueDefaultModifier{}
}

func (m icmpValueDefaultModifier) Description(ctx context.Context) string {
	return m.MarkdownDescription(ctx)
}

func (m icmpValueDefaultModifier) MarkdownDescription(_ context.Context) string {
	return "Defaults to `*` (any) on `ICMPV4` and `ICMPV6` rules, and to null on every other protocol."
}

func (m icmpValueDefaultModifier) PlanModifyString(
	ctx context.Context,
	req planmodifier.StringRequest,
	resp *planmodifier.StringResponse,
) {
	// Only an omitted value is filled in. A configured one is already the plan value, and
	// Terraform forbids planning anything else; preserving it is what lets "*" be written
	// out as well as omitted. A configured value that is still unknown belongs to the
	// expression that produced it and resolves at apply.
	if !req.ConfigValue.IsNull() {
		return
	}

	// The sibling protocol decides the value. Read it from the plan rather than the
	// configuration: schema defaults have already been applied by the time plan
	// modifiers run, so the plan is where a value the practitioner did not write is
	// visible.
	var protocol types.String
	resp.Diagnostics.Append(
		req.Plan.GetAttribute(ctx, req.Path.ParentPath().AtName("protocol"), &protocol)...,
	)
	if resp.Diagnostics.HasError() {
		return
	}

	// An unresolved protocol cannot be classified. The framework has already planned this
	// attribute as unknown, having found it null in the configuration, so leaving the plan
	// alone defers the choice to the plan Terraform runs at apply time, by which point the
	// protocol has a value.
	if protocol.IsUnknown() {
		return
	}

	if isICMPProtocol(protocol) {
		resp.PlanValue = types.StringValue(apiWildcard)
		return
	}
	resp.PlanValue = types.StringNull()
}
