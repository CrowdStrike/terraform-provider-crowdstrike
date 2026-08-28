package firewall

import (
	"context"
	"fmt"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// Ensure the validator satisfies the expected interface.
var _ validator.Object = ruleAttributeApplicabilityValidator{}

// ruleAttributeApplicabilityValidator rejects rule attributes that do not apply to the
// rule they are written on.
//
// The invariants are internal to a single rule, so they live on the rules element rather
// than in ValidateConfig: the whole rule arrives in req.ConfigValue and the diagnostic
// path is already the element's, with no resource-level context to consult.
// ValidateConfig holds the checks that need the group's platform.
//
// Every check guards a configuration the provider cannot honor. An ICMP type on a TCP rule
// is the clearest case: the payload builder sends no icmp object for a non-ICMP protocol,
// so the API stores nothing and the read reports null, which can never equal the
// configured value. An ICMP protocol paired with the other family's address_family is
// rejected by the API, as are specific addresses on a rule that matches any address
// family. A netmask on the wildcard address is dropped, and the API rejects a port range
// whose end is not past its start.
type ruleAttributeApplicabilityValidator struct{}

// ruleAttributeApplicability returns a validator for one element of the rules list.
func ruleAttributeApplicability() validator.Object {
	return ruleAttributeApplicabilityValidator{}
}

func (v ruleAttributeApplicabilityValidator) Description(ctx context.Context) string {
	return v.MarkdownDescription(ctx)
}

func (v ruleAttributeApplicabilityValidator) MarkdownDescription(_ context.Context) string {
	return "Rejects ICMP attributes on non-ICMP rules, an `address_family` that contradicts an ICMP protocol, specific addresses on rules whose `address_family` is `ANY`, a non-zero `netmask` on the `*` address, and a port range whose `end` is not greater than its `start`."
}

func (v ruleAttributeApplicabilityValidator) ValidateObject(
	ctx context.Context,
	req validator.ObjectRequest,
	resp *validator.ObjectResponse,
) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	var rule firewallRuleModel
	resp.Diagnostics.Append(req.ConfigValue.As(ctx, &rule, basetypes.ObjectAsOptions{
		UnhandledNullAsEmpty:    true,
		UnhandledUnknownAsEmpty: true,
	})...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !isICMPProtocol(rule.Protocol) && !rule.Protocol.IsUnknown() {
		if !rule.IcmpType.IsNull() && !rule.IcmpType.IsUnknown() {
			resp.Diagnostics.AddAttributeError(
				req.Path.AtName("icmp_type"),
				"Invalid ICMP configuration",
				"icmp_type is only valid for ICMPV4 or ICMPV6 protocols.",
			)
		}
		if !rule.IcmpCode.IsNull() && !rule.IcmpCode.IsUnknown() {
			resp.Diagnostics.AddAttributeError(
				req.Path.AtName("icmp_code"),
				"Invalid ICMP configuration",
				"icmp_code is only valid for ICMPV4 or ICMPV6 protocols.",
			)
		}
	}

	// ICMPv4 runs only over IPv4 and ICMPv6 only over IPv6, and the API rejects the
	// crossed pairs outright: "Address family IPv4 is not allowed with protocol
	// ICMPv6", and the mirror of it. ANY is accepted for both, so only the two
	// crossed combinations are errors.
	//
	// A null address_family is read as IP4 rather than skipped. The attribute
	// defaults to a static IP4, so an omitted value is certain to end up there, and
	// skipping it would miss the most likely spelling of this mistake: a bare ICMPV6
	// rule that never mentions the address family at all.
	if utils.IsKnown(rule.Protocol) && !rule.AddressFamily.IsUnknown() {
		family := rule.AddressFamily.ValueString()
		configured := !rule.AddressFamily.IsNull()
		if !configured {
			family = "IP4"
		}

		protocol := rule.Protocol.ValueString()
		if (protocol == "ICMPV4" && family == "IP6") || (protocol == "ICMPV6" && family == "IP4") {
			allowed := "IP6"
			if protocol == "ICMPV4" {
				allowed = "IP4"
			}
			detail := fmt.Sprintf(
				"address_family '%s' is not allowed with protocol %s. Use '%s' or 'ANY'.",
				family, protocol, allowed,
			)
			if !configured {
				detail = fmt.Sprintf(
					"address_family defaults to 'IP4', which is not allowed with protocol %s. Set it to '%s' or 'ANY'.",
					protocol, allowed,
				)
			}
			resp.Diagnostics.AddAttributeError(
				req.Path.AtName("address_family"),
				"Invalid address_family configuration",
				detail,
			)
		}
	}

	// A rule that matches any address family cannot restrict addresses: the API
	// rejects a specific address on one. The wildcard is allowed, because it is not a
	// restriction and is the value the provider stores for every rule.
	for _, list := range []struct {
		attribute string
		value     basetypes.ListValue
	}{
		{"local_address", rule.LocalAddress},
		{"remote_address", rule.RemoteAddress},
	} {
		addresses := utils.ListTypeAs[*addressRangeModel](ctx, list.value, &resp.Diagnostics)
		listPath := req.Path.AtName(list.attribute)

		if rule.AddressFamily.ValueString() == "ANY" && namesSpecificAddresses(addresses) {
			resp.Diagnostics.AddAttributeError(
				listPath,
				"Invalid address_family configuration",
				list.attribute+" cannot name specific addresses when address_family is 'ANY'. "+
					"Remove the addresses, use a single '*' entry, or choose 'IP4' or 'IP6'.",
			)
		}

		// The wildcard address carries no netmask: the API drops one, and the read
		// reports 0, so a configured value could never equal what comes back.
		for i, address := range addresses {
			if address == nil || address.Address.ValueString() != apiWildcard {
				continue
			}
			if !utils.IsKnown(address.Netmask) || address.Netmask.ValueInt64() == 0 {
				continue
			}
			resp.Diagnostics.AddAttributeError(
				listPath.AtListIndex(i).AtName("netmask"),
				"Invalid netmask configuration",
				"netmask must be 0, or omitted, on the '*' address. It matches any address, so there is no prefix to mask.",
			)
		}
	}

	// A single port is expressed by omitting end or setting it to 0. The API rejects
	// start == end as a duplicate port, and end < start has no meaning.
	for _, list := range []struct {
		attribute string
		value     basetypes.ListValue
	}{
		{"local_port", rule.LocalPort},
		{"remote_port", rule.RemotePort},
	} {
		ports := utils.ListTypeAs[*portRangeModel](ctx, list.value, &resp.Diagnostics)
		for i, port := range ports {
			if port == nil || !utils.IsKnown(port.Start) || !utils.IsKnown(port.End) {
				continue
			}
			end := port.End.ValueInt64()
			if end == 0 || end > port.Start.ValueInt64() {
				continue
			}
			resp.Diagnostics.AddAttributeError(
				req.Path.AtName(list.attribute).AtListIndex(i).AtName("end"),
				"Invalid port range",
				fmt.Sprintf(
					"end (%d) must be greater than start (%d). Omit end, or set it to 0, for a single port.",
					end, port.Start.ValueInt64(),
				),
			)
		}
	}
}

// namesSpecificAddresses reports whether a configured address list restricts the rule to
// particular addresses. A list of nothing but wildcards is not a restriction.
func namesSpecificAddresses(addresses []*addressRangeModel) bool {
	for _, address := range addresses {
		if address == nil || address.Address.IsUnknown() {
			continue
		}
		if address.Address.ValueString() != apiWildcard {
			return true
		}
	}
	return false
}
