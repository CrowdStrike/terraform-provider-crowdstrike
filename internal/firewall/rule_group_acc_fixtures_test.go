package firewall_test

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// This file holds the fixtures the rule group acceptance tests configure. A
// fixture is the single source of truth for one rule: hcl() renders the
// configuration and want() renders the complete expected state, so an assertion
// can never describe a value the configuration did not contain.
//
// want() does not read the resource schema. It restates the default contract as
// literals, and these tests live in package firewall_test, so they cannot reach
// isICMPProtocol or icmpValueDefault() even if they wanted to. Changing a schema
// default therefore breaks every test rather than silently agreeing with itself.

// opt marks a scalar fixture field as explicitly configured. An unset field is
// omitted from the rendered HCL, so its expected state is the schema default.
//
// opt is a value type on purpose. Copying a fixture and tweaking one field is
// the core move in these tests, and a pointer field would let the copy alias the
// original.
type opt[T any] struct {
	value T
	set   bool
}

// setVal marks a fixture field as explicitly configured with the given value.
func setVal[T any](v T) opt[T] {
	return opt[T]{value: v, set: true}
}

// addrFixture is one entry of a local_address or remote_address list.
type addrFixture struct {
	Address string
	Netmask opt[int64]
}

// addr builds an address entry. Passing no netmask leaves it out of the
// configuration, which is how a test asserts the 0 default.
func addr(address string, netmask ...int64) addrFixture {
	if len(netmask) > 1 {
		panic(fmt.Sprintf("addr(%q): at most one netmask, got %d", address, len(netmask)))
	}

	a := addrFixture{Address: address}
	if len(netmask) == 1 {
		a.Netmask = setVal(netmask[0])
	}

	return a
}

// portFixture is one entry of a local_port or remote_port list.
type portFixture struct {
	Start int64
	End   opt[int64]
}

// port builds a port entry. Passing no end leaves it out of the configuration,
// which is how a test asserts the 0 default and the single-port spelling.
func port(start int64, end ...int64) portFixture {
	if len(end) > 1 {
		panic(fmt.Sprintf("port(%d): at most one end, got %d", start, len(end)))
	}

	p := portFixture{Start: start}
	if len(end) == 1 {
		p.End = setVal(end[0])
	}

	return p
}

// ruleFixture describes one element of the rules list.
type ruleFixture struct {
	// Required by the schema, so always rendered.
	Name      string
	Action    string
	Direction string
	Protocol  string

	Description     opt[string]
	AddressFamily   opt[string]
	Fqdn            opt[string]
	NetworkLocation opt[string]
	ExecutablePath  opt[string]
	ServiceName     opt[string]
	IcmpType        opt[string]
	IcmpCode        opt[string]
	Enabled         opt[bool]
	WatchMode       opt[bool]

	// These four are plain nilable slices rather than opt values. All of them
	// carry listvalidator.SizeAtLeast(1), so an explicitly empty list is never a
	// valid configuration and nil is the only way to spell "unset".
	LocalAddress  []addrFixture
	RemoteAddress []addrFixture
	LocalPort     []portFixture
	RemotePort    []portFixture
}

// newRule builds a rule with only its required attributes set.
func newRule(name, action, direction, protocol string) ruleFixture {
	return ruleFixture{
		Name:      name,
		Action:    action,
		Direction: direction,
		Protocol:  protocol,
	}
}

// newTCPRule builds the minimal valid rule most tests start from.
func newTCPRule(name string) ruleFixture {
	return newRule(name, "ALLOW", "OUT", "TCP")
}

// hcl renders the rule as an HCL object, emitting only the attributes the
// fixture explicitly sets.
func (r ruleFixture) hcl() string {
	lines := []string{
		fmt.Sprintf("name = %q", r.Name),
		fmt.Sprintf("action = %q", r.Action),
		fmt.Sprintf("direction = %q", r.Direction),
		fmt.Sprintf("protocol = %q", r.Protocol),
	}

	scalars := []struct {
		attr  string
		value opt[string]
	}{
		{"description", r.Description},
		{"address_family", r.AddressFamily},
		{"fqdn", r.Fqdn},
		{"network_location", r.NetworkLocation},
		{"executable_path", r.ExecutablePath},
		{"service_name", r.ServiceName},
		{"icmp_type", r.IcmpType},
		{"icmp_code", r.IcmpCode},
	}
	for _, s := range scalars {
		if s.value.set {
			// %q, not bare quotes: Windows executable paths and multi-FQDN
			// values contain characters that break naive interpolation.
			lines = append(lines, fmt.Sprintf("%s = %q", s.attr, s.value.value))
		}
	}

	if r.Enabled.set {
		lines = append(lines, fmt.Sprintf("enabled = %t", r.Enabled.value))
	}
	if r.WatchMode.set {
		lines = append(lines, fmt.Sprintf("watch_mode = %t", r.WatchMode.value))
	}

	if r.LocalAddress != nil {
		lines = append(lines, addressHCL("local_address", r.LocalAddress))
	}
	if r.RemoteAddress != nil {
		lines = append(lines, addressHCL("remote_address", r.RemoteAddress))
	}
	if r.LocalPort != nil {
		lines = append(lines, portHCL("local_port", r.LocalPort))
	}
	if r.RemotePort != nil {
		lines = append(lines, portHCL("remote_port", r.RemotePort))
	}

	for i, line := range lines {
		lines[i] = "      " + line
	}

	return "    {\n" + strings.Join(lines, "\n") + "\n    }"
}

// want returns the complete expected state of the rule, filling every attribute
// the fixture leaves unset with its documented default.
func (r ruleFixture) want() knownvalue.Check {
	checks := map[string]knownvalue.Check{
		"id":               knownvalue.NotNull(),
		"name":             knownvalue.StringExact(r.Name),
		"action":           knownvalue.StringExact(r.Action),
		"direction":        knownvalue.StringExact(r.Direction),
		"protocol":         knownvalue.StringExact(r.Protocol),
		"description":      wantOptString(r.Description),
		"fqdn":             wantOptString(r.Fqdn),
		"executable_path":  wantOptString(r.ExecutablePath),
		"service_name":     wantOptString(r.ServiceName),
		"address_family":   wantOptStringOr(r.AddressFamily, "IP4"),
		"network_location": wantOptStringOr(r.NetworkLocation, "ANY"),
		"enabled":          wantOptBoolOr(r.Enabled, true),
		"watch_mode":       wantOptBoolOr(r.WatchMode, false),
		"local_address":    wantAddresses(r.LocalAddress),
		"remote_address":   wantAddresses(r.RemoteAddress),
		"local_port":       wantPorts(r.LocalPort),
		"remote_port":      wantPorts(r.RemotePort),
		"icmp_type":        r.wantICMP(r.IcmpType),
		"icmp_code":        r.wantICMP(r.IcmpCode),
	}

	return knownvalue.ObjectExact(checks)
}

// wantICMP resolves icmp_type or icmp_code. Unlike every other default, this one
// depends on a sibling attribute: neither has a schema Default, and
// icmpValueDefault() fills them from the planned protocol.
func (r ruleFixture) wantICMP(v opt[string]) knownvalue.Check {
	if v.set {
		return knownvalue.StringExact(v.value)
	}
	if r.Protocol == "ICMPV4" || r.Protocol == "ICMPV6" {
		return knownvalue.StringExact("*")
	}

	return knownvalue.Null()
}

// wantOptString expects null when the attribute is unset, which is the contract
// for every Optional-only string on a rule.
func wantOptString(v opt[string]) knownvalue.Check {
	if !v.set {
		return knownvalue.Null()
	}

	return knownvalue.StringExact(v.value)
}

// wantOptStringOr expects the schema default when the attribute is unset.
func wantOptStringOr(v opt[string], def string) knownvalue.Check {
	if !v.set {
		return knownvalue.StringExact(def)
	}

	return knownvalue.StringExact(v.value)
}

// wantOptBoolOr expects the schema default when the attribute is unset.
func wantOptBoolOr(v opt[bool], def bool) knownvalue.Check {
	if !v.set {
		return knownvalue.Bool(def)
	}

	return knownvalue.Bool(v.value)
}

// wantAddresses expects the single wildcard entry the schema defaults to when
// the list is unset.
func wantAddresses(addrs []addrFixture) knownvalue.Check {
	if addrs == nil {
		addrs = []addrFixture{addr("*")}
	}

	checks := make([]knownvalue.Check, 0, len(addrs))
	for _, a := range addrs {
		var netmask int64
		if a.Netmask.set {
			netmask = a.Netmask.value
		}
		checks = append(checks, knownvalue.ObjectExact(map[string]knownvalue.Check{
			"address": knownvalue.StringExact(a.Address),
			"netmask": knownvalue.Int64Exact(netmask),
		}))
	}

	return knownvalue.ListExact(checks)
}

// wantPorts expects null when the list is unset. local_port and remote_port are
// Optional only, with no default, so an omitted list stays absent rather than
// becoming an empty one.
func wantPorts(ports []portFixture) knownvalue.Check {
	if ports == nil {
		return knownvalue.Null()
	}

	checks := make([]knownvalue.Check, 0, len(ports))
	for _, p := range ports {
		var end int64
		if p.End.set {
			end = p.End.value
		}
		checks = append(checks, knownvalue.ObjectExact(map[string]knownvalue.Check{
			"start": knownvalue.Int64Exact(p.Start),
			"end":   knownvalue.Int64Exact(end),
		}))
	}

	return knownvalue.ListExact(checks)
}

func addressHCL(attr string, addrs []addrFixture) string {
	entries := make([]string, 0, len(addrs))
	for _, a := range addrs {
		fields := fmt.Sprintf("address = %q", a.Address)
		if a.Netmask.set {
			fields += fmt.Sprintf(", netmask = %d", a.Netmask.value)
		}
		entries = append(entries, "{ "+fields+" }")
	}

	return fmt.Sprintf("%s = [%s]", attr, strings.Join(entries, ", "))
}

func portHCL(attr string, ports []portFixture) string {
	entries := make([]string, 0, len(ports))
	for _, p := range ports {
		fields := fmt.Sprintf("start = %d", p.Start)
		if p.End.set {
			fields += fmt.Sprintf(", end = %d", p.End.value)
		}
		entries = append(entries, "{ "+fields+" }")
	}

	return fmt.Sprintf("%s = [%s]", attr, strings.Join(entries, ", "))
}

// ruleGroupFixture describes the single rule group every test configures.
type ruleGroupFixture struct {
	Name string
	// Platform is Windows unless a test is about the platform itself.
	Platform string
	// Enabled is required by the schema, so it is always rendered. It is not an
	// opt and it deliberately has no group-builder default of false: basic and
	// enabled need a disabled group to cover the teardown path that skips the
	// pre-delete disable, and defaulting the shared builder to false would
	// remove that distinction from every other test.
	Enabled     bool
	Description opt[string]
	// Rules unset omits the attribute; set to an empty slice renders an
	// explicit empty list. Those are different states, and the rules lifecycle
	// tests both.
	Rules opt[[]ruleFixture]
}

// newRuleGroup builds an enabled Windows group with the given rules. Passing no
// rules renders an explicit empty list; use newRuleGroupNoRules to omit the
// attribute entirely.
func newRuleGroup(name string, rules ...ruleFixture) ruleGroupFixture {
	if rules == nil {
		rules = []ruleFixture{}
	}

	return ruleGroupFixture{
		Name:     name,
		Platform: "Windows",
		Enabled:  true,
		Rules:    setVal(rules),
	}
}

// newRuleGroupNoRules builds an enabled Windows group with the rules attribute
// omitted, which is not the same as an empty list.
func newRuleGroupNoRules(name string) ruleGroupFixture {
	return ruleGroupFixture{
		Name:     name,
		Platform: "Windows",
		Enabled:  true,
	}
}

// on returns a copy of the group on the given platform.
func (g ruleGroupFixture) on(platform string) ruleGroupFixture {
	g.Platform = platform
	return g
}

// disabled returns a copy of the group with enabled = false.
func (g ruleGroupFixture) disabled() ruleGroupFixture {
	g.Enabled = false
	return g
}

// hcl renders the group, emitting description only when it is set and rules only
// when the attribute is present.
func (g ruleGroupFixture) hcl() string {
	attrs := []string{
		fmt.Sprintf("  name = %q", g.Name),
		fmt.Sprintf("  platform = %q", g.Platform),
		fmt.Sprintf("  enabled = %t", g.Enabled),
	}

	if g.Description.set {
		attrs = append(attrs, fmt.Sprintf("  description = %q", g.Description.value))
	}

	if g.Rules.set {
		if len(g.Rules.value) == 0 {
			attrs = append(attrs, "\n  rules = []")
		} else {
			rendered := make([]string, 0, len(g.Rules.value))
			for _, r := range g.Rules.value {
				rendered = append(rendered, r.hcl())
			}
			attrs = append(attrs, fmt.Sprintf("\n  rules = [\n%s\n  ]", strings.Join(rendered, ",\n")))
		}
	}

	return fmt.Sprintf(`
resource "crowdstrike_firewall_rule_group" "test" {
%s
}
`, strings.Join(attrs, "\n"))
}

// wantRules returns the expected state of the rules attribute, distinguishing
// omitted from explicitly empty.
func (g ruleGroupFixture) wantRules() knownvalue.Check {
	if !g.Rules.set {
		return knownvalue.Null()
	}
	if len(g.Rules.value) == 0 {
		return knownvalue.ListSizeExact(0)
	}

	checks := make([]knownvalue.Check, 0, len(g.Rules.value))
	for _, r := range g.Rules.value {
		checks = append(checks, r.want())
	}

	return knownvalue.ListExact(checks)
}

// wantGroup returns every state check for the group, derived from the same
// fixture that rendered the configuration.
//
// It takes the whole group rather than a separate list of rules on purpose.
// Accepting rules separately would let a stale fixture, a wrong order or a wrong
// count be asserted against a configuration that never contained it, which is
// the drift this fixture exists to prevent.
func wantGroup(g ruleGroupFixture) []statecheck.StateCheck {
	return []statecheck.StateCheck{
		statecheck.ExpectKnownValue(ruleGroupResourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
		statecheck.ExpectKnownValue(ruleGroupResourceName, tfjsonpath.New("name"), knownvalue.StringExact(g.Name)),
		statecheck.ExpectKnownValue(ruleGroupResourceName, tfjsonpath.New("platform"), knownvalue.StringExact(g.Platform)),
		statecheck.ExpectKnownValue(ruleGroupResourceName, tfjsonpath.New("enabled"), knownvalue.Bool(g.Enabled)),
		statecheck.ExpectKnownValue(ruleGroupResourceName, tfjsonpath.New("description"), wantOptString(g.Description)),
		statecheck.ExpectKnownValue(ruleGroupResourceName, tfjsonpath.New("rules"), g.wantRules()),
	}
}
