package firewall

import (
	"context"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// validateRuleForPlatform owns the cross-field rules that need the resource's
// platform, so they cannot live on the rules element the way
// ruleAttributeApplicability's do. Every branch is covered here; the acceptance
// suite carries one representative case per path to prove the validation is wired
// to the right attribute.

// ruleGroupConfig builds a config holding the given platform and rules. Config has
// no Set method, so the value is built through a Plan and its Raw reused.
//
// It exists only to exercise the ValidateConfig shell: the platform gate and the
// absent-rules and nil-element guards, none of which are reachable through
// validateRuleForPlatform. Every per-rule check is tested by calling that function
// directly, so a new validator test wants ruleDetails, not this.
func ruleGroupConfig(t *testing.T, platform types.String, rules types.List) tfsdk.Config {
	t.Helper()
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	(&firewallRuleGroupResource{}).Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("building schema: %v", schemaResp.Diagnostics)
	}

	plan := tfsdk.Plan{Schema: schemaResp.Schema}
	diags := plan.Set(ctx, firewallRuleGroupResourceModel{
		ID:          types.StringValue("group-a"),
		Name:        types.StringValue("group"),
		Description: types.StringNull(),
		Platform:    platform,
		Enabled:     types.BoolValue(true),
		Rules:       rules,
	})
	if diags.HasError() {
		t.Fatalf("setting config: %v", diags)
	}

	return tfsdk.Config{Schema: schemaResp.Schema, Raw: plan.Raw}
}

// validateRuleGroupConfig runs ValidateConfig and returns every diagnostic detail.
func validateRuleGroupConfig(t *testing.T, config tfsdk.Config) []string {
	t.Helper()

	resp := &resource.ValidateConfigResponse{}
	(&firewallRuleGroupResource{}).ValidateConfig(
		context.Background(),
		resource.ValidateConfigRequest{Config: config},
		resp,
	)

	return diagDetails(resp.Diagnostics)
}

// ruleDetails runs the per-rule platform checks and returns every diagnostic
// detail, so a case that fires the wrong check as well as the right one fails.
func ruleDetails(platform string, rule firewallRuleModel) []string {
	diags := validateRuleForPlatform(
		context.Background(),
		platform,
		&rule,
		path.Root("rules").AtListIndex(0),
	)

	return diagDetails(diags)
}

func TestValidateRuleForPlatform(t *testing.T) {
	t.Parallel()

	// fqdnRule is the shape every FQDN restriction starts from: outbound, on
	// Windows, with no specific remote address.
	fqdnRule := func() firewallRuleModel {
		rule := tfRule("rule-a", "a rule")
		rule.Fqdn = types.StringValue("example.com")

		return rule
	}

	tests := []struct {
		name     string
		platform string
		mutate   func(*firewallRuleModel)
		want     []string
	}{
		{
			name:     "an FQDN rule that is not outbound is rejected",
			platform: "Windows",
			mutate: func(r *firewallRuleModel) {
				*r = fqdnRule()
				r.Direction = types.StringValue("IN")
			},
			want: []string{"FQDN rules must have direction set to 'OUT'."},
		},
		{
			name:     "an FQDN rule naming a remote address is rejected",
			platform: "Windows",
			mutate: func(r *firewallRuleModel) {
				*r = fqdnRule()
				r.RemoteAddress = addressRangeList("10.0.0.0", 8)
			},
			want: []string{"FQDN and remote_address cannot be used together. FQDN rules use domain resolution instead of IP addresses."},
		},
		{
			name:     "an FQDN rule on Linux is rejected",
			platform: "Linux",
			mutate: func(r *firewallRuleModel) {
				*r = fqdnRule()
			},
			want: []string{"FQDN is not supported on Linux platform."},
		},
		{
			name:     "an FQDN containing a subdirectory is rejected",
			platform: "Windows",
			mutate: func(r *firewallRuleModel) {
				*r = fqdnRule()
				r.Fqdn = types.StringValue("example.com/api")
			},
			want: []string{"FQDN should not contain subdirectories (e.g., 'example.com/api' is invalid)."},
		},
		{
			// The FQDN restrictions do not short-circuit each other. A single rule
			// can break all four at once, and a user fixing one at a time would
			// otherwise need four applies to learn about the rest.
			name:     "a rule breaking every FQDN restriction reports all of them",
			platform: "Linux",
			mutate: func(r *firewallRuleModel) {
				*r = fqdnRule()
				r.Fqdn = types.StringValue("example.com/api")
				r.Direction = types.StringValue("IN")
				r.RemoteAddress = addressRangeList("10.0.0.0", 8)
			},
			want: []string{
				"FQDN rules must have direction set to 'OUT'.",
				"FQDN and remote_address cannot be used together. FQDN rules use domain resolution instead of IP addresses.",
				"FQDN is not supported on Linux platform.",
				"FQDN should not contain subdirectories (e.g., 'example.com/api' is invalid).",
			},
		},
		{
			// The wildcard remote address is not a specific address, so an FQDN
			// rule keeping the schema default has to be accepted.
			name:     "an FQDN rule with the wildcard remote address is accepted",
			platform: "Windows",
			mutate: func(r *firewallRuleModel) {
				*r = fqdnRule()
			},
			want: nil,
		},
		{
			name:     "service_name on Mac is rejected",
			platform: "Mac",
			mutate: func(r *firewallRuleModel) {
				r.ServiceName = types.StringValue("TestService")
			},
			want: []string{"service_name is only supported on Windows platform."},
		},
		{
			name:     "service_name on Linux is rejected",
			platform: "Linux",
			mutate: func(r *firewallRuleModel) {
				r.ServiceName = types.StringValue("TestService")
			},
			want: []string{"service_name is only supported on Windows platform."},
		},
		{
			name:     "service_name on Windows is accepted",
			platform: "Windows",
			mutate: func(r *firewallRuleModel) {
				r.ServiceName = types.StringValue("TestService")
			},
			want: nil,
		},
		{
			name:     "executable_path on Linux is rejected",
			platform: "Linux",
			mutate: func(r *firewallRuleModel) {
				r.ExecutablePath = types.StringValue("/usr/bin/curl")
			},
			want: []string{"executable_path is not supported on Linux platform."},
		},
		{
			// Mac supports it; only Linux does not.
			name:     "executable_path on Mac is accepted",
			platform: "Mac",
			mutate: func(r *firewallRuleModel) {
				r.ExecutablePath = types.StringValue("/usr/bin/curl")
			},
			want: nil,
		},
		{
			name:     "a non-ANY network_location on Linux is rejected",
			platform: "Linux",
			mutate: func(r *firewallRuleModel) {
				r.NetworkLocation = types.StringValue("PUBLIC")
			},
			want: []string{"network_location must be 'ANY' on Linux platform."},
		},
		{
			name:     "ANY network_location on Linux is accepted",
			platform: "Linux",
			mutate: func(r *firewallRuleModel) {
				r.NetworkLocation = types.StringValue("ANY")
			},
			want: nil,
		},
		{
			// Configuration carries null until the schema default applies, so an
			// omitted network_location must not be read as a non-ANY value.
			name:     "an omitted network_location on Linux is accepted",
			platform: "Linux",
			mutate: func(r *firewallRuleModel) {
				r.NetworkLocation = types.StringNull()
			},
			want: nil,
		},
		{
			name:     "a non-ANY network_location on Windows is accepted",
			platform: "Windows",
			mutate: func(r *firewallRuleModel) {
				r.NetworkLocation = types.StringValue("PUBLIC")
			},
			want: nil,
		},
		{
			name:     "local_port on a protocol without ports is rejected",
			platform: "Windows",
			mutate: func(r *firewallRuleModel) {
				r.Protocol = types.StringValue("ANY")
				r.LocalPort = portRangeList(443, 0)
			},
			want: []string{"local_port is only valid for TCP or UDP protocols."},
		},
		{
			name:     "remote_port on a protocol without ports is rejected",
			platform: "Windows",
			mutate: func(r *firewallRuleModel) {
				r.Protocol = types.StringValue("ANY")
				r.RemotePort = portRangeList(443, 0)
			},
			want: []string{"remote_port is only valid for TCP or UDP protocols."},
		},
		{
			name:     "ports on UDP are accepted",
			platform: "Windows",
			mutate: func(r *firewallRuleModel) {
				r.Protocol = types.StringValue("UDP")
				r.LocalPort = portRangeList(443, 0)
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rule := tfRule("rule-a", "a rule")
			tt.mutate(&rule)

			// The whole set is compared, so a case cannot pass while a second,
			// unwanted check also fires.
			got := slices.Sorted(slices.Values(ruleDetails(tt.platform, rule)))
			want := slices.Sorted(slices.Values(tt.want))
			if !slices.Equal(got, want) {
				t.Errorf("diagnostic details:\n  got  %v\n  want %v", got, want)
			}
		})
	}
}

// TestValidateRuleForPlatformLinuxProtocols covers every protocol the Linux agent
// does not support. Each produces its own message, and the acceptance suite only
// runs one of them rather than paying for a live plan per protocol.
func TestValidateRuleForPlatformLinuxProtocols(t *testing.T) {
	t.Parallel()

	for _, protocol := range linuxUnsupportedProtocols {
		t.Run(protocol, func(t *testing.T) {
			t.Parallel()

			rule := tfRule("rule-a", "a rule")
			rule.Protocol = types.StringValue(protocol)

			want := []string{"Protocol '" + protocol + "' is not supported on Linux platform."}
			got := slices.Sorted(slices.Values(ruleDetails("Linux", rule)))
			if !slices.Equal(got, want) {
				t.Errorf("diagnostic details:\n  got  %v\n  want %v", got, want)
			}
		})
	}
}

// TestValidateConfigSkipsWithoutPlatform covers the gate that returns before any
// check runs. Every branch below it compares against a literal platform, so an
// interpolated one has to be left alone rather than treated as no platform at all.
func TestValidateConfigSkipsWithoutPlatform(t *testing.T) {
	t.Parallel()

	// A rule that would be rejected outright on Linux.
	rule := tfRule("rule-a", "a rule")
	rule.Fqdn = types.StringValue("example.com/api")
	rule.ExecutablePath = types.StringValue("/usr/bin/curl")
	rule.ServiceName = types.StringValue("TestService")
	rules := tfList(firewallRuleModel{}.attrTypes(), []firewallRuleModel{rule})

	// An unknown platform is the reachable case: platform is Required with a
	// OneOf validator, so it is never the empty string in a configuration that is
	// not already failing, but it is unknown whenever it is interpolated.
	details := validateRuleGroupConfig(t, ruleGroupConfig(t, types.StringUnknown(), rules))
	if len(details) > 0 {
		t.Errorf("expected no diagnostics for an unknown platform, got: %v", details)
	}
}

// TestValidateConfigSkipsAbsentRules covers the null-element and empty-list paths.
// A null rules element is representable in configuration, and dereferencing it
// would panic rather than produce a diagnostic.
func TestValidateConfigSkipsAbsentRules(t *testing.T) {
	t.Parallel()

	objectType := types.ObjectType{AttrTypes: firewallRuleModel{}.attrTypes()}

	cases := map[string]types.List{
		"a null rules attribute": types.ListNull(objectType),
		"an empty rules list":    types.ListValueMust(objectType, []attr.Value{}),
		"a null rules element":   types.ListValueMust(objectType, []attr.Value{types.ObjectNull(firewallRuleModel{}.attrTypes())}),
		"an unknown rules list":  types.ListUnknown(objectType),
	}

	for name, rules := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			details := validateRuleGroupConfig(t,
				ruleGroupConfig(t, types.StringValue("Linux"), rules))
			if len(details) > 0 {
				t.Fatalf("expected no diagnostics, got: %v", details)
			}
		})
	}
}

// TestRuleAttributeApplicability covers the checks that live on the rules element because
// the invariants are internal to one rule.
func TestRuleAttributeApplicability(t *testing.T) {
	t.Parallel()

	// specific is an address list that names one network rather than the wildcard.
	specific := addressRangeList("10.0.0.0", 8)

	// rulePath is the element path the validator is attached at, and the base for
	// every attribute path a diagnostic is expected on.
	rulePath := path.Root("rules").AtListIndex(0)

	tests := []struct {
		name   string
		mutate func(*firewallRuleModel)
		// wantPath is the attribute the diagnostic must name, empty when the rule
		// is expected to validate. The validator enforces four unrelated rules, so
		// a case that only asserted "an error" could pass on the wrong one.
		wantPath path.Path
	}{
		{
			name:   "a plain TCP rule is accepted",
			mutate: func(*firewallRuleModel) {},
		},
		{
			name: "an ICMP type on a TCP rule is rejected",
			mutate: func(r *firewallRuleModel) {
				r.IcmpType = types.StringValue("8")
			},
			wantPath: rulePath.AtName("icmp_type"),
		},
		{
			// The wildcard is no more valid here than a real type: the payload
			// builder sends no icmp object for a non-ICMP protocol, so the API
			// stores nothing and the read reports null.
			name: "a wildcard ICMP code on a TCP rule is rejected",
			mutate: func(r *firewallRuleModel) {
				r.IcmpCode = types.StringValue(apiWildcard)
			},
			wantPath: rulePath.AtName("icmp_code"),
		},
		{
			name: "an ICMP type on an ICMP rule is accepted",
			mutate: func(r *firewallRuleModel) {
				r.Protocol = types.StringValue("ICMPV4")
				r.IcmpType = types.StringValue("8")
			},
		},
		{
			// The API rejects a specific address on a rule that matches any address
			// family.
			name: "a specific address with address_family ANY is rejected",
			mutate: func(r *firewallRuleModel) {
				r.AddressFamily = types.StringValue("ANY")
				r.LocalAddress = specific
			},
			wantPath: rulePath.AtName("local_address"),
		},
		{
			// The wildcard is not a restriction, and it is the value the provider
			// stores for every rule, so writing it out has to be accepted.
			name: "the wildcard address with address_family ANY is accepted",
			mutate: func(r *firewallRuleModel) {
				r.AddressFamily = types.StringValue("ANY")
				r.LocalAddress = wildcardAddressList()
				r.RemoteAddress = wildcardAddressList()
			},
		},
		{
			// Configuration has no netmask until the schema default is applied, so
			// the check cannot compare against the wildcard list value.
			name: "a wildcard address with no netmask is accepted with ANY",
			mutate: func(r *firewallRuleModel) {
				r.AddressFamily = types.StringValue("ANY")
				r.LocalAddress = tfList(addressRangeAttrTypes(), []addressRangeModel{
					{Address: types.StringValue(apiWildcard), Netmask: types.Int64Null()},
				})
			},
		},
		{
			name: "a specific address with address_family IP4 is accepted",
			mutate: func(r *firewallRuleModel) {
				r.LocalAddress = specific
			},
		},
		{
			// The API drops a netmask on the wildcard and the read reports 0, so a
			// configured value could never equal what comes back.
			name: "a netmask on the wildcard address is rejected",
			mutate: func(r *firewallRuleModel) {
				r.RemoteAddress = addressRangeList(apiWildcard, 24)
			},
			wantPath: rulePath.AtName("remote_address").AtListIndex(0).AtName("netmask"),
		},
		{
			// The API rejects start == end as a duplicate port. This lives on the
			// element rather than in ValidateConfig, which is gated on the resource's
			// platform being known.
			name: "a port range whose end equals its start is rejected",
			mutate: func(r *firewallRuleModel) {
				r.LocalPort = portRangeList(443, 443)
			},
			wantPath: rulePath.AtName("local_port").AtListIndex(0).AtName("end"),
		},
		{
			name: "a single port expressed as end 0 is accepted",
			mutate: func(r *firewallRuleModel) {
				r.LocalPort = portRangeList(443, 0)
			},
		},
		{
			// A null element is representable in configuration, and must not panic.
			name: "a null port element is ignored",
			mutate: func(r *firewallRuleModel) {
				r.LocalPort = types.ListValueMust(
					types.ObjectType{AttrTypes: portRangeAttrTypes()},
					[]attr.Value{types.ObjectNull(portRangeAttrTypes())},
				)
			},
		},
		{
			name: "an ICMP code on an ICMPV6 rule is accepted",
			mutate: func(r *firewallRuleModel) {
				r.Protocol = types.StringValue("ICMPV6")
				r.AddressFamily = types.StringValue("IP6")
				r.IcmpType = types.StringValue("128")
				r.IcmpCode = types.StringValue("0")
			},
		},
		{
			// ICMPv6 runs only over IPv6, and the default address_family is IP4, so
			// the bare ICMPV6 rule is the likeliest spelling of this mistake.
			name: "an ICMPV6 rule with the default address_family is rejected",
			mutate: func(r *firewallRuleModel) {
				r.Protocol = types.StringValue("ICMPV6")
				r.AddressFamily = types.StringNull()
			},
			wantPath: rulePath.AtName("address_family"),
		},
		{
			name: "an ICMPV6 rule with address_family IP4 is rejected",
			mutate: func(r *firewallRuleModel) {
				r.Protocol = types.StringValue("ICMPV6")
				r.AddressFamily = types.StringValue("IP4")
			},
			wantPath: rulePath.AtName("address_family"),
		},
		{
			name: "an ICMPV4 rule with address_family IP6 is rejected",
			mutate: func(r *firewallRuleModel) {
				r.Protocol = types.StringValue("ICMPV4")
				r.AddressFamily = types.StringValue("IP6")
			},
			wantPath: rulePath.AtName("address_family"),
		},
		{
			// ANY is accepted for both ICMP protocols, which the API confirms.
			name: "an ICMPV6 rule with address_family ANY is accepted",
			mutate: func(r *firewallRuleModel) {
				r.Protocol = types.StringValue("ICMPV6")
				r.AddressFamily = types.StringValue("ANY")
			},
		},
		{
			name: "an ICMPV4 rule with address_family ANY is accepted",
			mutate: func(r *firewallRuleModel) {
				r.Protocol = types.StringValue("ICMPV4")
				r.AddressFamily = types.StringValue("ANY")
			},
		},
		{
			// An unresolved address_family cannot be classified, so the pair is left
			// to the API rather than guessed at.
			name: "an ICMPV6 rule with an unknown address_family is accepted",
			mutate: func(r *firewallRuleModel) {
				r.Protocol = types.StringValue("ICMPV6")
				r.AddressFamily = types.StringUnknown()
			},
		},
		{
			// The second iteration of the address loop, which the netmask cases
			// exercise but the address_family cases did not.
			name: "a specific remote address with address_family ANY is rejected",
			mutate: func(r *firewallRuleModel) {
				r.AddressFamily = types.StringValue("ANY")
				r.RemoteAddress = specific
			},
			wantPath: rulePath.AtName("remote_address"),
		},
		{
			// An interpolated protocol is not known until apply, so the ICMP
			// applicability check cannot fire on it yet.
			name: "ICMP values with an unknown protocol are accepted",
			mutate: func(r *firewallRuleModel) {
				r.Protocol = types.StringUnknown()
				r.IcmpType = types.StringValue("8")
				r.IcmpCode = types.StringValue("0")
			},
		},
		{
			// An unknown address cannot be compared against the wildcard, so it
			// must not count as naming a specific address.
			name: "an unknown address with address_family ANY is accepted",
			mutate: func(r *firewallRuleModel) {
				r.AddressFamily = types.StringValue("ANY")
				r.LocalAddress = tfList(addressRangeAttrTypes(), []addressRangeModel{
					{Address: types.StringUnknown(), Netmask: types.Int64Null()},
				})
			},
		},
		{
			// Same for an unknown netmask on the wildcard: there is nothing to
			// compare against 0 yet.
			name: "an unknown netmask on the wildcard address is accepted",
			mutate: func(r *firewallRuleModel) {
				r.LocalAddress = tfList(addressRangeAttrTypes(), []addressRangeModel{
					{Address: types.StringValue(apiWildcard), Netmask: types.Int64Unknown()},
				})
			},
		},
		{
			name: "a port range with an unknown start is accepted",
			mutate: func(r *firewallRuleModel) {
				r.LocalPort = tfList(portRangeAttrTypes(), []portRangeModel{
					{Start: types.Int64Unknown(), End: types.Int64Value(443)},
				})
			},
		},
		{
			name: "a port range with an unknown end is accepted",
			mutate: func(r *firewallRuleModel) {
				r.LocalPort = tfList(portRangeAttrTypes(), []portRangeModel{
					{Start: types.Int64Value(443), End: types.Int64Unknown()},
				})
			},
		},
		{
			// end is Optional+Computed, so configuration carries null until the
			// schema default supplies 0.
			name: "a port range with a null end is accepted",
			mutate: func(r *firewallRuleModel) {
				r.LocalPort = tfList(portRangeAttrTypes(), []portRangeModel{
					{Start: types.Int64Value(443), End: types.Int64Null()},
				})
			},
		},
		{
			name: "a valid port range is accepted",
			mutate: func(r *firewallRuleModel) {
				r.LocalPort = portRangeList(8000, 9000)
			},
		},
		{
			name: "a port range whose end is below its start is rejected",
			mutate: func(r *firewallRuleModel) {
				r.LocalPort = portRangeList(9000, 8000)
			},
			wantPath: rulePath.AtName("local_port").AtListIndex(0).AtName("end"),
		},
		{
			// The second iteration of the port loop.
			name: "an invalid remote port range is rejected",
			mutate: func(r *firewallRuleModel) {
				r.RemotePort = portRangeList(9000, 8000)
			},
			wantPath: rulePath.AtName("remote_port").AtListIndex(0).AtName("end"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			rule := tfRule("rule-a", "a rule")
			tt.mutate(&rule)

			object, diags := types.ObjectValueFrom(ctx, firewallRuleModel{}.attrTypes(), rule)
			if diags.HasError() {
				t.Fatalf("wrapping rule: %v", diags)
			}

			req := validator.ObjectRequest{
				Path:        rulePath,
				ConfigValue: object,
			}
			resp := &validator.ObjectResponse{}

			ruleAttributeApplicability().ValidateObject(ctx, req, resp)

			if len(tt.wantPath.Steps()) == 0 {
				if resp.Diagnostics.HasError() {
					t.Fatalf("expected no error, got: %v", resp.Diagnostics)
				}

				return
			}

			errors := resp.Diagnostics.Errors()
			if len(errors) == 0 {
				t.Fatal("expected an error, got none")
			}
			withPath, ok := errors[0].(diag.DiagnosticWithPath)
			if !ok {
				t.Fatalf("diagnostic %v carries no path, so it does not name an attribute", errors[0])
			}
			if !withPath.Path().Equal(tt.wantPath) {
				t.Errorf("diagnostic names %s, want %s: %v", withPath.Path(), tt.wantPath, errors[0])
			}
		})
	}
}

// TestRuleAttributeApplicabilityAbsentObject covers the guard that returns before
// decoding. A null or unknown rules element is representable in configuration, and
// reaching the checks with one would panic rather than produce a diagnostic.
func TestRuleAttributeApplicabilityAbsentObject(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value types.Object
	}{
		{"a null rule is ignored", types.ObjectNull(firewallRuleModel{}.attrTypes())},
		{"an unknown rule is ignored", types.ObjectUnknown(firewallRuleModel{}.attrTypes())},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := validator.ObjectRequest{
				Path:        path.Root("rules").AtListIndex(0),
				ConfigValue: tt.value,
			}
			resp := &validator.ObjectResponse{}

			ruleAttributeApplicability().ValidateObject(context.Background(), req, resp)

			if resp.Diagnostics.HasError() {
				t.Fatalf("expected no error, got: %v", resp.Diagnostics)
			}
		})
	}
}
