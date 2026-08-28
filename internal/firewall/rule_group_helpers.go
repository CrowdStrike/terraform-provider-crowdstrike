package firewall

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client/firewall_management"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/swag"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// apiWildcard is the API's "any" value, and the provider's. It is what the API stores
// when a rule's address list is submitted empty and when an ICMP type or code is
// submitted empty, and what it reports for a rule that restricts neither. Because a
// configured value can never be planned as something else, and reads derive everything
// from the API response alone, this one spelling has to serve configuration, plan and
// state alike: it is what an omitted address list or ICMP value defaults to, and
// writing it out explicitly means the same thing.
const apiWildcard = "*"

var platformTitleCase = map[string]string{
	"windows": "Windows",
	"mac":     "Mac",
	"linux":   "Linux",
}

// normalizePlatform converts the API's lowercase platform value to the
// title-case form used in schema validation.
func normalizePlatform(platform string) string {
	if titleCase, ok := platformTitleCase[strings.ToLower(platform)]; ok {
		return titleCase
	}
	return platform
}

// addressFamilyToAPI maps the Terraform address_family value to the API value.
// The console's "Any" option is sent to the API as "NONE".
func addressFamilyToAPI(family string) string {
	if family == "ANY" {
		return "NONE"
	}
	return family
}

// addressFamilyFromAPI maps the API address_family value to the Terraform value.
func addressFamilyFromAPI(family string) string {
	if family == "NONE" {
		return "ANY"
	}
	return family
}

// protocolToAPI maps the Terraform protocol name to the IANA number the API
// takes. A name the mapping does not know becomes the wildcard, which is what the
// read reports for an unrecognized number, so the two agree.
func protocolToAPI(protocol types.String) string {
	if number, found := protocolMapping[protocol.ValueString()]; found {
		return number
	}
	return apiWildcard
}

// icmpValueToAPI maps an ICMP type or code to the API value. An unset value means
// any, which the API spells as the wildcard: it stores the wildcard for an ICMP
// rule that submits an empty type or code, so sending it is what the API would do
// anyway, said out loud.
func icmpValueToAPI(value types.String) string {
	if value.ValueString() == "" {
		return apiWildcard
	}
	return value.ValueString()
}

// icmpValuesFromAPI reports an ICMP rule's type and code the way the provider stores
// them. Only call it for a rule whose protocol is ICMP; every other protocol has no
// ICMP data and reads back as null.
//
// A rule that sends no icmp object at all still comes back with one, both values
// wildcarded, so a missing object means the same as two wildcards.
func icmpValuesFromAPI(icmp *models.FwmgrFirewallICMP) (types.String, types.String) {
	if icmp == nil {
		return types.StringValue(apiWildcard), types.StringValue(apiWildcard)
	}
	return icmpValueFromAPI(icmp.IcmpType), icmpValueFromAPI(icmp.IcmpCode)
}

// icmpValueFromAPI maps one API ICMP type or code to the value the provider stores.
// The API stores the wildcard for a value submitted empty, so an empty value and the
// wildcard are the same "any" and both read back as the wildcard.
func icmpValueFromAPI(value *string) types.String {
	if v := swag.StringValue(value); v != "" {
		return types.StringValue(v)
	}
	return types.StringValue(apiWildcard)
}

// getRuleGroup retrieves a rule group by ID. The returned boolean indicates
// the resource was not found (i.e., the API returned 404 or empty payload).
func (r *firewallRuleGroupResource) getRuleGroup(
	ctx context.Context,
	id string,
	op tferrors.Operation,
) (*models.FwmgrAPIRuleGroupV1, bool, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := firewall_management.NewGetRuleGroupsParams().
		WithContext(ctx).
		WithIds([]string{id})

	result, err := r.client.FirewallManagement.GetRuleGroups(params)
	if err != nil {
		d := tferrors.NewDiagnosticFromAPIError(op, err, apiScopesRead)
		if d.Summary() == tferrors.NotFoundErrorSummary {
			return nil, true, diags
		}
		diags.Append(d)
		return nil, false, diags
	}

	if result == nil || result.Payload == nil || len(result.Payload.Resources) == 0 || result.Payload.Resources[0] == nil {
		return nil, true, diags
	}

	// The API soft-deletes rule groups: a deleted group is still returned by this
	// endpoint, with deleted set and its rules already detached. Treating it as
	// live refreshes a group that no longer exists back into state, and the
	// missing rules then surface as an unexplained read failure.
	if swag.BoolValue(result.Payload.Resources[0].Deleted) {
		return nil, true, diags
	}

	return result.Payload.Resources[0], false, diags
}

// readRuleGroupState refreshes state from the API. Rules are always stored in
// the rule group's rule_ids order, which is the group's rule precedence. State
// order therefore mirrors the API, so an out-of-band reorder surfaces as a diff
// rather than being silently absorbed, and state.Rules[i] always corresponds to
// ruleGroup.RuleIds[i]. The returned boolean indicates the rule group no longer
// exists.
func (r *firewallRuleGroupResource) readRuleGroupState(
	ctx context.Context,
	state *firewallRuleGroupResourceModel,
) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics

	ruleGroup, removed, d := r.getRuleGroup(ctx, state.ID.ValueString(), tferrors.Read)
	diags.Append(d...)
	if diags.HasError() || removed {
		return removed, diags
	}

	state.Name = flex.StringPointerToFramework(ruleGroup.Name)
	state.Description = flex.StringPointerToFramework(ruleGroup.Description)
	if ruleGroup.Platform != nil {
		state.Platform = flex.StringValueToFramework(normalizePlatform(*ruleGroup.Platform))
	}
	state.Enabled = types.BoolPointerValue(ruleGroup.Enabled)

	if len(ruleGroup.RuleIds) == 0 {
		// rules is optional and not computed, so after an apply Terraform requires
		// the value to equal the configuration exactly: an explicitly empty list
		// must stay an empty list, and an omitted one must stay null. Collapsing
		// both to null makes "rules = []" fail with an inconsistent-result error.
		if !utils.IsKnown(state.Rules) || len(state.Rules.Elements()) > 0 {
			state.Rules = types.ListNull(types.ObjectType{AttrTypes: firewallRuleModel{}.attrTypes()})
		}
		return false, diags
	}

	rulesByFamily, d := fetchRulesByFamily(ctx, r.client.FirewallManagement, ruleGroup.RuleIds)
	diags.Append(d...)
	if diags.HasError() {
		return false, diags
	}
	orderedRules := orderRulesByFamily(rulesByFamily, ruleGroup.RuleIds)

	// Every rule_ids entry must resolve to a returned rule. If one does not,
	// state.Rules[i] no longer lines up with RuleIds[i] and a later update would
	// patch the wrong rule, so fail loudly rather than store a skewed list.
	if len(orderedRules) != len(ruleGroup.RuleIds) {
		diags.AddError(
			"Unexpected firewall rule group response",
			fmt.Sprintf(
				"Rule group '%s' references %d rules but %d could be retrieved. Retry, and please report this issue to the provider developers if it persists.",
				state.ID.ValueString(), len(ruleGroup.RuleIds), len(orderedRules),
			),
		)
		return false, diags
	}

	rulesList, d := wrapRules(ctx, orderedRules)
	diags.Append(d...)
	if diags.HasError() {
		return false, diags
	}
	state.Rules = rulesList

	return false, diags
}

// getRulesBatchSize is how many ids one GET /fwmgr/entities/rules/v1 request
// carries. The endpoint caps the ids a single request may take, so a group with
// more rules than the cap has to be fetched in batches; sending them all at once
// makes such a group permanently unreadable.
const getRulesBatchSize = 100

// fetchRulesByFamily retrieves firewall rules by family id, in batches, keyed by
// family. A rule group's rule_ids entries are family identifiers, the identity a
// rule keeps for its lifetime, so that is the key both callers need.
func fetchRulesByFamily(
	ctx context.Context,
	fwClient firewall_management.ClientService,
	ids []string,
) (map[string]*models.FwmgrFirewallRuleV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	rulesByFamily := make(map[string]*models.FwmgrFirewallRuleV1, len(ids))

	for start := 0; start < len(ids); start += getRulesBatchSize {
		params := firewall_management.NewGetRulesParams().
			WithContext(ctx).
			WithIds(ids[start:min(start+getRulesBatchSize, len(ids))])

		result, err := fwClient.GetRules(params)
		if err != nil {
			diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, apiScopesRead))
			return rulesByFamily, diags
		}

		if result == nil || result.Payload == nil {
			continue
		}
		for _, rule := range result.Payload.Resources {
			if rule != nil && rule.Family != nil {
				rulesByFamily[*rule.Family] = rule
			}
		}
	}

	return rulesByFamily, diags
}

// orderRulesByFamily orders rules to match the rule group's rule_ids order,
// which is the group's rule precedence. The rules API
// (GET /fwmgr/entities/rules/v1) returns rules in a nondeterministic order that
// ignores the requested id order, even across identical requests, so this
// canonicalization is what makes reads deterministic.
//
// A rule_ids entry with no rule is skipped, so a short result means the group
// references a rule the API did not return.
func orderRulesByFamily(
	rulesByFamily map[string]*models.FwmgrFirewallRuleV1,
	ruleIDs []string,
) []*models.FwmgrFirewallRuleV1 {
	ordered := make([]*models.FwmgrFirewallRuleV1, 0, len(ruleIDs))
	for _, ruleID := range ruleIDs {
		if rule, found := rulesByFamily[ruleID]; found && rule != nil {
			ordered = append(ordered, rule)
		}
	}

	return ordered
}

// wrapRules converts API rules to Terraform list type. The API's values are
// authoritative: every attribute round-trips from the response alone, so no
// plan or state is consulted here.
func wrapRules(
	ctx context.Context,
	apiRules []*models.FwmgrFirewallRuleV1,
) (types.List, diag.Diagnostics) {
	var diags diag.Diagnostics

	if len(apiRules) == 0 {
		return types.ListNull(types.ObjectType{AttrTypes: firewallRuleModel{}.attrTypes()}), diags
	}

	rules := buildRuleModels(ctx, apiRules, &diags)

	rulesList, d := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: firewallRuleModel{}.attrTypes()}, rules)
	diags.Append(d...)

	return rulesList, diags
}

// buildRuleModels maps API rules to rule models. It is the one read mapper: the
// data source wraps the result in its own object type rather than converting a
// list built here back into models.
func buildRuleModels(
	ctx context.Context,
	apiRules []*models.FwmgrFirewallRuleV1,
	diags *diag.Diagnostics,
) []firewallRuleModel {
	rules := make([]firewallRuleModel, 0, len(apiRules))
	for _, apiRule := range apiRules {
		if apiRule == nil {
			continue
		}
		rule := firewallRuleModel{
			// Family, not ID: rule_ids references families, and ID is a
			// per-version handle that resolves to a superseded snapshot.
			ID:          flex.StringPointerToFramework(apiRule.Family),
			Name:        flex.StringPointerToFramework(apiRule.Name),
			Description: flex.StringPointerToFramework(apiRule.Description),
			Enabled:     types.BoolPointerValue(apiRule.Enabled),
			Action:      types.StringPointerValue(apiRule.Action),
			Direction:   types.StringPointerValue(apiRule.Direction),
		}

		if apiRule.AddressFamily != nil {
			rule.AddressFamily = types.StringValue(addressFamilyFromAPI(*apiRule.AddressFamily))
		}

		if apiRule.Protocol != nil {
			rule.Protocol = types.StringValue(reverseProtocolMapping(*apiRule.Protocol))
		}

		// An FQDN that exists but is disabled server-side is not in effect, so
		// it is reported as unset and shows up as drift.
		if apiRule.Fqdn != nil && *apiRule.Fqdn != "" && swag.BoolValue(apiRule.FqdnEnabled) {
			rule.Fqdn = types.StringPointerValue(apiRule.Fqdn)
		}

		family := swag.StringValue(apiRule.Family)
		rule.LocalAddress = wrapFirewallAddressRanges(ctx, apiRule.LocalAddress, family, "local_address", diags)
		rule.RemoteAddress = wrapFirewallAddressRanges(ctx, apiRule.RemoteAddress, family, "remote_address", diags)

		rule.LocalPort = wrapFirewallPortRanges(ctx, apiRule.LocalPort, family, "local_port", diags)
		rule.RemotePort = wrapFirewallPortRanges(ctx, apiRule.RemotePort, family, "remote_port", diags)

		rule.NetworkLocation = types.StringValue("ANY")
		rule.ExecutablePath = types.StringNull()
		rule.ServiceName = types.StringNull()

		if apiRule.Fields != nil {
			for _, field := range apiRule.Fields {
				if field.Name == nil {
					continue
				}
				switch *field.Name {
				case "network_location":
					if len(field.Values) > 0 && field.Values[0] != "ANY" {
						rule.NetworkLocation = types.StringValue(field.Values[0])
					}
				case "image_name":
					if field.Value != nil && *field.Value != "" {
						rule.ExecutablePath = types.StringPointerValue(field.Value)
					}
				case "service_name":
					if field.Value != nil && *field.Value != "" {
						rule.ServiceName = types.StringPointerValue(field.Value)
					}
				}
			}
		}

		// An ICMP rule always carries a type and a code: the API stores the wildcard
		// for either one submitted empty, and synthesizes both for a rule that sends
		// no icmp object at all. A rule on any other protocol carries no ICMP data,
		// and the API reports it as null. The schema plans exactly this split, so
		// reproducing it here is what makes the two agree.
		if isICMPProtocol(rule.Protocol) {
			rule.IcmpType, rule.IcmpCode = icmpValuesFromAPI(apiRule.Icmp)
		}

		// The API does not return a dedicated watch_mode flag. Instead, the
		// presence of the Monitor object on the rule indicates watch mode is
		// enabled (set when WatchMode is true in buildRulesPayload).
		rule.WatchMode = types.BoolValue(apiRule.Monitor != nil)

		rules = append(rules, rule)
	}

	return rules
}

// protocolNames is protocolMapping inverted, so the read path costs a lookup
// rather than a scan. Every number in protocolMapping is unique, which
// TestProtocolMappingRoundTrip enforces.
var protocolNames = func() map[string]string {
	names := make(map[string]string, len(protocolMapping))
	for name, number := range protocolMapping {
		names[number] = name
	}
	return names
}()

// reverseProtocolMapping converts IANA numbers to protocol names.
func reverseProtocolMapping(protocol string) string {
	if name, found := protocolNames[protocol]; found {
		return name
	}
	return "ANY"
}

// wrapFirewallAddressRanges converts API address ranges to a Terraform list.
//
// A single wildcard entry is the API's "any address", and it is what the API reports
// for every rule that does not restrict addresses, whatever the rule's address family.
// That is also what the schema defaults an omitted list to, so it is stored as itself
// rather than collapsed: the two spellings the practitioner can write, omitting the
// list and writing the wildcard out, both arrive here as the same one value.
//
// It is normalized rather than passed through so that the netmask on a wildcard entry
// is always 0, which is what the default plans. The API omits the netmask for the
// wildcard today; pinning it means a response that started reporting one could not
// desync state from the plan.
//
// State's element indices are the API's element indices, which is what lets an
// update patch a single address in place. A malformed entry is therefore an
// error rather than something to skip: a short list would make every later index
// name a different address.
func wrapFirewallAddressRanges(
	ctx context.Context,
	apiAddresses []*models.FwmgrFirewallAddressRange,
	family string,
	attribute string,
	diags *diag.Diagnostics,
) types.List {
	// The API does not report an empty address list: removing the last entry leaves
	// the wildcard behind. Reporting the wildcard for one anyway keeps this total, so
	// there is no response the plan's default cannot match.
	if len(apiAddresses) == 0 {
		return wildcardAddressList()
	}

	if len(apiAddresses) == 1 && apiAddresses[0] != nil &&
		swag.StringValue(apiAddresses[0].Address) == apiWildcard {
		return wildcardAddressList()
	}

	addresses := make([]addressRangeModel, 0, len(apiAddresses))
	for i, addr := range apiAddresses {
		if addr == nil || addr.Address == nil {
			diags.AddError(
				"Unexpected firewall rule response",
				fmt.Sprintf(
					"Rule '%s' %s entry %d has no address. Retry, and please report this issue to the provider developers if it persists.",
					family, attribute, i,
				),
			)
			return types.ListNull(types.ObjectType{AttrTypes: addressRangeAttrTypes()})
		}
		addresses = append(addresses, addressRangeModel{
			Address: types.StringPointerValue(addr.Address),
			Netmask: types.Int64Value(addr.Netmask),
		})
	}

	list, d := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: addressRangeAttrTypes()}, addresses)
	diags.Append(d...)
	return list
}

// wrapFirewallPortRanges converts API port ranges to a Terraform list. The
// API's end value is stored verbatim; it reports 0 for a single port, which is
// what the schema means by 0. A malformed entry is an error, for the reason
// wrapFirewallAddressRanges gives.
func wrapFirewallPortRanges(
	ctx context.Context,
	apiPorts []*models.FwmgrFirewallPortRange,
	family string,
	attribute string,
	diags *diag.Diagnostics,
) types.List {
	if len(apiPorts) == 0 {
		return types.ListNull(types.ObjectType{AttrTypes: portRangeAttrTypes()})
	}

	ports := make([]portRangeModel, 0, len(apiPorts))
	for i, port := range apiPorts {
		if port == nil || port.Start == nil {
			diags.AddError(
				"Unexpected firewall rule response",
				fmt.Sprintf(
					"Rule '%s' %s entry %d has no start port. Retry, and please report this issue to the provider developers if it persists.",
					family, attribute, i,
				),
			)
			return types.ListNull(types.ObjectType{AttrTypes: portRangeAttrTypes()})
		}
		ports = append(ports, portRangeModel{
			Start: types.Int64PointerValue(port.Start),
			End:   types.Int64Value(swag.Int64Value(port.End)),
		})
	}

	list, d := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: portRangeAttrTypes()}, ports)
	diags.Append(d...)
	return list
}

// buildRulesPayload converts Terraform rule models to API create request format.
func buildRulesPayload(
	ctx context.Context,
	rulesList types.List,
	platform string,
) ([]*models.FwmgrAPIRuleCreateRequestV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	if !utils.IsKnown(rulesList) {
		return []*models.FwmgrAPIRuleCreateRequestV1{}, diags
	}

	var rules []firewallRuleModel
	diags.Append(rulesList.ElementsAs(ctx, &rules, false)...)
	if diags.HasError() {
		return nil, diags
	}

	apiRules := make([]*models.FwmgrAPIRuleCreateRequestV1, 0, len(rules))
	for i, rule := range rules {
		apiRules = append(apiRules, buildRuleCreateRequest(
			ctx, rule, platform, fmt.Sprintf("temp_id:%d", i), &diags,
		))
	}

	return apiRules, diags
}

// buildRuleCreateRequest builds the API representation of one rule. It is the
// single description of a new rule on the wire: the create endpoint takes a list
// of these, and an "add /rules/-" patch operation carries one (see
// buildRuleAddValue), so a newly added schema attribute cannot reach one path and
// miss the other.
func buildRuleCreateRequest(
	ctx context.Context,
	rule firewallRuleModel,
	platform string,
	tempID string,
	diags *diag.Diagnostics,
) *models.FwmgrAPIRuleCreateRequestV1 {
	fqdnValue := rule.Fqdn.ValueString()

	apiRule := &models.FwmgrAPIRuleCreateRequestV1{
		TempID:        swag.String(tempID),
		Name:          swag.String(rule.Name.ValueString()),
		Description:   flex.FrameworkToStringPointer(rule.Description),
		Enabled:       swag.Bool(rule.Enabled.ValueBool()),
		Action:        swag.String(rule.Action.ValueString()),
		Direction:     swag.String(rule.Direction.ValueString()),
		Protocol:      swag.String(protocolToAPI(rule.Protocol)),
		AddressFamily: swag.String(addressFamilyToAPI(rule.AddressFamily.ValueString())),
		Fqdn:          swag.String(fqdnValue),
		FqdnEnabled:   swag.Bool(fqdnValue != ""),
		// The API marks "log" as required but never returns it on read and the
		// console exposes no control for it, so it is not part of the schema.
		// Send a constant false to satisfy the required field.
		Log:    swag.Bool(false),
		Fields: buildFieldsPayload(rule, platform),
	}

	apiRule.LocalAddress = buildAddressPayload(ctx, rule.LocalAddress, diags)
	apiRule.RemoteAddress = buildAddressPayload(ctx, rule.RemoteAddress, diags)
	apiRule.LocalPort = buildPortPayload(ctx, rule.LocalPort, diags)
	apiRule.RemotePort = buildPortPayload(ctx, rule.RemotePort, diags)

	if isICMPProtocol(rule.Protocol) {
		apiRule.Icmp = &models.FwmgrDomainICMP{
			IcmpType: swag.String(icmpValueToAPI(rule.IcmpType)),
			IcmpCode: swag.String(icmpValueToAPI(rule.IcmpCode)),
		}
	}

	if rule.WatchMode.ValueBool() {
		apiRule.Monitor = &models.FwmgrDomainMonitoring{
			Count:    swag.String("1"),
			PeriodMs: swag.String("3600000"),
		}
	}

	return apiRule
}

// ruleField is one entry of a rule's fields array. It exists because the two
// wire encodings the provider needs are not interchangeable:
// FwmgrAPIWorkaroundUIFieldValue tags Value omitempty, so an empty value
// disappears from the request, while a "replace /rules/N/fields" operation must
// carry an explicit empty value to clear an entry. Both renderers below work
// from this one description so the two encodings cannot drift apart.
type ruleField struct {
	name string
	typ  string
	// values is set for the "set" typed entries, value for the rest.
	value  string
	values []string
}

// ruleFields describes a rule's complete fields array. Every applicable entry is
// always present, with an empty value when the attribute is unset: the API
// merges fields by name, so an omitted entry preserves whatever the rule already
// held rather than clearing it.
func ruleFields(rule firewallRuleModel, platform string) []ruleField {
	networkLocation := rule.NetworkLocation.ValueString()
	if networkLocation == "" {
		networkLocation = "ANY"
	}

	pathType := "windows_path"
	if platform == "Mac" || platform == "Linux" {
		pathType = "unix_path"
	}

	fields := []ruleField{
		{name: "network_location", typ: "set", values: []string{networkLocation}},
		{name: "image_name", typ: pathType, value: rule.ExecutablePath.ValueString()},
	}

	if platform == "Windows" {
		fields = append(fields, ruleField{
			name:  "service_name",
			typ:   "string",
			value: rule.ServiceName.ValueString(),
		})
	}

	return fields
}

// buildFieldsPayload renders a rule's fields for the create request.
func buildFieldsPayload(
	rule firewallRuleModel,
	platform string,
) []*models.FwmgrAPIWorkaroundUIFieldValue {
	fields := ruleFields(rule, platform)
	payload := make([]*models.FwmgrAPIWorkaroundUIFieldValue, 0, len(fields))
	for _, field := range fields {
		payload = append(payload, &models.FwmgrAPIWorkaroundUIFieldValue{
			Name:   swag.String(field.name),
			Type:   field.typ,
			Value:  field.value,
			Values: field.values,
		})
	}
	return payload
}

// buildFieldsForDiff renders a rule's fields for a JSON Patch value. Unlike
// buildFieldsPayload it always writes the value key, which is what clears
// executable_path or service_name through a "replace /rules/N/fields".
func buildFieldsForDiff(
	rule firewallRuleModel,
	platform string,
) []map[string]interface{} {
	fields := ruleFields(rule, platform)
	payload := make([]map[string]interface{}, 0, len(fields))
	for _, field := range fields {
		entry := map[string]interface{}{"name": field.name, "type": field.typ}
		if field.values != nil {
			entry["values"] = field.values
		} else {
			entry["value"] = field.value
		}
		payload = append(payload, entry)
	}
	return payload
}

// buildAddressPayload converts Terraform address list to API format. An omitted
// list is sent empty; the API canonicalizes that to the wildcard address.
func buildAddressPayload(
	ctx context.Context,
	addressList types.List,
	diags *diag.Diagnostics,
) []*models.FwmgrDomainAddressRange {
	if !utils.IsKnown(addressList) || len(addressList.Elements()) == 0 {
		return []*models.FwmgrDomainAddressRange{}
	}

	var addresses []addressRangeModel
	diags.Append(addressList.ElementsAs(ctx, &addresses, false)...)
	if diags.HasError() {
		return nil
	}

	apiAddresses := make([]*models.FwmgrDomainAddressRange, 0, len(addresses))
	for _, addr := range addresses {
		apiAddresses = append(apiAddresses, &models.FwmgrDomainAddressRange{
			Address: swag.String(addr.Address.ValueString()),
			Netmask: addr.Netmask.ValueInt64(),
		})
	}

	return apiAddresses
}

// buildPortPayload converts Terraform port list to API format.
func buildPortPayload(
	ctx context.Context,
	portList types.List,
	diags *diag.Diagnostics,
) []*models.FwmgrDomainPortRange {
	if !utils.IsKnown(portList) || len(portList.Elements()) == 0 {
		return []*models.FwmgrDomainPortRange{}
	}

	var ports []portRangeModel
	diags.Append(portList.ElementsAs(ctx, &ports, false)...)
	if diags.HasError() {
		return nil
	}

	apiPorts := make([]*models.FwmgrDomainPortRange, 0, len(ports))
	for _, port := range ports {
		apiPorts = append(apiPorts, &models.FwmgrDomainPortRange{
			Start: swag.Int64(port.Start.ValueInt64()),
			End:   swag.Int64(port.End.ValueInt64()),
		})
	}

	return apiPorts
}

// jsonDiff builds a JSON Patch operation. A nil value marshals to
// "value": null, which is what a remove sends and what clearing icmp or monitor
// requires.
func jsonDiff(op, path string, value interface{}) *models.FwmgrAPIJSONDiff {
	return &models.FwmgrAPIJSONDiff{
		Op:    swag.String(op),
		Path:  swag.String(path),
		Value: value,
	}
}

// buildDiffOperations creates JSON Patch operations for updating rule group fields and rules.
func buildDiffOperations(
	ctx context.Context,
	plan firewallRuleGroupResourceModel,
	state firewallRuleGroupResourceModel,
	ruleGroup *models.FwmgrAPIRuleGroupV1,
) ([]*models.FwmgrAPIJSONDiff, []string, []int64, diag.Diagnostics) {
	var diags diag.Diagnostics

	diffOps := make([]*models.FwmgrAPIJSONDiff, 0)
	newRuleIDs := make([]string, 0)
	newRuleVersions := make([]int64, 0)

	// Check for rule group field changes
	if !plan.Name.Equal(state.Name) {
		diffOps = append(diffOps, jsonDiff("replace", "/name", plan.Name.ValueString()))
	}

	if !plan.Description.Equal(state.Description) {
		diffOps = append(diffOps, jsonDiff("replace", "/description", plan.Description.ValueString()))
	}

	if !plan.Enabled.Equal(state.Enabled) {
		diffOps = append(diffOps, jsonDiff("replace", "/enabled", plan.Enabled.ValueBool()))
	}

	// Get planned rules
	var planRules []firewallRuleModel
	if utils.IsKnown(plan.Rules) {
		diags.Append(plan.Rules.ElementsAs(ctx, &planRules, false)...)
		if diags.HasError() {
			return nil, nil, nil, diags
		}
	}

	// Get state rules
	var stateRules []firewallRuleModel
	if utils.IsKnown(state.Rules) {
		diags.Append(state.Rules.ElementsAs(ctx, &stateRules, false)...)
		if diags.HasError() {
			return nil, nil, nil, diags
		}
	}

	// Read stores rules in rule_ids order and sets each rule's id to its family,
	// so stateRules[j] is the rule that ruleGroup.RuleIds[j] refers to. Every
	// index below relies on that, so check it rather than assume it: a reorder
	// made outside Terraform after the last refresh leaves the lengths equal
	// while every index points at a different rule. This guard is also the only
	// thing standing behind an in-place edit, because the API positionally
	// cross-checks removes against rule_ids but not replaces.
	stateRuleIDs := make([]string, 0, len(stateRules))
	for _, rule := range stateRules {
		stateRuleIDs = append(stateRuleIDs, rule.ID.ValueString())
	}
	if !slices.Equal(stateRuleIDs, ruleGroup.RuleIds) {
		diags.AddError(
			"Firewall rule group state is out of sync",
			fmt.Sprintf(
				"State tracks rules %v but rule group '%s' has %v. Run 'terraform refresh' and try again...",
				stateRuleIDs, plan.ID.ValueString(), ruleGroup.RuleIds,
			),
		)
		return nil, nil, nil, diags
	}

	// match[i] is the index in stateRules that planRules[i] continues, or -1 if
	// it is a new rule. edited[i] marks a match that needs attribute operations.
	// used[j] marks a state rule as claimed.
	match := make([]int, len(planRules))
	edited := make([]bool, len(planRules))
	used := make([]bool, len(stateRules))

	// Same position and unchanged: the common case, and it keeps identical rules
	// paired with themselves rather than with an interchangeable twin.
	for i := range planRules {
		match[i] = -1
		if i < len(stateRules) && !ruleHasChanged(planRules[i], stateRules[i]) {
			match[i], used[i] = i, true
		}
	}

	// Unchanged but moved: an insert, a delete, or a reorder shifts rules to a
	// different index. Matching them by content lets them keep their identity
	// instead of being needlessly torn down and recreated.
	for i := range planRules {
		if match[i] != -1 {
			continue
		}
		for j := range stateRules {
			if !used[j] && !ruleHasChanged(planRules[i], stateRules[j]) {
				match[i], used[j] = j, true
				break
			}
		}
	}

	// Changed, but still the same rule: edit it in place so it keeps the Rule ID
	// the product documents as permanent, and with it the firewall event history
	// recorded against that id. Same position is tried first, so editing rule 2
	// of 5 pairs planRules[2] with stateRules[2]; a rule that was edited and
	// moved in the same apply falls to the second pass.
	for i := range planRules {
		if match[i] != -1 || i >= len(stateRules) || used[i] {
			continue
		}
		if ruleIsContinuation(planRules[i], stateRules[i]) {
			match[i], edited[i], used[i] = i, true, true
		}
	}
	for i := range planRules {
		if match[i] != -1 {
			continue
		}
		for j := range stateRules {
			if !used[j] && ruleIsContinuation(planRules[i], stateRules[j]) {
				match[i], edited[i], used[j] = j, true, true
				break
			}
		}
	}

	// rule_ids must be the complete final list in precedence order: the existing
	// family for a rule that survives, a temp_id placeholder for one the API has
	// to create. An edited rule keeps its family, which is what lets an edit, a
	// reorder, an add and a delete all compose in one request.
	//
	// rule_versions is only required to match rule_ids in length. Its values are
	// inert: real, stale and arbitrary versions are all accepted and applied, so
	// it is not optimistic-concurrency control and fetching real versions would
	// buy nothing. Concurrency protection is the rule_ids check above.
	type ruleToAdd struct {
		tempID string
		rule   firewallRuleModel
	}
	var rulesToAdd []ruleToAdd

	for i := range planRules {
		if j := match[i]; j != -1 {
			newRuleIDs = append(newRuleIDs, ruleGroup.RuleIds[j])
			newRuleVersions = append(newRuleVersions, 0)
			continue
		}
		tempID := fmt.Sprintf("temp_id:%d", len(rulesToAdd)+1)
		rulesToAdd = append(rulesToAdd, ruleToAdd{tempID: tempID, rule: planRules[i]})
		newRuleIDs = append(newRuleIDs, tempID)
		newRuleVersions = append(newRuleVersions, 0)
	}

	// In-place edits, addressed by each rule's current index. They come before
	// every rule-level add and remove, so no index has shifted when they run.
	for i := range planRules {
		if edited[i] {
			diffOps = append(diffOps, ruleEditOps(
				match[i], planRules[i], stateRules[match[i]], plan.Platform.ValueString(),
			)...)
		}
	}

	// Remove every state rule nothing claimed: rules dropped from the
	// configuration, and rules an unrelated rule replaced at the same position.
	// Descending, because a remove shifts the indices of everything after it.
	for j := len(stateRules) - 1; j >= 0; j-- {
		if !used[j] {
			diffOps = append(diffOps, jsonDiff("remove", fmt.Sprintf("/rules/%d", j), nil))
		}
	}

	// Adds append to the end of the rules array; their position in the group is
	// set by where their temp_id sits in rule_ids, not by op order. They are
	// emitted in ascending temp_id order to keep the payload readable.
	for _, add := range rulesToAdd {
		rulePayload := buildRulePayloadForDiff(ctx, add.rule, plan.Platform.ValueString(), add.tempID, &diags)
		diffOps = append(diffOps, jsonDiff("add", "/rules/-", rulePayload))
	}

	return diffOps, newRuleIDs, newRuleVersions, diags
}

// ruleListPaths names the four element-addressed rule lists. isAddress marks the
// two whose empty form the API materializes as a wildcard entry.
var ruleListPaths = []struct {
	attribute string
	isAddress bool
	get       func(firewallRuleModel) types.List
}{
	{"local_address", true, func(r firewallRuleModel) types.List { return r.LocalAddress }},
	{"remote_address", true, func(r firewallRuleModel) types.List { return r.RemoteAddress }},
	{"local_port", false, func(r firewallRuleModel) types.List { return r.LocalPort }},
	{"remote_port", false, func(r firewallRuleModel) types.List { return r.RemotePort }},
}

// apiListLen reports how many elements the API holds for a rule list. State normally
// mirrors the API: an address list is never empty server-side, and the read reports the
// wildcard entry the API keeps there, so the length is just state's own.
//
// State is not the authority on that length, though. An address list state records as
// null or empty still counts as one, because the API holds the wildcard entry for it
// regardless. Counting it as zero would skip the remove and leave the rebuilt list as the
// new address plus that wildcard, silently widening the rule to match any address. Port
// lists have no such placeholder, so state's length is the API's.
func apiListLen(list types.List, isAddress bool) int {
	length := 0
	if utils.IsKnown(list) {
		length = len(list.Elements())
	}
	if isAddress && length == 0 {
		return 1
	}
	return length
}

// ruleEditOps returns the operations that bring the rule the API holds at index
// up to the planned rule. Paths use the rule's current index, which is valid
// because buildDiffOperations emits these before any rule-level add or remove.
//
// The operation vocabulary avoids the endpoint's silent no-ops by construction:
// icmp, monitor and fields are replaced whole rather than by leaf, because a
// leaf replace inside them is accepted and does nothing; and lists are rebuilt
// element by element, because a replace on a whole list appends to it.
func ruleEditOps(
	index int,
	plan, state firewallRuleModel,
	platform string,
) []*models.FwmgrAPIJSONDiff {
	rulePath := fmt.Sprintf("/rules/%d", index)
	ops := make([]*models.FwmgrAPIJSONDiff, 0)

	// A changed list is torn down and rebuilt rather than minimally diffed. The
	// removes descend, so each index is still the last element when its operation
	// runs; the adds then ascend into an empty array, where adding at index i is
	// appending. Every remove precedes every add so that no intermediate array
	// state can pick up the wildcard entry the API materializes for an address
	// list, which would silently widen the rule to match any address.
	var listAdds []*models.FwmgrAPIJSONDiff
	for _, list := range ruleListPaths {
		planList, stateList := list.get(plan), list.get(state)
		if planList.Equal(stateList) {
			continue
		}

		listPath := rulePath + "/" + list.attribute
		for i := apiListLen(stateList, list.isAddress) - 1; i >= 0; i-- {
			ops = append(ops, jsonDiff("remove", fmt.Sprintf("%s/%d", listPath, i), nil))
		}

		var elements []map[string]interface{}
		if list.isAddress {
			elements = buildAddressListForDiff(planList)
		} else {
			elements = buildPortListForDiff(planList)
		}
		for i, element := range elements {
			listAdds = append(listAdds, jsonDiff("add", fmt.Sprintf("%s/%d", listPath, i), element))
		}
	}

	if !plan.Name.Equal(state.Name) {
		ops = append(ops, jsonDiff("replace", rulePath+"/name", plan.Name.ValueString()))
	}
	if !plan.Description.Equal(state.Description) {
		ops = append(ops, jsonDiff("replace", rulePath+"/description", plan.Description.ValueString()))
	}
	if !plan.Enabled.Equal(state.Enabled) {
		ops = append(ops, jsonDiff("replace", rulePath+"/enabled", plan.Enabled.ValueBool()))
	}
	if !plan.Action.Equal(state.Action) {
		ops = append(ops, jsonDiff("replace", rulePath+"/action", plan.Action.ValueString()))
	}
	if !plan.Direction.Equal(state.Direction) {
		ops = append(ops, jsonDiff("replace", rulePath+"/direction", plan.Direction.ValueString()))
	}
	if !plan.Protocol.Equal(state.Protocol) {
		ops = append(ops, jsonDiff("replace", rulePath+"/protocol", protocolToAPI(plan.Protocol)))
	}
	if !plan.AddressFamily.Equal(state.AddressFamily) {
		ops = append(ops, jsonDiff(
			"replace",
			rulePath+"/address_family",
			addressFamilyToAPI(plan.AddressFamily.ValueString()),
		))
	}

	// The API rejects an empty fqdn, so clearing one is expressed by disabling
	// it. A disabled FQDN is not in effect and the read reports it as unset, so
	// this round-trips; the stored string stays server-side, dormant.
	if !plan.Fqdn.Equal(state.Fqdn) {
		fqdn := plan.Fqdn.ValueString()
		ops = append(ops, jsonDiff("replace", rulePath+"/fqdn_enabled", fqdn != ""))
		if fqdn != "" {
			ops = append(ops, jsonDiff("replace", rulePath+"/fqdn", fqdn))
		}
	}

	// icmp follows protocol as well as its own two attributes: a rule that
	// leaves ICMP has to clear it, and one that becomes ICMP has to gain it even
	// when neither icmp_type nor icmp_code changed.
	planIsICMP, stateIsICMP := isICMPProtocol(plan.Protocol), isICMPProtocol(state.Protocol)
	if !plan.IcmpType.Equal(state.IcmpType) || !plan.IcmpCode.Equal(state.IcmpCode) ||
		planIsICMP != stateIsICMP {
		var icmp interface{}
		if planIsICMP {
			icmp = map[string]interface{}{
				"icmp_type": icmpValueToAPI(plan.IcmpType),
				"icmp_code": icmpValueToAPI(plan.IcmpCode),
			}
		}
		ops = append(ops, jsonDiff("replace", rulePath+"/icmp", icmp))
	}

	// The API has no watch_mode flag; the presence of monitor is it.
	if !plan.WatchMode.Equal(state.WatchMode) {
		var monitor interface{}
		if plan.WatchMode.ValueBool() {
			monitor = map[string]interface{}{"count": "1", "period_ms": "3600000"}
		}
		ops = append(ops, jsonDiff("replace", rulePath+"/monitor", monitor))
	}

	// fields carries three attributes and the API merges it by name, so the whole
	// array goes out whenever any of them changed.
	if !plan.NetworkLocation.Equal(state.NetworkLocation) ||
		!plan.ExecutablePath.Equal(state.ExecutablePath) ||
		!plan.ServiceName.Equal(state.ServiceName) {
		ops = append(ops, jsonDiff("replace", rulePath+"/fields", buildFieldsForDiff(plan, platform)))
	}

	return append(ops, listAdds...)
}

// isICMPProtocol reports whether a protocol value carries an ICMP type and code.
func isICMPProtocol(protocol types.String) bool {
	return protocol.ValueString() == "ICMPV4" || protocol.ValueString() == "ICMPV6"
}

// buildRuleAddValue is the value of an "add /rules/-" patch operation: the same
// rule description the create endpoint takes, with the fields array re-encoded.
//
// Only fields needs re-encoding. FwmgrAPIWorkaroundUIFieldValue tags Value
// omitempty, so an empty value vanishes from the request, and the API merges
// fields by name, meaning an absent value leaves whatever the rule already held
// rather than clearing it. Shadowing the embedded struct's fields with a type
// that always writes value is what makes an added rule and an edited rule agree
// on how "unset" is spelled. Nothing else on FwmgrAPIRuleCreateRequestV1 is
// omitempty, so every other attribute goes out exactly as Create sends it.
type buildRuleAddValue struct {
	*models.FwmgrAPIRuleCreateRequestV1
	Fields []map[string]interface{} `json:"fields"`
}

// buildRulePayloadForDiff builds the value of an "add /rules/-" operation.
func buildRulePayloadForDiff(
	ctx context.Context,
	rule firewallRuleModel,
	platform string,
	tempID string,
	diags *diag.Diagnostics,
) buildRuleAddValue {
	return buildRuleAddValue{
		FwmgrAPIRuleCreateRequestV1: buildRuleCreateRequest(ctx, rule, platform, tempID, diags),
		Fields:                      buildFieldsForDiff(rule, platform),
	}
}

// buildAddressListForDiff converts address ranges to a list for JSON Patch.
func buildAddressListForDiff(addressList types.List) []map[string]interface{} {
	if !utils.IsKnown(addressList) {
		return nil
	}

	result := make([]map[string]interface{}, 0)
	for _, elem := range addressList.Elements() {
		obj, ok := elem.(types.Object)
		if !ok {
			continue
		}
		attrs := obj.Attributes()
		addrAttr, addrOk := attrs["address"].(types.String)
		netmaskAttr, netmaskOk := attrs["netmask"].(types.Int64)
		if addrOk && netmaskOk {
			result = append(result, map[string]interface{}{
				"address": addrAttr.ValueString(),
				"netmask": netmaskAttr.ValueInt64(),
			})
		}
	}
	return result
}

// buildPortListForDiff converts port ranges to a list for JSON Patch.
func buildPortListForDiff(portList types.List) []map[string]interface{} {
	if !utils.IsKnown(portList) {
		return nil
	}

	result := make([]map[string]interface{}, 0)
	for _, elem := range portList.Elements() {
		obj, ok := elem.(types.Object)
		if !ok {
			continue
		}
		attrs := obj.Attributes()
		startAttr, startOk := attrs["start"].(types.Int64)
		endAttr, endOk := attrs["end"].(types.Int64)
		if startOk && endOk {
			result = append(result, map[string]interface{}{
				"start": startAttr.ValueInt64(),
				"end":   endAttr.ValueInt64(),
			})
		}
	}
	return result
}

// ruleHasChanged reports whether two rules differ in any user-configurable
// attribute. It decides that a plan rule and a state rule are the same rule
// unchanged, whether at the same index or moved. Comparing full content rather
// than name is what makes duplicate rule names safe, since two fully identical
// rules are interchangeable.
//
// Two constraints on what may be compared here. Every attribute a user can set
// must be, or a change to it is silently dropped. And every attribute compared
// must have a known value in the plan, which is why id is excluded: a computed
// attribute inside a list element is unknown whenever the plan differs from
// state, so comparing it would report every rule as changed. Optional and
// computed attributes are given defaults for the same reason.
func ruleHasChanged(plan, state firewallRuleModel) bool {
	return !plan.Name.Equal(state.Name) || ruleHasChangedIgnoringName(plan, state)
}

// ruleHasChangedIgnoringName is ruleHasChanged without the name, which is what
// tells a renamed rule apart from a different rule at the same position.
func ruleHasChangedIgnoringName(plan, state firewallRuleModel) bool {
	if !plan.Description.Equal(state.Description) {
		return true
	}
	if !plan.Enabled.Equal(state.Enabled) {
		return true
	}
	if !plan.Action.Equal(state.Action) {
		return true
	}
	if !plan.Direction.Equal(state.Direction) {
		return true
	}
	if !plan.Protocol.Equal(state.Protocol) {
		return true
	}
	if !plan.AddressFamily.Equal(state.AddressFamily) {
		return true
	}
	if !plan.NetworkLocation.Equal(state.NetworkLocation) {
		return true
	}
	if !plan.ExecutablePath.Equal(state.ExecutablePath) {
		return true
	}
	if !plan.ServiceName.Equal(state.ServiceName) {
		return true
	}
	if !plan.Fqdn.Equal(state.Fqdn) {
		return true
	}
	if !plan.IcmpType.Equal(state.IcmpType) {
		return true
	}
	if !plan.IcmpCode.Equal(state.IcmpCode) {
		return true
	}
	if !plan.WatchMode.Equal(state.WatchMode) {
		return true
	}
	if !plan.LocalAddress.Equal(state.LocalAddress) {
		return true
	}
	if !plan.RemoteAddress.Equal(state.RemoteAddress) {
		return true
	}
	if !plan.LocalPort.Equal(state.LocalPort) {
		return true
	}
	if !plan.RemotePort.Equal(state.RemotePort) {
		return true
	}
	return false
}

// ruleIsContinuation reports whether a planned rule is the state rule edited,
// rather than an unrelated rule that happens to sit at the same position. Two
// rules are the same rule when they agree on the name the console shows, or when
// they agree on everything but the name.
//
// A predicate is needed because position alone over-attributes. Replacing one
// rule in the configuration with an unrelated one would hand the new rule the old
// rule's Rule ID, fusing two rules' firewall event histories under one
// identifier, and no assertion on Terraform state can see it happen. The cost is
// that renaming a rule and changing its settings in the same apply recreates it.
func ruleIsContinuation(plan, state firewallRuleModel) bool {
	return plan.Name.Equal(state.Name) || !ruleHasChangedIgnoringName(plan, state)
}
