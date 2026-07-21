package firewall

import (
	"context"
	"fmt"
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

	return result.Payload.Resources[0], false, diags
}

// readRuleGroupState refreshes the state from the API.
// If planRules is provided, rules are ordered to match the plan.
// The returned boolean indicates the rule group no longer exists.
func (r *firewallRuleGroupResource) readRuleGroupState(
	ctx context.Context,
	state *firewallRuleGroupResourceModel,
	planRules types.List,
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

	if len(ruleGroup.RuleIds) > 0 {
		rulesParams := firewall_management.NewGetRulesParams().
			WithContext(ctx).
			WithIds(ruleGroup.RuleIds)

		rulesResult, err := r.client.FirewallManagement.GetRules(rulesParams)
		if err != nil {
			diags.Append(tferrors.NewDiagnosticFromAPIError(
				tferrors.Read,
				err,
				apiScopesRead,
			))
			return false, diags
		}

		if rulesResult != nil && rulesResult.Payload != nil && len(rulesResult.Payload.Resources) > 0 {
			// The API returns rules in a nondeterministic order, so first
			// canonicalize to the rule group's rule_ids order (the group's
			// precedence order), then order to match the plan order by name.
			// The canonical order is what makes reads deterministic when no
			// plan is available (e.g. terraform import).
			canonicalRules := orderRulesByRuleIDs(rulesResult.Payload.Resources, ruleGroup.RuleIds)
			orderedRules, d := orderRulesByPlanNames(ctx, canonicalRules, planRules)
			diags.Append(d...)
			if diags.HasError() {
				return false, diags
			}

			rulesList, d := wrapRules(ctx, orderedRules, planRules)
			diags.Append(d...)
			if diags.HasError() {
				return false, diags
			}
			state.Rules = rulesList
		}
	} else {
		state.Rules = types.ListNull(types.ObjectType{AttrTypes: firewallRuleModel{}.attrTypes()})
	}

	return false, diags
}

// orderRulesByRuleIDs orders API rules to match the rule group's rule_ids
// order, which is the group's canonical rule precedence. The rules API
// (GET /fwmgr/entities/rules/v1) returns rules in a nondeterministic order,
// even across identical requests, so without this canonicalization any read
// that has no plan to order against (e.g. terraform import) stores rules in
// a random order and the subsequent plan shows spurious rule reordering.
//
// A rule group's rule_ids entries reference the rules' family identifiers
// (the stable identifier across rule updates), so rules are matched by
// Family first and fall back to ID. Rules that match nothing in rule_ids
// (which should not happen) are appended in response order.
func orderRulesByRuleIDs(
	apiRules []*models.FwmgrFirewallRuleV1,
	ruleIDs []string,
) []*models.FwmgrFirewallRuleV1 {
	if len(apiRules) == 0 || len(ruleIDs) == 0 {
		return apiRules
	}

	rulesByFamily := make(map[string]*models.FwmgrFirewallRuleV1, len(apiRules))
	rulesByID := make(map[string]*models.FwmgrFirewallRuleV1, len(apiRules))
	for _, rule := range apiRules {
		if rule == nil {
			continue
		}
		if rule.Family != nil {
			rulesByFamily[*rule.Family] = rule
		}
		if rule.ID != nil {
			rulesByID[*rule.ID] = rule
		}
	}

	ordered := make([]*models.FwmgrFirewallRuleV1, 0, len(apiRules))
	seen := make(map[*models.FwmgrFirewallRuleV1]bool, len(apiRules))
	for _, ruleID := range ruleIDs {
		rule, found := rulesByFamily[ruleID]
		if !found {
			rule, found = rulesByID[ruleID]
		}
		if found && !seen[rule] {
			ordered = append(ordered, rule)
			seen[rule] = true
		}
	}

	// Append any rules not referenced by rule_ids in response order.
	for _, rule := range apiRules {
		if rule != nil && !seen[rule] {
			ordered = append(ordered, rule)
		}
	}

	return ordered
}

// orderRulesByPlanNames orders API rules to match plan order.
func orderRulesByPlanNames(
	ctx context.Context,
	apiRules []*models.FwmgrFirewallRuleV1,
	planRules types.List,
) ([]*models.FwmgrFirewallRuleV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	if len(apiRules) == 0 {
		return apiRules, diags
	}

	// If no plan rules provided, return as-is
	if !utils.IsKnown(planRules) {
		return apiRules, diags
	}

	// Build a map of rule name to API rule
	rulesByName := make(map[string]*models.FwmgrFirewallRuleV1)
	for _, rule := range apiRules {
		if rule != nil && rule.Name != nil {
			rulesByName[*rule.Name] = rule
		}
	}

	// Get plan rule names in order
	var planRuleModels []firewallRuleModel
	diags.Append(planRules.ElementsAs(ctx, &planRuleModels, false)...)
	if diags.HasError() {
		return apiRules, diags
	}

	// Build ordered slice matching plan order
	ordered := make([]*models.FwmgrFirewallRuleV1, 0, len(planRuleModels))
	for _, planRule := range planRuleModels {
		name := planRule.Name.ValueString()
		if rule, found := rulesByName[name]; found {
			ordered = append(ordered, rule)
			delete(rulesByName, name) // Remove to avoid duplicates
		}
	}

	// Append any remaining rules not in plan (shouldn't happen normally)
	for _, rule := range apiRules {
		if rule != nil && rule.Name != nil {
			if _, stillExists := rulesByName[*rule.Name]; stillExists {
				ordered = append(ordered, rule)
			}
		}
	}

	return ordered, diags
}

// wrapRules converts API rules to Terraform list type.
// planRules is used to preserve values the API doesn't return (e.g. port end values).
func wrapRules(
	ctx context.Context,
	apiRules []*models.FwmgrFirewallRuleV1,
	planRules types.List,
) (types.List, diag.Diagnostics) {
	var diags diag.Diagnostics

	if len(apiRules) == 0 {
		return types.ListNull(types.ObjectType{AttrTypes: firewallRuleModel{}.attrTypes()}), diags
	}

	// Build a map of plan rules by name to preserve values the API doesn't return
	planRulesByName := make(map[string]firewallRuleModel)
	if utils.IsKnown(planRules) {
		var planRuleModels []firewallRuleModel
		diags.Append(planRules.ElementsAs(ctx, &planRuleModels, false)...)
		if !diags.HasError() {
			for _, pr := range planRuleModels {
				planRulesByName[pr.Name.ValueString()] = pr
			}
		}
	}

	rules := make([]firewallRuleModel, 0, len(apiRules))
	for _, apiRule := range apiRules {
		if apiRule == nil {
			continue
		}
		rule := firewallRuleModel{
			ID:          flex.StringPointerToFramework(apiRule.ID),
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

		if apiRule.Fqdn != nil && *apiRule.Fqdn != "" {
			rule.Fqdn = types.StringPointerValue(apiRule.Fqdn)
		}

		// Get plan rule for preserving values the API rewrites (address "*"
		// sentinel and single-port end values).
		var planRule *firewallRuleModel
		if apiRule.Name != nil {
			if pr, ok := planRulesByName[*apiRule.Name]; ok {
				planRule = &pr
			}
		}

		var planLocalAddress, planRemoteAddress types.List
		if planRule != nil {
			planLocalAddress = planRule.LocalAddress
			planRemoteAddress = planRule.RemoteAddress
		}
		rule.LocalAddress = wrapFirewallAddressRanges(ctx, apiRule.LocalAddress, planLocalAddress, &diags)
		rule.RemoteAddress = wrapFirewallAddressRanges(ctx, apiRule.RemoteAddress, planRemoteAddress, &diags)

		rule.LocalPort = wrapFirewallPortRanges(ctx, apiRule.LocalPort, planRule, true, &diags)
		rule.RemotePort = wrapFirewallPortRanges(ctx, apiRule.RemotePort, planRule, false, &diags)

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

		if apiRule.Icmp != nil {
			if apiRule.Icmp.IcmpType != nil {
				rule.IcmpType = types.StringPointerValue(apiRule.Icmp.IcmpType)
			}
			if apiRule.Icmp.IcmpCode != nil {
				rule.IcmpCode = types.StringPointerValue(apiRule.Icmp.IcmpCode)
			}
		}

		// The API does not return a dedicated watch_mode flag. Instead, the
		// presence of the Monitor object on the rule indicates watch mode is
		// enabled (set when WatchMode is true in buildRulesPayload).
		rule.WatchMode = types.BoolValue(apiRule.Monitor != nil)

		rules = append(rules, rule)
	}

	rulesList, d := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: firewallRuleModel{}.attrTypes()}, rules)
	diags.Append(d...)

	return rulesList, diags
}

// reverseProtocolMapping converts IANA numbers to protocol names.
func reverseProtocolMapping(protocol string) string {
	for name, num := range protocolMapping {
		if num == protocol {
			return name
		}
	}
	return "ANY"
}

// wrapFirewallAddressRanges converts API address ranges to Terraform list.
// planAddresses is the configured list for this rule. When the user omits the
// address list, the provider sends a single "*" entry to mean "any" and the API
// echoes it back; in that case the API "*" sentinel is collapsed to null so the
// omitted-list config round-trips. When the user explicitly configures addresses
// (including "*"), the API values are written back verbatim.
func wrapFirewallAddressRanges(
	ctx context.Context,
	apiAddresses []*models.FwmgrFirewallAddressRange,
	planAddresses types.List,
	diags *diag.Diagnostics,
) types.List {
	if len(apiAddresses) == 0 {
		return types.ListNull(types.ObjectType{AttrTypes: addressRangeAttrTypes()})
	}

	// When the config omitted the address list, collapse the provider's synthetic
	// "*" (any) sentinel back to null so it round-trips.
	planOmitted := !utils.IsKnown(planAddresses) || len(planAddresses.Elements()) == 0

	addresses := make([]addressRangeModel, 0, len(apiAddresses))
	for _, addr := range apiAddresses {
		if addr.Address == nil {
			continue
		}
		if planOmitted && *addr.Address == "*" {
			continue
		}
		addresses = append(addresses, addressRangeModel{
			Address: types.StringPointerValue(addr.Address),
			Netmask: types.Int64Value(addr.Netmask),
		})
	}

	if len(addresses) == 0 {
		return types.ListNull(types.ObjectType{AttrTypes: addressRangeAttrTypes()})
	}

	list, d := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: addressRangeAttrTypes()}, addresses)
	diags.Append(d...)
	return list
}

// wrapFirewallPortRanges converts API port ranges to Terraform list.
// planRule is used to preserve port end values when API returns end=0 but plan has end=start.
// isLocalPort indicates whether this is for local_port (true) or remote_port (false).
func wrapFirewallPortRanges(
	ctx context.Context,
	apiPorts []*models.FwmgrFirewallPortRange,
	planRule *firewallRuleModel,
	isLocalPort bool,
	diags *diag.Diagnostics,
) types.List {
	if len(apiPorts) == 0 {
		return types.ListNull(types.ObjectType{AttrTypes: portRangeAttrTypes()})
	}

	// Get plan ports for comparison
	var planPorts []portRangeModel
	if planRule != nil {
		var portList types.List
		if isLocalPort {
			portList = planRule.LocalPort
		} else {
			portList = planRule.RemotePort
		}
		if utils.IsKnown(portList) {
			_ = portList.ElementsAs(ctx, &planPorts, false)
		}
	}

	ports := make([]portRangeModel, 0, len(apiPorts))
	for i, port := range apiPorts {
		if port.Start != nil {
			endVal := port.End
			// If API returns end=0 (single port) but plan has end=start, preserve plan value
			if endVal != nil && *endVal == 0 && i < len(planPorts) {
				planEnd := planPorts[i].End.ValueInt64()
				planStart := planPorts[i].Start.ValueInt64()
				// If plan had start==end (user specified single port as range), preserve that
				if planEnd == planStart {
					endVal = &planEnd
				}
			}
			ports = append(ports, portRangeModel{
				Start: types.Int64PointerValue(port.Start),
				End:   types.Int64PointerValue(endVal),
			})
		}
	}

	if len(ports) == 0 {
		return types.ListNull(types.ObjectType{AttrTypes: portRangeAttrTypes()})
	}

	list, d := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: portRangeAttrTypes()}, ports)
	diags.Append(d...)
	return list
}

// buildRulesPayload converts Terraform rule models to API create request format.
func (r *firewallRuleGroupResource) buildRulesPayload(
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
		tempID := fmt.Sprintf("temp_id:%d", i)

		protocol := protocolMapping[rule.Protocol.ValueString()]
		if protocol == "" {
			protocol = "*"
		}

		fqdnValue := rule.Fqdn.ValueString()
		fqdnEnabled := fqdnValue != ""

		apiRule := &models.FwmgrAPIRuleCreateRequestV1{
			TempID:        swag.String(tempID),
			Name:          swag.String(rule.Name.ValueString()),
			Description:   flex.FrameworkToStringPointer(rule.Description),
			Enabled:       swag.Bool(rule.Enabled.ValueBool()),
			Action:        swag.String(rule.Action.ValueString()),
			Direction:     swag.String(rule.Direction.ValueString()),
			Protocol:      swag.String(protocol),
			AddressFamily: swag.String(addressFamilyToAPI(rule.AddressFamily.ValueString())),
			Fqdn:          swag.String(fqdnValue),
			FqdnEnabled:   swag.Bool(fqdnEnabled),
			// The API marks "log" as required but never returns it on read and the
			// console exposes no control for it, so it is not part of the schema.
			// Send a constant false to satisfy the required field.
			Log:    swag.Bool(false),
			Fields: r.buildFieldsPayload(rule, platform),
		}

		apiRule.LocalAddress = r.buildAddressPayload(ctx, rule.LocalAddress, &diags)
		apiRule.RemoteAddress = r.buildAddressPayload(ctx, rule.RemoteAddress, &diags)
		apiRule.LocalPort = r.buildPortPayload(ctx, rule.LocalPort, &diags)
		apiRule.RemotePort = r.buildPortPayload(ctx, rule.RemotePort, &diags)

		protocol = rule.Protocol.ValueString()
		if protocol == "ICMPV4" || protocol == "ICMPV6" {
			icmpType := rule.IcmpType.ValueString()
			icmpCode := rule.IcmpCode.ValueString()
			if icmpType == "" {
				icmpType = "*"
			}
			if icmpCode == "" {
				icmpCode = "*"
			}
			apiRule.Icmp = &models.FwmgrDomainICMP{
				IcmpType: swag.String(icmpType),
				IcmpCode: swag.String(icmpCode),
			}
		}

		if rule.WatchMode.ValueBool() {
			apiRule.Monitor = &models.FwmgrDomainMonitoring{
				Count:    swag.String("1"),
				PeriodMs: swag.String("3600000"),
			}
		}

		apiRules = append(apiRules, apiRule)
	}

	return apiRules, diags
}

// buildFieldsPayload creates the fields array for the API request.
func (r *firewallRuleGroupResource) buildFieldsPayload(
	rule firewallRuleModel,
	platform string,
) []*models.FwmgrAPIWorkaroundUIFieldValue {
	fields := make([]*models.FwmgrAPIWorkaroundUIFieldValue, 0, 3)

	networkLocation := rule.NetworkLocation.ValueString()
	if networkLocation == "" {
		networkLocation = "ANY"
	}
	fields = append(fields, &models.FwmgrAPIWorkaroundUIFieldValue{
		Name:   swag.String("network_location"),
		Type:   "set",
		Values: []string{networkLocation},
	})

	execPath := rule.ExecutablePath.ValueString()
	pathType := "windows_path"
	if platform == "Mac" || platform == "Linux" {
		pathType = "unix_path"
	}
	fields = append(fields, &models.FwmgrAPIWorkaroundUIFieldValue{
		Name:  swag.String("image_name"),
		Type:  pathType,
		Value: execPath,
	})

	if platform == "Windows" {
		serviceName := rule.ServiceName.ValueString()
		fields = append(fields, &models.FwmgrAPIWorkaroundUIFieldValue{
			Name:  swag.String("service_name"),
			Type:  "string",
			Value: serviceName,
		})
	}

	return fields
}

// buildAddressPayload converts Terraform address list to API format.
func (r *firewallRuleGroupResource) buildAddressPayload(
	ctx context.Context,
	addressList types.List,
	diags *diag.Diagnostics,
) []*models.FwmgrDomainAddressRange {
	if !utils.IsKnown(addressList) || len(addressList.Elements()) == 0 {
		return []*models.FwmgrDomainAddressRange{
			{Address: swag.String("*"), Netmask: 0},
		}
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
func (r *firewallRuleGroupResource) buildPortPayload(
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
		startVal := port.Start.ValueInt64()
		endVal := port.End.ValueInt64()
		// If start == end, treat as single port by setting end to 0
		// The API rejects ranges where start == end as "duplicate ports"
		if startVal == endVal {
			endVal = 0
		}
		apiPorts = append(apiPorts, &models.FwmgrDomainPortRange{
			Start: swag.Int64(startVal),
			End:   swag.Int64(endVal),
		})
	}

	return apiPorts
}

// buildDiffOperations creates JSON Patch operations for updating rule group fields and rules.
func (r *firewallRuleGroupResource) buildDiffOperations(
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
		diffOps = append(diffOps, &models.FwmgrAPIJSONDiff{
			Op:    swag.String("replace"),
			Path:  swag.String("/name"),
			Value: plan.Name.ValueString(),
		})
	}

	if !plan.Description.Equal(state.Description) {
		diffOps = append(diffOps, &models.FwmgrAPIJSONDiff{
			Op:    swag.String("replace"),
			Path:  swag.String("/description"),
			Value: plan.Description.ValueString(),
		})
	}

	if !plan.Enabled.Equal(state.Enabled) {
		diffOps = append(diffOps, &models.FwmgrAPIJSONDiff{
			Op:    swag.String("replace"),
			Path:  swag.String("/enabled"),
			Value: plan.Enabled.ValueBool(),
		})
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

	// Build maps for state rules - by name to ID and by name to rule model
	stateRulesByName := make(map[string]string)
	stateRuleModelsByName := make(map[string]firewallRuleModel)
	for i, rule := range stateRules {
		if utils.IsKnown(rule.ID) && i < len(ruleGroup.RuleIds) {
			stateRulesByName[rule.Name.ValueString()] = ruleGroup.RuleIds[i]
			stateRuleModelsByName[rule.Name.ValueString()] = rule
		}
	}

	// Build a map of rule ID to index for replace operations
	ruleIDToIndex := make(map[string]int)
	for i, id := range ruleGroup.RuleIds {
		ruleIDToIndex[id] = i
	}

	// Track which existing rule IDs are still in use
	usedRuleIDs := make(map[string]bool)

	// Track rules that need to be added (new or modified)
	type ruleToAdd struct {
		tempID string
		rule   firewallRuleModel
	}
	var rulesToAdd []ruleToAdd

	// First pass: determine which rules need temp_ids and build the rule_ids array
	tempIDCounter := 1
	for _, planRule := range planRules {
		ruleName := planRule.Name.ValueString()
		if existingID, found := stateRulesByName[ruleName]; found {
			// Existing rule - check if it has changed
			stateRule := stateRuleModelsByName[ruleName]
			if r.ruleHasChanged(planRule, stateRule) {
				// Rule properties changed - needs remove+add with temp_id
				tempID := fmt.Sprintf("temp_id:%d", tempIDCounter)
				tempIDCounter++
				rulesToAdd = append(rulesToAdd, ruleToAdd{
					tempID: tempID,
					rule:   planRule,
				})
				newRuleIDs = append(newRuleIDs, tempID)
				newRuleVersions = append(newRuleVersions, 0)
			} else {
				// Rule unchanged - keep existing ID
				newRuleIDs = append(newRuleIDs, existingID)
				newRuleVersions = append(newRuleVersions, 0)
				usedRuleIDs[existingID] = true
			}
		} else {
			// New rule - add with temp_id
			tempID := fmt.Sprintf("temp_id:%d", tempIDCounter)
			tempIDCounter++
			rulesToAdd = append(rulesToAdd, ruleToAdd{
				tempID: tempID,
				rule:   planRule,
			})
			newRuleIDs = append(newRuleIDs, tempID)
			newRuleVersions = append(newRuleVersions, 0)
		}
	}

	// Handle removed rules - add "remove" operations for rules no longer in plan
	// Process in reverse order to maintain correct indices
	for i := len(ruleGroup.RuleIds) - 1; i >= 0; i-- {
		ruleID := ruleGroup.RuleIds[i]
		if !usedRuleIDs[ruleID] {
			diffOps = append(diffOps, &models.FwmgrAPIJSONDiff{
				Op:   swag.String("remove"),
				Path: swag.String(fmt.Sprintf("/rules/%d", i)),
			})
		}
	}

	// Add operations for new/modified rules in ascending temp_id order
	// This ensures temp_ids in diff_operations match the order in rule_ids
	for _, add := range rulesToAdd {
		rulePayload := r.buildRulePayloadForDiff(add.rule, plan.Platform.ValueString(), add.tempID)
		diffOps = append(diffOps, &models.FwmgrAPIJSONDiff{
			Op:    swag.String("add"),
			Path:  swag.String("/rules/-"),
			Value: rulePayload,
		})
	}

	return diffOps, newRuleIDs, newRuleVersions, diags
}

// buildRulePayloadForDiff creates a rule payload map for JSON Patch add operations.
func (r *firewallRuleGroupResource) buildRulePayloadForDiff(
	rule firewallRuleModel,
	_ string,
	tempID string,
) map[string]interface{} {
	// Map protocol name to IANA number
	protocol := rule.Protocol.ValueString()
	if protoNum, ok := protocolMapping[protocol]; ok {
		protocol = protoNum
	}

	payload := map[string]interface{}{
		"temp_id":        tempID,
		"name":           rule.Name.ValueString(),
		"description":    rule.Description.ValueString(),
		"enabled":        rule.Enabled.ValueBool(),
		"action":         rule.Action.ValueString(),
		"direction":      rule.Direction.ValueString(),
		"protocol":       protocol,
		"address_family": addressFamilyToAPI(rule.AddressFamily.ValueString()),
		// The API requires "log" but never returns it and the console has no
		// control for it, so it is not part of the schema. Send a constant false.
		"log": false,
	}

	// Add local_address if specified
	if utils.IsKnown(rule.LocalAddress) {
		payload["local_address"] = r.buildAddressListForDiff(rule.LocalAddress)
	}

	// Add remote_address if specified
	if utils.IsKnown(rule.RemoteAddress) {
		payload["remote_address"] = r.buildAddressListForDiff(rule.RemoteAddress)
	}

	// Add local_port if specified
	if utils.IsKnown(rule.LocalPort) {
		payload["local_port"] = r.buildPortListForDiff(rule.LocalPort)
	}

	// Add remote_port if specified
	if utils.IsKnown(rule.RemotePort) {
		payload["remote_port"] = r.buildPortListForDiff(rule.RemotePort)
	}

	// Add fields for network_location, image_name, service_name
	fields := make([]map[string]interface{}, 0)

	networkLocation := rule.NetworkLocation.ValueString()
	if networkLocation == "" {
		networkLocation = "ANY"
	}
	fields = append(fields, map[string]interface{}{
		"name":   "network_location",
		"type":   "set",
		"values": []string{networkLocation},
	})

	if !rule.ExecutablePath.IsNull() && rule.ExecutablePath.ValueString() != "" {
		fields = append(fields, map[string]interface{}{
			"name":  "image_name",
			"type":  "windows_path",
			"value": rule.ExecutablePath.ValueString(),
		})
	}

	if !rule.ServiceName.IsNull() && rule.ServiceName.ValueString() != "" {
		fields = append(fields, map[string]interface{}{
			"name":  "service_name",
			"type":  "string",
			"value": rule.ServiceName.ValueString(),
		})
	}

	payload["fields"] = fields

	// Add monitor mode if watch_mode is enabled
	if rule.WatchMode.ValueBool() {
		payload["monitor"] = map[string]interface{}{
			"count":     "1",
			"period_ms": "3600000",
		}
	}

	return payload
}

// buildAddressListForDiff converts address ranges to a list for JSON Patch.
func (r *firewallRuleGroupResource) buildAddressListForDiff(addressList types.List) []map[string]interface{} {
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
func (r *firewallRuleGroupResource) buildPortListForDiff(portList types.List) []map[string]interface{} {
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
			startVal := startAttr.ValueInt64()
			endVal := endAttr.ValueInt64()
			// If start == end, treat as single port by setting end to 0
			// The API rejects ranges where start == end as "duplicate ports"
			if startVal == endVal {
				endVal = 0
			}
			result = append(result, map[string]interface{}{
				"start": startVal,
				"end":   endVal,
			})
		}
	}
	return result
}

// ruleHasChanged checks if a rule's properties have changed between plan and state.
func (r *firewallRuleGroupResource) ruleHasChanged(plan, state firewallRuleModel) bool {
	// Compare key rule properties
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

// hasRuleOrderChanged checks if the order of rules has changed between plan and state.
// This is used to trigger an update even if no diff operations are needed,
// since rule order determines precedence.
func (r *firewallRuleGroupResource) hasRuleOrderChanged(
	plan firewallRuleGroupResourceModel,
	state firewallRuleGroupResourceModel,
) bool {
	// If either is null/unknown, can't compare
	if !utils.IsKnown(plan.Rules) || !utils.IsKnown(state.Rules) {
		return false
	}

	planElems := plan.Rules.Elements()
	stateElems := state.Rules.Elements()

	// Different number of rules means order changed (or rules added/removed)
	if len(planElems) != len(stateElems) {
		return true
	}

	// Compare rule names in order
	for i := range planElems {
		planObj, planOk := planElems[i].(types.Object)
		stateObj, stateOk := stateElems[i].(types.Object)
		if !planOk || !stateOk {
			continue
		}

		planAttrs := planObj.Attributes()
		stateAttrs := stateObj.Attributes()

		planName, planNameOk := planAttrs["name"].(types.String)
		stateName, stateNameOk := stateAttrs["name"].(types.String)

		if planNameOk && stateNameOk && planName.ValueString() != stateName.ValueString() {
			return true
		}
	}

	return false
}
