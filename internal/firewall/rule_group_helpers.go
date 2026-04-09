package firewall

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client/firewall_management"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/swag"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// getRuleGroup retrieves a rule group by ID.
func (r *firewallRuleGroupResource) getRuleGroup(
	ctx context.Context,
	id string,
) (*models.FwmgrAPIRuleGroupV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := firewall_management.NewGetRuleGroupsParams().
		WithContext(ctx).
		WithIds([]string{id})

	result, err := r.client.FirewallManagement.GetRuleGroups(params)
	if err != nil {
		diags.AddError(
			"Failed to read firewall rule group",
			fmt.Sprintf("Could not read firewall rule group '%s': %s", id, err.Error()),
		)
		return nil, diags
	}

	if result.Payload == nil || len(result.Payload.Resources) == 0 {
		diags.AddError(
			"Firewall rule group not found",
			fmt.Sprintf("Firewall rule group '%s' was not found.", id),
		)
		return nil, diags
	}

	return result.Payload.Resources[0], diags
}

// readRuleGroupState refreshes the state from the API.
// If planRules is provided, rules are ordered to match the plan.
func (r *firewallRuleGroupResource) readRuleGroupState(
	ctx context.Context,
	state *firewallRuleGroupResourceModel,
	planRules types.List,
) diag.Diagnostics {
	var diags diag.Diagnostics

	ruleGroup, d := r.getRuleGroup(ctx, state.ID.ValueString())
	diags.Append(d...)
	if diags.HasError() {
		return diags
	}

	state.Name = types.StringPointerValue(ruleGroup.Name)
	state.Description = types.StringPointerValue(ruleGroup.Description)
	// Preserve user's platform case (API returns lowercase, but user may have specified title case)
	if ruleGroup.Platform != nil {
		// Convert API response back to title case to match schema validation
		// Map lowercase API values to title case for consistency
		platformMap := map[string]string{
			"windows": "Windows",
			"mac":     "Mac",
			"linux":   "Linux",
		}
		platform := *ruleGroup.Platform
		if titleCase, ok := platformMap[strings.ToLower(platform)]; ok {
			platform = titleCase
		}
		state.Platform = types.StringValue(platform)
	}
	state.Enabled = types.BoolPointerValue(ruleGroup.Enabled)

	if len(ruleGroup.RuleIds) > 0 {
		rulesParams := firewall_management.NewGetRulesParams().
			WithContext(ctx).
			WithIds(ruleGroup.RuleIds)

		rulesResult, err := r.client.FirewallManagement.GetRules(rulesParams)
		if err != nil {
			diags.AddError(
				"Failed to read firewall rules",
				fmt.Sprintf("Could not read rules for rule group '%s': %s", state.ID.ValueString(), err.Error()),
			)
			return diags
		}

		if rulesResult.Payload != nil && len(rulesResult.Payload.Resources) > 0 {
			// Order rules to match the plan order by name
			// The API returns rules in reverse order from how we send them
			orderedRules := r.orderRulesByPlanNames(ctx, rulesResult.Payload.Resources, planRules)

			rulesList, d := r.wrapRules(ctx, orderedRules, planRules)
			diags.Append(d...)
			if diags.HasError() {
				return diags
			}
			state.Rules = rulesList
		}
	} else {
		state.Rules = types.ListNull(types.ObjectType{AttrTypes: firewallRuleModel{}.attrTypes()})
	}

	return diags
}

// orderRulesByPlanNames orders API rules to match plan order.
// The API returns rules in reverse order from submission.
func (r *firewallRuleGroupResource) orderRulesByPlanNames(
	ctx context.Context,
	apiRules []*models.FwmgrFirewallRuleV1,
	planRules types.List,
) []*models.FwmgrFirewallRuleV1 {
	if len(apiRules) == 0 {
		return apiRules
	}

	// If no plan rules provided, return as-is
	if planRules.IsNull() || planRules.IsUnknown() {
		return apiRules
	}

	// Build a map of rule name to API rule
	rulesByName := make(map[string]*models.FwmgrFirewallRuleV1)
	for _, rule := range apiRules {
		if rule.Name != nil {
			rulesByName[*rule.Name] = rule
		}
	}

	// Get plan rule names in order
	var planRuleModels []firewallRuleModel
	diags := planRules.ElementsAs(ctx, &planRuleModels, false)
	if diags.HasError() {
		return apiRules
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
		if rule.Name != nil {
			if _, stillExists := rulesByName[*rule.Name]; stillExists {
				ordered = append(ordered, rule)
			}
		}
	}

	return ordered
}

// wrapRules converts API rules to Terraform list type.
// planRules is used to preserve the log field value since the API doesn't return it.
func (r *firewallRuleGroupResource) wrapRules(
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
	if !planRules.IsNull() && !planRules.IsUnknown() {
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
		// Preserve log value from plan if available, otherwise default to false
		logValue := types.BoolValue(false)
		if apiRule.Name != nil {
			if planRule, ok := planRulesByName[*apiRule.Name]; ok && !planRule.Log.IsNull() && !planRule.Log.IsUnknown() {
				logValue = planRule.Log
			}
		}

		rule := firewallRuleModel{
			ID:            types.StringPointerValue(apiRule.ID),
			Name:          types.StringPointerValue(apiRule.Name),
			Description:   types.StringPointerValue(apiRule.Description),
			Enabled:       types.BoolPointerValue(apiRule.Enabled),
			Action:        types.StringPointerValue(apiRule.Action),
			Direction:     types.StringPointerValue(apiRule.Direction),
			AddressFamily: types.StringPointerValue(apiRule.AddressFamily),
			Log:           logValue,
		}

		if apiRule.Protocol != nil {
			rule.Protocol = types.StringValue(r.reverseProtocolMapping(*apiRule.Protocol))
		}

		if apiRule.Fqdn != nil && *apiRule.Fqdn != "" {
			rule.Fqdn = types.StringPointerValue(apiRule.Fqdn)
		}

		rule.LocalAddress = r.wrapFirewallAddressRanges(ctx, apiRule.LocalAddress, &diags)
		rule.RemoteAddress = r.wrapFirewallAddressRanges(ctx, apiRule.RemoteAddress, &diags)

		// Get plan rule for preserving port values
		var planRule *firewallRuleModel
		if apiRule.Name != nil {
			if pr, ok := planRulesByName[*apiRule.Name]; ok {
				planRule = &pr
			}
		}
		rule.LocalPort = r.wrapFirewallPortRanges(ctx, apiRule.LocalPort, planRule, true, &diags)
		rule.RemotePort = r.wrapFirewallPortRanges(ctx, apiRule.RemotePort, planRule, false, &diags)

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
			// API returns "*" for "any" which is the default - treat as null (not user-specified)
			if apiRule.Icmp.IcmpType != nil && *apiRule.Icmp.IcmpType != "*" {
				rule.IcmpType = types.StringPointerValue(apiRule.Icmp.IcmpType)
			}
			if apiRule.Icmp.IcmpCode != nil && *apiRule.Icmp.IcmpCode != "*" {
				rule.IcmpCode = types.StringPointerValue(apiRule.Icmp.IcmpCode)
			}
		}

		rule.WatchMode = types.BoolValue(apiRule.Monitor != nil)

		rules = append(rules, rule)
	}

	rulesList, d := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: firewallRuleModel{}.attrTypes()}, rules)
	diags.Append(d...)

	return rulesList, diags
}

// reverseProtocolMapping converts IANA numbers to protocol names.
func (r *firewallRuleGroupResource) reverseProtocolMapping(protocol string) string {
	for name, num := range protocolMapping {
		if num == protocol {
			return name
		}
	}
	return "ANY"
}

// wrapFirewallAddressRanges converts API address ranges to Terraform list.
func (r *firewallRuleGroupResource) wrapFirewallAddressRanges(
	ctx context.Context,
	apiAddresses []*models.FwmgrFirewallAddressRange,
	diags *diag.Diagnostics,
) types.List {
	if len(apiAddresses) == 0 {
		return types.ListNull(types.ObjectType{AttrTypes: addressRangeAttrTypes()})
	}

	addresses := make([]addressRangeModel, 0, len(apiAddresses))
	for _, addr := range apiAddresses {
		if addr.Address != nil && *addr.Address != "*" {
			addresses = append(addresses, addressRangeModel{
				Address: types.StringPointerValue(addr.Address),
				Netmask: types.Int64Value(addr.Netmask),
			})
		}
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
func (r *firewallRuleGroupResource) wrapFirewallPortRanges(
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
		if !portList.IsNull() && !portList.IsUnknown() {
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

	if rulesList.IsNull() || rulesList.IsUnknown() {
		return []*models.FwmgrAPIRuleCreateRequestV1{}, diags
	}

	var rules []firewallRuleModel
	diags.Append(rulesList.ElementsAs(ctx, &rules, false)...)
	if diags.HasError() {
		return nil, diags
	}

	apiRules := make([]*models.FwmgrAPIRuleCreateRequestV1, 0, len(rules))
	for i, rule := range rules {
		tempID := fmt.Sprintf("temp_%d", i)

		protocol := protocolMapping[rule.Protocol.ValueString()]
		if protocol == "" {
			protocol = "*"
		}

		fqdnValue := rule.Fqdn.ValueString()
		fqdnEnabled := fqdnValue != ""

		apiRule := &models.FwmgrAPIRuleCreateRequestV1{
			TempID:        swag.String(tempID),
			Name:          swag.String(rule.Name.ValueString()),
			Description:   swag.String(rule.Description.ValueString()),
			Enabled:       swag.Bool(rule.Enabled.ValueBool()),
			Action:        swag.String(rule.Action.ValueString()),
			Direction:     swag.String(rule.Direction.ValueString()),
			Protocol:      swag.String(protocol),
			AddressFamily: swag.String(rule.AddressFamily.ValueString()),
			Fqdn:          swag.String(fqdnValue),
			FqdnEnabled:   swag.Bool(fqdnEnabled),
			Log:           swag.Bool(rule.Log.ValueBool()),
			Fields:        r.buildFieldsPayload(rule, platform),
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
	if addressList.IsNull() || addressList.IsUnknown() || len(addressList.Elements()) == 0 {
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
	if portList.IsNull() || portList.IsUnknown() || len(portList.Elements()) == 0 {
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
	if !plan.Rules.IsNull() && !plan.Rules.IsUnknown() {
		diags.Append(plan.Rules.ElementsAs(ctx, &planRules, false)...)
		if diags.HasError() {
			return nil, nil, nil, diags
		}
	}

	// Get state rules
	var stateRules []firewallRuleModel
	if !state.Rules.IsNull() && !state.Rules.IsUnknown() {
		diags.Append(state.Rules.ElementsAs(ctx, &stateRules, false)...)
		if diags.HasError() {
			return nil, nil, nil, diags
		}
	}

	// Build maps for state rules - by name to ID and by name to rule model
	stateRulesByName := make(map[string]string)
	stateRuleModelsByName := make(map[string]firewallRuleModel)
	for i, rule := range stateRules {
		if !rule.ID.IsNull() && !rule.ID.IsUnknown() && i < len(ruleGroup.RuleIds) {
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
		"address_family": rule.AddressFamily.ValueString(),
		"log":            rule.Log.ValueBool(),
	}

	// Add local_address if specified
	if !rule.LocalAddress.IsNull() && !rule.LocalAddress.IsUnknown() {
		payload["local_address"] = r.buildAddressListForDiff(rule.LocalAddress)
	}

	// Add remote_address if specified
	if !rule.RemoteAddress.IsNull() && !rule.RemoteAddress.IsUnknown() {
		payload["remote_address"] = r.buildAddressListForDiff(rule.RemoteAddress)
	}

	// Add local_port if specified
	if !rule.LocalPort.IsNull() && !rule.LocalPort.IsUnknown() {
		payload["local_port"] = r.buildPortListForDiff(rule.LocalPort)
	}

	// Add remote_port if specified
	if !rule.RemotePort.IsNull() && !rule.RemotePort.IsUnknown() {
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
			"type":  "windows_service_name",
			"value": rule.ServiceName.ValueString(),
		})
	}

	payload["fields"] = fields

	// Add monitor mode if watch_mode is enabled
	if rule.WatchMode.ValueBool() {
		payload["monitor"] = map[string]interface{}{
			"count":          "1",
			"period_ms":      "60000",
			"count_operator": ">=",
		}
	}

	return payload
}

// buildAddressListForDiff converts address ranges to a list for JSON Patch.
func (r *firewallRuleGroupResource) buildAddressListForDiff(addressList types.List) []map[string]interface{} {
	if addressList.IsNull() || addressList.IsUnknown() {
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
	if portList.IsNull() || portList.IsUnknown() {
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
	if !plan.Log.Equal(state.Log) {
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
	// Note: We don't compare port/address lists deeply here for simplicity
	// A full implementation would compare those as well
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
	if plan.Rules.IsNull() || plan.Rules.IsUnknown() || state.Rules.IsNull() || state.Rules.IsUnknown() {
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
