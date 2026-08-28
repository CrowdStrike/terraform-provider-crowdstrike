package firewall_test

import (
	"context"
	"fmt"
	"slices"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/firewall_management"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/testconfig"
	"github.com/go-openapi/swag"
	tfjson "github.com/hashicorp/terraform-json"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// This file holds the state checks and the out-of-band API helpers the rule group
// acceptance tests share.
//
// The checks here are the ones the testing library cannot express: per-position
// rule identity is statecheck.CompareValue, but "no rule recycled a deleted id"
// and "this id is gone from the whole group" have no built-in equivalent.
//
// The API helpers deliberately spell out their own request payloads rather than
// borrowing the resource's builders, so a bug in the provider's payload
// construction cannot hide by appearing on both sides of an assertion.

// ruleGroupResourceName is the address every rule group scenario uses.
const ruleGroupResourceName = "crowdstrike_firewall_rule_group.test"

// refreshExpectingUpdate is the second half of every drift scenario: mutate the
// group through the API in PreConfig, then refresh and require a non-empty plan
// that repairs the group in place.
//
// A RefreshState step honors only step.Check and RefreshPlanChecks.PostRefresh;
// ConfigStateChecks and ConfigPlanChecks are ignored on it. State assertions
// therefore belong on the reapply step that follows.
func refreshExpectingUpdate(preConfig func()) resource.TestStep {
	return resource.TestStep{
		PreConfig:          preConfig,
		RefreshState:       true,
		ExpectNonEmptyPlan: true,
		RefreshPlanChecks: resource.RefreshPlanChecks{
			PostRefresh: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction(ruleGroupResourceName, plancheck.ResourceActionUpdate),
			},
		},
	}
}

// importVerify is the standard command-style import round trip.
func importVerify() resource.TestStep {
	return resource.TestStep{
		ResourceName:      ruleGroupResourceName,
		ImportState:       true,
		ImportStateVerify: true,
	}
}

// stateCheckFunc adapts a plain function into a statecheck.StateCheck.
type stateCheckFunc func(ctx context.Context, state *tfjson.State) error

func (f stateCheckFunc) CheckState(
	ctx context.Context,
	req statecheck.CheckStateRequest,
	resp *statecheck.CheckStateResponse,
) {
	resp.Error = f(ctx, req.State)
}

func stateResource(state *tfjson.State) (*tfjson.StateResource, error) {
	if state == nil || state.Values == nil || state.Values.RootModule == nil {
		return nil, fmt.Errorf("state is empty")
	}
	for _, res := range state.Values.RootModule.Resources {
		if res.Address == ruleGroupResourceName {
			return res, nil
		}
	}

	return nil, fmt.Errorf("%s not found in state", ruleGroupResourceName)
}

// stateGroupID returns the rule group's id from state. Every check that reaches
// for the API needs it, and an empty one means the resource never got created.
func stateGroupID(state *tfjson.State) (string, error) {
	res, err := stateResource(state)
	if err != nil {
		return "", err
	}
	id, ok := res.AttributeValues["id"].(string)
	if !ok || id == "" {
		return "", fmt.Errorf("%s: id is not a non-empty string", ruleGroupResourceName)
	}

	return id, nil
}

// stateRuleIDs returns the rules[*].id values in state, in order, or an empty
// slice when the rules attribute is unset.
func stateRuleIDs(state *tfjson.State) ([]string, error) {
	res, err := stateResource(state)
	if err != nil {
		return nil, err
	}
	raw, ok := res.AttributeValues["rules"]
	if !ok || raw == nil {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("rules is not a list: %T", raw)
	}
	ids := make([]string, 0, len(list))
	for i, elem := range list {
		rule, ok := elem.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("rules[%d] is not an object: %T", i, elem)
		}
		id, ok := rule["id"].(string)
		if !ok {
			return nil, fmt.Errorf("rules[%d].id is not a string: %v", i, rule["id"])
		}
		ids = append(ids, id)
	}

	return ids, nil
}

// ruleIDs holds the rules[*].id values captured in one step so a later step can
// assert which rule identities survived a change.
type ruleIDs struct {
	ids []string
}

// ruleIDPath addresses one rule's id, which is the value a test follows across
// steps to prove the rule was moved or edited rather than recreated. A
// statecheck.CompareValue is fed one of these per step; both comparers walk
// consecutive pairs, so one comparer can span more than two steps.
func ruleIDPath(index int) tfjsonpath.Path {
	return tfjsonpath.New("rules").AtSliceIndex(index).AtMapKey("id")
}

// captureRuleIDs records the rule ids in state for comparison by a later step.
func captureRuleIDs(dst *ruleIDs) statecheck.StateCheck {
	return stateCheckFunc(func(_ context.Context, state *tfjson.State) error {
		ids, err := stateRuleIDs(state)
		if err != nil {
			return err
		}
		dst.ids = ids

		return nil
	})
}

// captureGroupID records the rule group id so a later step's PreConfig can change
// the group directly through the API.
func captureGroupID(dst *string) statecheck.StateCheck {
	return stateCheckFunc(func(_ context.Context, state *tfjson.State) error {
		id, err := stateGroupID(state)
		if err != nil {
			return err
		}
		*dst = id

		return nil
	})
}

// wantRuleIDsUsable asserts every rule has a non-empty id and that no two rules
// share one, since state addresses rules by id.
func wantRuleIDsUsable() statecheck.StateCheck {
	return stateCheckFunc(func(_ context.Context, state *tfjson.State) error {
		ids, err := stateRuleIDs(state)
		if err != nil {
			return err
		}
		seen := make(map[string]int, len(ids))
		for i, id := range ids {
			if id == "" {
				return fmt.Errorf("rules[%d].id is empty (all ids: %v)", i, ids)
			}
			if prev, dup := seen[id]; dup {
				return fmt.Errorf("rules[%d].id duplicates rules[%d].id (%s)", i, prev, id)
			}
			seen[id] = i
		}

		return nil
	})
}

// wantRuleIDsNew asserts the rules at the given positions do not claim an
// identity that already belonged to a different rule, which is what an
// index-based implementation does when a rule is inserted.
func wantRuleIDsNew(captured *ruleIDs, positions ...int) statecheck.StateCheck {
	return stateCheckFunc(func(_ context.Context, state *tfjson.State) error {
		ids, err := stateRuleIDs(state)
		if err != nil {
			return err
		}
		for _, pos := range positions {
			if pos >= len(ids) {
				return fmt.Errorf("rules[%d] missing: state has only %d rules", pos, len(ids))
			}
			if slices.Contains(captured.ids, ids[pos]) {
				return fmt.Errorf(
					"rules[%d].id is %q, which already belonged to another rule before this change (before: %v)",
					pos, ids[pos], captured.ids,
				)
			}
		}

		return nil
	})
}

// wantRuleIDsAbsent asserts the identities the captured state held at the given
// positions are no longer in the group. Pairing it with a per-position identity
// comparison is what pins down which rule a delete actually removed: the
// survivors keep their ids and the deleted rule's id is gone.
func wantRuleIDsAbsent(captured *ruleIDs, positions ...int) statecheck.StateCheck {
	return stateCheckFunc(func(_ context.Context, state *tfjson.State) error {
		ids, err := stateRuleIDs(state)
		if err != nil {
			return err
		}
		for _, pos := range positions {
			if pos >= len(captured.ids) {
				return fmt.Errorf("captured state has only %d rules, cannot compare against index %d", len(captured.ids), pos)
			}
			if slices.Contains(ids, captured.ids[pos]) {
				return fmt.Errorf(
					"rule %q (captured index %d) is still in the group, so the delete removed a different rule. before: %v, after: %v",
					captured.ids[pos], pos, captured.ids, ids,
				)
			}
		}

		return nil
	})
}

// apiGroupFromState reads the rule group id from state and fetches the live
// group. Every check that reaches for the API starts here, and a group Terraform
// tracks that the API does not have is a failure in itself.
func apiGroupFromState(ctx context.Context, state *tfjson.State) (*models.FwmgrAPIRuleGroupV1, error) {
	groupID, err := stateGroupID(state)
	if err != nil {
		return nil, err
	}
	group, err := apiRuleGroup(ctx, groupID)
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, fmt.Errorf("rule group %s is in state but not in the API", groupID)
	}

	return group, nil
}

// wantAPIPrecedence asserts the group's rule_ids array, which is the only
// authority on firewall precedence, matches rules[*].id in state exactly. This
// catches both a precedence order the user did not ask for and an id in state
// that no longer names a live rule.
//
// Every successful apply step that configures rules asserts this, so an
// unrelated update cannot silently corrupt precedence.
func wantAPIPrecedence() statecheck.StateCheck {
	return stateCheckFunc(func(ctx context.Context, state *tfjson.State) error {
		stateIDs, err := stateRuleIDs(state)
		if err != nil {
			return err
		}

		group, err := apiGroupFromState(ctx, state)
		if err != nil {
			return err
		}

		if !slices.Equal(group.RuleIds, stateIDs) {
			return fmt.Errorf(
				"rule group %s: API rule_ids order %v does not match state rules[*].id order %v",
				swag.StringValue(group.ID), group.RuleIds, stateIDs,
			)
		}

		return nil
	})
}

// wantGroupExistsInAPI asserts the group Terraform tracks is really there. Every
// other check reads Terraform state, which a provider that invented its state
// would satisfy on its own.
func wantGroupExistsInAPI() statecheck.StateCheck {
	return stateCheckFunc(func(ctx context.Context, state *tfjson.State) error {
		_, err := apiGroupFromState(ctx, state)

		return err
	})
}

// wantAPIRuleIDCount asserts the live group holds exactly the given number of
// rules, which is how a test proves an empty rules list really emptied the group
// rather than only Terraform's view of it.
func wantAPIRuleIDCount(count int) statecheck.StateCheck {
	return stateCheckFunc(func(ctx context.Context, state *tfjson.State) error {
		group, err := apiGroupFromState(ctx, state)
		if err != nil {
			return err
		}
		if len(group.RuleIds) != count {
			return fmt.Errorf("rule group %s has %d rule ids, want %d: %v",
				swag.StringValue(group.ID), len(group.RuleIds), count, group.RuleIds)
		}

		return nil
	})
}

// testClient returns the shared acceptance-test API client.
func testClient() (*client.CrowdStrikeAPISpecification, error) {
	c := testconfig.GetTestClient()
	if c == nil {
		return nil, fmt.Errorf("test client is not initialized; acctest.PreCheck must run first")
	}

	return c, nil
}

// apiRuleGroup fetches a rule group so a test can read its rule_ids array. A
// group that is not live comes back nil: the API soft-deletes, so a deleted group
// is still returned by this endpoint with deleted set, and presence in the
// response is not the same as existing.
func apiRuleGroup(ctx context.Context, groupID string) (*models.FwmgrAPIRuleGroupV1, error) {
	apiClient, err := testClient()
	if err != nil {
		return nil, err
	}

	params := firewall_management.NewGetRuleGroupsParams().
		WithContext(ctx).
		WithIds([]string{groupID})

	resp, err := apiClient.FirewallManagement.GetRuleGroups(params)
	if err != nil {
		return nil, fmt.Errorf("getting rule group %s: %w", groupID, err)
	}
	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 || resp.Payload.Resources[0] == nil {
		return nil, nil
	}
	if swag.BoolValue(resp.Payload.Resources[0].Deleted) {
		return nil, nil
	}

	return resp.Payload.Resources[0], nil
}

// existingRuleIndex and appendableIndex name apiGroupAtIndex's bound. Only an
// insert may address the position one past the last rule.
const (
	existingRuleIndex = false
	appendableIndex   = true
)

// apiGroupAtIndex fetches a rule group for an out-of-band mutation of the rule at
// the given rule_ids index, rejecting an index the group cannot address. action
// names the mutation in the error message.
func apiGroupAtIndex(
	ctx context.Context,
	groupID, action string,
	index int,
	bound bool,
) (*models.FwmgrAPIRuleGroupV1, error) {
	group, err := apiRuleGroup(ctx, groupID)
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, fmt.Errorf("rule group %s not found", groupID)
	}

	limit := len(group.RuleIds)
	if bound == appendableIndex {
		limit++
	}
	if index >= limit {
		return nil, fmt.Errorf("rule group %s has %d rules, cannot %s index %d",
			groupID, len(group.RuleIds), action, index)
	}

	return group, nil
}

// replaceOps builds a deterministic JSON-Patch replace operation per field, at
// prefix. An empty prefix targets the group's own attributes; "/rules/N" targets
// one rule.
func replaceOps(prefix string, fields map[string]any) []*models.FwmgrAPIJSONDiff {
	// Sorted so the request is deterministic run to run.
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	slices.Sort(names)

	ops := make([]*models.FwmgrAPIJSONDiff, 0, len(names))
	for _, name := range names {
		ops = append(ops, &models.FwmgrAPIJSONDiff{
			Op:    swag.String("replace"),
			Path:  swag.String(prefix + "/" + name),
			Value: fields[name],
		})
	}

	return ops
}

// testAccCheckFirewallRuleGroupDestroy verifies every rule group tracked in state
// is gone from the API once the test tears down. Delete disables the group and
// then deletes it, and treats a not-found response from either call as success,
// so without this check a Delete that never removed anything still passes.
func testAccCheckFirewallRuleGroupDestroy(s *terraform.State) error {
	ctx := context.Background()
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "crowdstrike_firewall_rule_group" {
			continue
		}
		group, err := apiRuleGroup(ctx, rs.Primary.ID)
		if err != nil {
			return err
		}
		if group != nil {
			return fmt.Errorf("firewall rule group %s still exists after destroy", rs.Primary.ID)
		}
	}

	return nil
}

// deleteAPIRuleGroup deletes a group outside Terraform, the way a user deleting
// it in the console would. It disables the group first because the API refuses to
// delete an enabled one.
func deleteAPIRuleGroup(ctx context.Context, groupID string) error {
	apiClient, err := testClient()
	if err != nil {
		return err
	}

	group, err := apiRuleGroup(ctx, groupID)
	if err != nil {
		return err
	}
	if group == nil {
		return fmt.Errorf("rule group %s not found", groupID)
	}

	if err := patchRuleGroup(ctx, group, group.RuleIds, []*models.FwmgrAPIJSONDiff{{
		Op:    swag.String("replace"),
		Path:  swag.String("/enabled"),
		Value: false,
	}}); err != nil {
		return fmt.Errorf("disabling rule group %s: %w", groupID, err)
	}

	del := firewall_management.NewDeleteRuleGroupsParams().
		WithContext(ctx).
		WithIds([]string{groupID})
	if _, err := apiClient.FirewallManagement.DeleteRuleGroups(del); err != nil {
		return fmt.Errorf("deleting rule group %s: %w", groupID, err)
	}

	return nil
}

// editAPIRuleGroupScalars changes the group's own attributes outside Terraform in
// a single request.
func editAPIRuleGroupScalars(ctx context.Context, groupID string, fields map[string]any) error {
	group, err := apiRuleGroup(ctx, groupID)
	if err != nil {
		return err
	}
	if group == nil {
		return fmt.Errorf("rule group %s not found", groupID)
	}

	if err := patchRuleGroup(ctx, group, group.RuleIds, replaceOps("", fields)); err != nil {
		return fmt.Errorf("editing rule group %s: %w", groupID, err)
	}

	return nil
}

// patchRuleGroup submits a rule group modify request the way the console does.
// ruleIDs is the group's precedence order and ops are the rule-level changes;
// either may be left as it is so a caller can change only the other.
func patchRuleGroup(
	ctx context.Context,
	group *models.FwmgrAPIRuleGroupV1,
	ruleIDs []string,
	ops []*models.FwmgrAPIJSONDiff,
) error {
	apiClient, err := testClient()
	if err != nil {
		return err
	}

	params := firewall_management.NewUpdateRuleGroupParams().
		WithContext(ctx).
		WithBody(&models.FwmgrAPIRuleGroupModifyRequestV1{
			ID:             group.ID,
			Tracking:       group.Tracking,
			DiffType:       swag.String("application/json-patch+json"),
			DiffOperations: ops,
			RuleIds:        ruleIDs,
			// The API rejects a request whose rule_versions length differs from
			// rule_ids, whatever the values are.
			RuleVersions: make([]int64, len(ruleIDs)),
		})

	_, err = apiClient.FirewallManagement.UpdateRuleGroup(params)

	return err
}

// deleteAPIRule removes the rule at the given rule_ids index outside Terraform,
// simulating a user deleting one rule from a group in the console. The rule group
// modify endpoint is the only way to delete a rule, and it takes the group's new
// rule_ids in the same request, so this can never leave rule_ids naming a rule
// that no longer exists.
func deleteAPIRule(ctx context.Context, groupID string, index int) error {
	group, err := apiGroupAtIndex(ctx, groupID, "delete", index, existingRuleIndex)
	if err != nil {
		return err
	}

	remaining := slices.Delete(slices.Clone(group.RuleIds), index, index+1)

	if err := patchRuleGroup(ctx, group, remaining, []*models.FwmgrAPIJSONDiff{{
		Op:   swag.String("remove"),
		Path: swag.String(fmt.Sprintf("/rules/%d", index)),
	}}); err != nil {
		return fmt.Errorf("deleting rule at index %d of group %s: %w", index, groupID, err)
	}

	return nil
}

// replaceAPIRule rewrites the rule at the given rule_ids index outside Terraform,
// simulating a user editing a rule in the console. An edit is a remove plus an
// add, the same shape the resource's own update uses, so the rule that comes back
// carries a new family id at the same precedence position. The add appends to the
// group's rules array; its position is set by where its temp id sits in rule_ids.
//
// This is the only out-of-band edit that can set a rule's fields array or monitor
// object, so it is what covers reading those back. editAPIRuleFieldsInPlace
// cannot, for the reasons in its own comment.
func replaceAPIRule(ctx context.Context, groupID string, index int, rule apiRulePayload) error {
	group, err := apiGroupAtIndex(ctx, groupID, "replace", index, existingRuleIndex)
	if err != nil {
		return err
	}

	const tempID = "temp_id:1"
	newRuleIDs := slices.Clone(group.RuleIds)
	newRuleIDs[index] = tempID

	ops := []*models.FwmgrAPIJSONDiff{
		{
			Op:   swag.String("remove"),
			Path: swag.String(fmt.Sprintf("/rules/%d", index)),
		},
		{
			Op:    swag.String("add"),
			Path:  swag.String("/rules/-"),
			Value: rule.build(tempID),
		},
	}

	if err := patchRuleGroup(ctx, group, newRuleIDs, ops); err != nil {
		return fmt.Errorf("replacing rule at index %d of group %s: %w", index, groupID, err)
	}

	return nil
}

// insertAPIRule adds a rule the configuration does not know about at the given
// rule_ids position, simulating a user adding a rule to a managed group in the
// console. The add appends to the rules array; the position comes from where its
// temp id sits in rule_ids.
func insertAPIRule(ctx context.Context, groupID string, index int, rule apiRulePayload) error {
	group, err := apiGroupAtIndex(ctx, groupID, "insert at", index, appendableIndex)
	if err != nil {
		return err
	}

	const tempID = "temp_id:1"
	newRuleIDs := slices.Insert(slices.Clone(group.RuleIds), index, tempID)

	ops := []*models.FwmgrAPIJSONDiff{{
		Op:    swag.String("add"),
		Path:  swag.String("/rules/-"),
		Value: rule.build(tempID),
	}}

	if err := patchRuleGroup(ctx, group, newRuleIDs, ops); err != nil {
		return fmt.Errorf("inserting rule at index %d of group %s: %w", index, groupID, err)
	}

	return nil
}

// editAPIRuleFieldsInPlace changes scalar fields on the rule at the given
// rule_ids index with JSON Patch replace operations, the way the console does an
// edit that touches nothing but scalars. Unlike a remove plus add, this preserves
// the rule's family, so the group's rule_ids comes back byte for byte identical
// and only the rule's contents and version change. It returns the family at that
// index before and after so a caller can prove the identity really did survive.
//
// Only scalar fields are supported on purpose: replacing a list field appends to
// it instead of replacing it, replacing a list with an empty list does nothing at
// all, and the endpoint rejects add and remove on any rule sub-path, so an
// in-place edit cannot express a change to a port list, an address list, an
// executable path, a service name or watch mode. Use replaceAPIRule for those.
func editAPIRuleFieldsInPlace(
	ctx context.Context,
	groupID string,
	index int,
	fields map[string]any,
) (before, after string, err error) {
	group, err := apiGroupAtIndex(ctx, groupID, "edit", index, existingRuleIndex)
	if err != nil {
		return "", "", err
	}
	before = group.RuleIds[index]

	ops := replaceOps(fmt.Sprintf("/rules/%d", index), fields)

	// rule_ids is resubmitted unchanged: an in-place edit changes no identities.
	if err := patchRuleGroup(ctx, group, group.RuleIds, ops); err != nil {
		return "", "", fmt.Errorf("editing rule %d of group %s in place: %w", index, groupID, err)
	}

	updated, err := apiRuleGroup(ctx, groupID)
	if err != nil {
		return "", "", err
	}
	if updated == nil {
		return "", "", fmt.Errorf("rule group %s disappeared during an in-place edit", groupID)
	}
	if index >= len(updated.RuleIds) {
		return "", "", fmt.Errorf("rule group %s lost index %d during an in-place edit", groupID, index)
	}

	return before, updated.RuleIds[index], nil
}

// apiRulePayload is the rule object the rule group modify endpoint accepts. It is
// spelled out here rather than borrowed from the resource so a test says for
// itself what it sent to the API, and so a bug in the resource's own payload
// builder cannot hide by being on both sides of the assertion.
type apiRulePayload struct {
	name        string
	description string
	enabled     bool
	action      string
	direction   string
	protocol    string // IANA number, which is what the API stores.
	remotePort  int64
	// localAddress, when set, names a specific address instead of the wildcard.
	localAddress    []apiAddress
	watchMode       bool
	networkLocation string
}

// apiAddress is one entry of a rule's address list in an API payload.
type apiAddress struct {
	address string
	netmask int64
}

func (p apiRulePayload) build(tempID string) map[string]any {
	networkLocation := p.networkLocation
	if networkLocation == "" {
		networkLocation = "ANY"
	}

	payload := map[string]any{
		"temp_id":     tempID,
		"name":        p.name,
		"description": p.description,
		"enabled":     p.enabled,
		"action":      p.action,
		"direction":   p.direction,
		"protocol":    p.protocol,
		// The Terraform address_family "IP4" with no address list, which is what
		// every rule these tests drift is configured with.
		"address_family": "IP4",
		"fqdn":           "",
		"fqdn_enabled":   false,
		// Required by the API, never returned, and not part of the schema.
		"log": false,
		"fields": []map[string]any{{
			"name":   "network_location",
			"type":   "set",
			"values": []string{networkLocation},
		}},
	}

	if p.remotePort != 0 {
		payload["remote_port"] = []map[string]any{{"start": p.remotePort, "end": 0}}
	}

	if len(p.localAddress) > 0 {
		addresses := make([]map[string]any, 0, len(p.localAddress))
		for _, a := range p.localAddress {
			addresses = append(addresses, map[string]any{
				"address": a.address,
				"netmask": a.netmask,
			})
		}
		payload["local_address"] = addresses
	}

	if p.watchMode {
		payload["monitor"] = map[string]any{"count": "1", "period_ms": "3600000"}
	}

	return payload
}

// rotateAPIRuleOrder moves the last rule to the front of a group's rule_ids
// outside Terraform, which drifts precedence without the symmetry of a reversal.
func rotateAPIRuleOrder(ctx context.Context, groupID string) error {
	group, err := apiRuleGroup(ctx, groupID)
	if err != nil {
		return err
	}
	if group == nil {
		return fmt.Errorf("rule group %s not found", groupID)
	}
	if len(group.RuleIds) < 2 {
		return fmt.Errorf("rule group %s has %d rules, need at least 2 to reorder", groupID, len(group.RuleIds))
	}

	rotated := slices.Clone(group.RuleIds)
	last := len(rotated) - 1
	rotated = slices.Insert(slices.Delete(rotated, last, last+1), 0, group.RuleIds[last])

	if err := patchRuleGroup(ctx, group, rotated, []*models.FwmgrAPIJSONDiff{}); err != nil {
		return fmt.Errorf("rotating rule_ids for group %s: %w", groupID, err)
	}

	return nil
}
