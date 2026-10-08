package ioarulegroup

import (
	"fmt"
	"slices"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
)

// hasKey reports whether any rule has a key that is a value.
func hasKey(rules []ioaRuleModel) bool {
	return slices.ContainsFunc(rules, func(r ioaRuleModel) bool { return utils.IsKnown(r.LocalKey) })
}

// hasUnknownKey reports whether any rule has an unknown key.
func hasUnknownKey(rules []ioaRuleModel) bool {
	return slices.ContainsFunc(rules, func(r ioaRuleModel) bool { return r.LocalKey.IsUnknown() })
}

// pairRules returns the planned instance ID of each planned rule: the ID of
// the prior state rule it updates, or unknown when the rule will be created.
//
// Without keys, each rule matches the prior rule at the same list index. With
// a key on every rule, each rule matches the prior rule with the same key.
// When every rule gets a key and no prior rule has one, rules match by index
// only if each rule equals the prior rule at its index, because from then on
// the key is all that identifies a rule.
//
// An unknown planned key may resolve to null or to a value, so while any key
// is unknown every ID stays unknown, and the rules are paired when Terraform
// plans again during apply with every key known. Keys are all or nothing, so
// once every key is known, either every key is a value or every key is null.
//
// A matched rule whose type differs from its prior rule's type, or is unknown,
// gets an unknown ID: the update API cannot change a rule's type, so Update
// deletes the prior rule and creates a new one.
//
// Terraform plans again during apply with every value known, and rejects an
// apply that changes an ID this plan made known. Every known ID here is the ID
// that plan chooses, or that plan fails with an error.
//
// An unconfigured Optional+Computed value in planned is null, unknown, or the
// prior value at the same index, and none of those is a difference.
func pairRules(planned, prior []ioaRuleModel) ([]types.String, diag.Diagnostics) {
	var diags diag.Diagnostics
	plannedKeys, priorKeys := hasKey(planned), hasKey(prior)

	// matched[i] is the index of the prior rule planned[i] updates, or -1.
	matched := slices.Repeat([]int{-1}, len(planned))

	switch {
	case hasUnknownKey(planned):
		// Every ID stays unknown until the keys are known.

	case plannedKeys && priorKeys:
		priorByKey := make(map[string]int, len(prior))
		for j, p := range prior {
			if utils.IsKnown(p.LocalKey) {
				priorByKey[p.LocalKey.ValueString()] = j
			}
		}
		for i, r := range planned {
			if j, ok := priorByKey[r.LocalKey.ValueString()]; ok {
				matched[i] = j
			}
		}

	case plannedKeys && len(prior) == 0:
		// No prior rules, so every rule is created.

	case plannedKeys:
		if attrPath, reason := firstAdoptionDifference(planned, prior); reason != "" {
			diags.AddAttributeError(
				attrPath,
				"Rule keys added with other rule changes",
				"Rule keys must be added in their own apply, with the rules in the same order and with the same values as the current state. "+reason,
			)
			break
		}
		// A value still unknown either matches during apply, so the rules
		// match by index then too, or differs and that plan fails.
		fallthrough

	default:
		// Without keys, rules match by index.
		for i := range min(len(planned), len(prior)) {
			matched[i] = i
		}
	}

	ids := make([]types.String, len(planned))
	for i, j := range matched {
		ids[i] = types.StringUnknown()
		if j < 0 {
			continue
		}
		r, p := planned[i], prior[j]
		switch {
		case !utils.IsKnown(p.InstanceID), r.Type.IsUnknown():
		case !r.Type.Equal(p.Type):
			diags.AddAttributeWarning(
				path.Root("rules").AtListIndex(i),
				"IOA rule will be recreated",
				fmt.Sprintf(
					"The existing rule %q has type %q, but rules[%d] (%q) has type %q. A rule's type cannot be updated, so the existing rule will be deleted and a new rule with a new instance ID will be created.",
					p.Name.ValueString(),
					p.Type.ValueString(),
					i,
					r.Name.ValueString(),
					r.Type.ValueString(),
				),
			)
		default:
			ids[i] = p.InstanceID
		}
	}

	return ids, diags
}

// firstAdoptionDifference compares rules being given keys for the first time
// with the prior rules at the same index. It returns the path of the first
// rule with a known difference, or of the rules list when a prior rule is
// missing, and a sentence naming it, or an empty reason when there is none.
// Unknown values are not differences.
func firstAdoptionDifference(planned, prior []ioaRuleModel) (path.Path, string) {
	rules := path.Root("rules")
	for i := range max(len(planned), len(prior)) {
		switch {
		case i >= len(prior):
			return rules.AtListIndex(i), fmt.Sprintf(
				"The first rule that differs is rules[%d] (%q): the current state has no rule at that position.",
				i, planned[i].Name.ValueString(),
			)
		case i >= len(planned):
			return rules, fmt.Sprintf(
				"The first rule that differs is the current rule %q at rules[%d]: it is missing from the configuration.",
				prior[i].Name.ValueString(), i,
			)
		}

		if attrName := ruleDifference(planned[i], prior[i]); attrName != "" {
			return rules.AtListIndex(i), fmt.Sprintf(
				"The first rule that differs is rules[%d] (%q): its %s does not match the current rule %q.",
				i, planned[i].Name.ValueString(), attrName, prior[i].Name.ValueString(),
			)
		}
	}
	return rules, ""
}

// ruleDifference returns the name of the first configured attribute of the
// planned rule that differs from the prior rule, or "" when none does. An
// unknown planned value is not a difference. key and comment are ignored:
// neither changes what the rule detects.
func ruleDifference(planned, prior ioaRuleModel) string {
	values := []struct {
		name           string
		planned, prior attr.Value
	}{
		{"name", planned.Name, prior.Name},
		{"description", planned.Description, prior.Description},
		{"pattern_severity", planned.PatternSeverity, prior.PatternSeverity},
		{"type", planned.Type, prior.Type},
		{"action", planned.Action, prior.Action},
		{"enabled", planned.Enabled, prior.Enabled},
		{"file_type", planned.FileType, prior.FileType},
		{"connection_type", planned.ConnectionType, prior.ConnectionType},
	}
	for _, v := range values {
		if !v.planned.IsUnknown() && !v.planned.Equal(v.prior) {
			return v.name
		}
	}

	priorFields := prior.excludableFields()
	for i, f := range planned.excludableFields() {
		if excludableDiffers(f.value, priorFields[i].value) {
			return f.name
		}
	}

	return ""
}

// excludableDiffers reports whether a configured excludable field differs
// from the prior value. The field and its include pattern are
// Optional+Computed, so leaving either unconfigured accepts whatever the API
// stored. An unknown value is not a difference.
func excludableDiffers(planned, prior types.Object) bool {
	switch {
	case planned.IsUnknown(), planned.IsNull():
		return false
	case prior.IsNull() || prior.IsUnknown():
		return true
	}

	plannedAttrs := planned.Attributes()
	priorAttrs := prior.Attributes()

	include := plannedAttrs["include"]
	if utils.IsKnown(include) && !include.Equal(priorAttrs["include"]) {
		return true
	}

	exclude := plannedAttrs["exclude"]
	return !exclude.IsUnknown() && !exclude.Equal(priorAttrs["exclude"])
}
