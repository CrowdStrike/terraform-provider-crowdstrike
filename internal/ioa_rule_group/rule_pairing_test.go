package ioarulegroup

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
)

type ruleOpt func(*ioaRuleModel)

func withKey(k string) ruleOpt { return func(r *ioaRuleModel) { r.LocalKey = types.StringValue(k) } }

func renamed() ruleOpt { return func(r *ioaRuleModel) { r.Name = types.StringValue("renamed") } }

// asDomainRule makes the rule a Domain Name rule matching the given domain pattern.
func asDomainRule(include string) ruleOpt {
	return func(r *ioaRuleModel) {
		r.Type = types.StringValue("Domain Name")
		r.DomainName = excludable(types.StringValue(include), types.StringNull())
	}
}

func withDescription(d string) ruleOpt {
	return func(r *ioaRuleModel) { r.Description = types.StringValue(d) }
}

func withEnabled(e bool) ruleOpt { return func(r *ioaRuleModel) { r.Enabled = types.BoolValue(e) } }

func withComment(c string) ruleOpt { return func(r *ioaRuleModel) { r.Comment = types.StringValue(c) } }

func withFileType(t string) ruleOpt {
	return func(r *ioaRuleModel) {
		r.FileType = types.SetValueMust(types.StringType, []attr.Value{types.StringValue(t)})
	}
}

func withUnknownName() ruleOpt { return func(r *ioaRuleModel) { r.Name = types.StringUnknown() } }

func withUnknownType() ruleOpt { return func(r *ioaRuleModel) { r.Type = types.StringUnknown() } }

func withUnknownKey() ruleOpt { return func(r *ioaRuleModel) { r.LocalKey = types.StringUnknown() } }

func withNullKey() ruleOpt { return func(r *ioaRuleModel) { r.LocalKey = types.StringNull() } }

// withUnknownValues makes every value except key and type unknown.
func withUnknownValues() ruleOpt {
	return func(r *ioaRuleModel) {
		r.Name = types.StringUnknown()
		r.Description = types.StringUnknown()
		r.PatternSeverity = types.StringUnknown()
		r.Action = types.StringUnknown()
		r.Enabled = types.BoolUnknown()
		r.ImageFilename = types.ObjectUnknown(excludableFieldAttrTypes)
	}
}

func withImageFilename(include, exclude types.String) ruleOpt {
	return func(r *ioaRuleModel) { r.ImageFilename = excludable(include, exclude) }
}

func excludable(include, exclude types.String) types.Object {
	return types.ObjectValueMust(excludableFieldAttrTypes, map[string]attr.Value{
		"include": include,
		"exclude": exclude,
	})
}

// newRule builds a configured Process Creation rule whose identity is its
// name, so tests can tell rules apart without setting every attribute.
func newRule(name string, opts ...ruleOpt) ioaRuleModel {
	r := ioaRuleModel{
		InstanceID:               types.StringNull(),
		LocalKey:                 types.StringNull(),
		Name:                     types.StringValue(name),
		Description:              types.StringValue(name + " description"),
		Comment:                  types.StringNull(),
		PatternSeverity:          types.StringValue("high"),
		Type:                     types.StringValue("Process Creation"),
		Action:                   types.StringValue("Detect"),
		Enabled:                  types.BoolValue(true),
		GrandparentImageFilename: types.ObjectNull(excludableFieldAttrTypes),
		GrandparentCommandLine:   types.ObjectNull(excludableFieldAttrTypes),
		ParentImageFilename:      types.ObjectNull(excludableFieldAttrTypes),
		ParentCommandLine:        types.ObjectNull(excludableFieldAttrTypes),
		ImageFilename:            excludable(types.StringValue(".*"+name+".*"), types.StringNull()),
		CommandLine:              types.ObjectNull(excludableFieldAttrTypes),
		FilePath:                 types.ObjectNull(excludableFieldAttrTypes),
		FileType:                 types.SetNull(types.StringType),
		RemoteIPAddress:          types.ObjectNull(excludableFieldAttrTypes),
		RemotePort:               types.ObjectNull(excludableFieldAttrTypes),
		ConnectionType:           types.SetNull(types.StringType),
		DomainName:               types.ObjectNull(excludableFieldAttrTypes),
	}
	for _, opt := range opts {
		opt(&r)
	}
	return r
}

// stateRule builds a rule as it appears in state: it has an instance ID and
// the API fills command_line, which configuration leaves unset.
func stateRule(name, id string, opts ...ruleOpt) ioaRuleModel {
	r := newRule(name, opts...)
	r.InstanceID = types.StringValue(id)
	if r.CommandLine.IsNull() {
		r.CommandLine = excludable(types.StringValue(".*"), types.StringNull())
	}
	return r
}

// ids builds planned instance IDs, where "" is an unknown ID.
func ids(values ...string) []types.String {
	out := make([]types.String, len(values))
	for i, v := range values {
		if v == "" {
			out[i] = types.StringUnknown()
		} else {
			out[i] = types.StringValue(v)
		}
	}
	return out
}

func TestPairRules(t *testing.T) {
	a, b, c := stateRule("a", "1"), stateRule("b", "2"), stateRule("c", "3")
	ka, kb := stateRule("a", "1", withKey("ka")), stateRule("b", "2", withKey("kb"))

	tests := []struct {
		name    string
		planned []ioaRuleModel
		prior   []ioaRuleModel
		want    []types.String
		// warnings lists the planned rules warned that they will be recreated.
		warnings []int
		// wantError is part of the expected error detail, or "" for no error.
		wantError string
	}{
		// Case 1: no rule has a key, so rules match by index.
		{
			name:    "no keys: unchanged",
			planned: []ioaRuleModel{newRule("a"), newRule("b")},
			prior:   []ioaRuleModel{a, b},
			want:    ids("1", "2"),
		},
		{
			name:    "no keys: insert at front shifts IDs by index",
			planned: []ioaRuleModel{newRule("new"), newRule("a"), newRule("b")},
			prior:   []ioaRuleModel{a, b},
			want:    ids("1", "2", ""),
		},
		{
			name:    "no keys: remove leaves the last prior rule unmatched",
			planned: []ioaRuleModel{newRule("a"), newRule("c")},
			prior:   []ioaRuleModel{a, b, c},
			want:    ids("1", "2"),
		},
		{
			name:    "no keys: reorder keeps IDs by index",
			planned: []ioaRuleModel{newRule("b"), newRule("a")},
			prior:   []ioaRuleModel{a, b},
			want:    ids("1", "2"),
		},
		{
			name:    "no keys: only type is read",
			planned: []ioaRuleModel{newRule("a", withUnknownValues()), newRule("b", withUnknownValues())},
			prior:   []ioaRuleModel{a, b},
			want:    ids("1", "2"),
		},
		{
			name:     "no keys: type change in place recreates the rule",
			planned:  []ioaRuleModel{newRule("a"), newRule("b", asDomainRule(".*b.*"))},
			prior:    []ioaRuleModel{a, b},
			want:     ids("1", ""),
			warnings: []int{1},
		},
		{
			name:     "no keys: insert of another type at front recreates index 0",
			planned:  []ioaRuleModel{newRule("d", asDomainRule(".*d.*")), newRule("a"), newRule("b")},
			prior:    []ioaRuleModel{a, b},
			want:     ids("", "2", ""),
			warnings: []int{0},
		},
		{
			name:    "no keys: unknown type leaves the ID unknown without a warning",
			planned: []ioaRuleModel{newRule("a", withUnknownType()), newRule("b")},
			prior:   []ioaRuleModel{a, b},
			want:    ids("", "2"),
		},
		{
			name:    "no keys: prior keys are ignored once every key is removed",
			planned: []ioaRuleModel{newRule("b"), newRule("a")},
			prior:   []ioaRuleModel{ka, kb},
			want:    ids("1", "2"),
		},
		{
			name:    "no keys: prior rule without an instance ID",
			planned: []ioaRuleModel{newRule("a")},
			prior:   []ioaRuleModel{newRule("a")},
			want:    ids(""),
		},

		// Case 2: every rule has a key and a prior rule has one, so rules match by key.
		{
			name:    "keys: insert and reorder match by key",
			planned: []ioaRuleModel{newRule("b", withKey("kb")), newRule("new", withKey("kn")), newRule("a", withKey("ka"))},
			prior:   []ioaRuleModel{ka, kb},
			want:    ids("2", "", "1"),
		},
		{
			name:    "keys: rename and edit keep the ID",
			planned: []ioaRuleModel{newRule("a", withKey("ka"), renamed(), withEnabled(false)), newRule("b", withKey("kb"), withDescription("edited"))},
			prior:   []ioaRuleModel{ka, kb},
			want:    ids("1", "2"),
		},
		{
			name:    "keys: removed rule is left unmatched",
			planned: []ioaRuleModel{newRule("b", withKey("kb"))},
			prior:   []ioaRuleModel{ka, kb},
			want:    ids("2"),
		},
		{
			name:    "keys: changed key is a new rule",
			planned: []ioaRuleModel{newRule("a", withKey("ka2")), newRule("b", withKey("kb"))},
			prior:   []ioaRuleModel{ka, kb},
			want:    ids("", "2"),
		},
		{
			name:    "keys: only key and type are read",
			planned: []ioaRuleModel{newRule("a", withKey("ka"), withUnknownValues()), newRule("new", withKey("kn")), newRule("b", withKey("kb"), withUnknownValues())},
			prior:   []ioaRuleModel{ka, kb},
			want:    ids("1", "", "2"),
		},
		{
			name:     "keys: type change recreates the rule",
			planned:  []ioaRuleModel{newRule("a", withKey("ka")), newRule("b", withKey("kb"), asDomainRule(".*b.*"))},
			prior:    []ioaRuleModel{ka, kb},
			want:     ids("1", ""),
			warnings: []int{1},
		},
		{
			name:    "keys: unknown type leaves the ID unknown without a warning",
			planned: []ioaRuleModel{newRule("a", withKey("ka")), newRule("b", withKey("kb"), withUnknownType())},
			prior:   []ioaRuleModel{ka, kb},
			want:    ids("1", ""),
		},
		{
			name:    "keys: unkeyed prior rules never match",
			planned: []ioaRuleModel{newRule("a", withKey("ka")), newRule("b", withKey("kb"))},
			prior:   []ioaRuleModel{ka, b},
			want:    ids("1", ""),
		},

		// Case 3: every rule gets a key and no prior rule has one.
		{
			name:    "adopting keys: unchanged rules match by index",
			planned: []ioaRuleModel{newRule("a", withKey("ka")), newRule("b", withKey("kb"))},
			prior:   []ioaRuleModel{a, b},
			want:    ids("1", "2"),
		},
		{
			name:    "adopting keys: comment and unconfigured Optional+Computed values are ignored",
			planned: []ioaRuleModel{newRule("a", withKey("ka"), withComment("new"), withImageFilename(types.StringNull(), types.StringValue("ex")))},
			prior:   []ioaRuleModel{stateRule("a", "1", withComment("old"), withImageFilename(types.StringValue(".*a.*"), types.StringValue("ex")))},
			want:    ids("1"),
		},
		{
			name:      "adopting keys: rename fails",
			planned:   []ioaRuleModel{newRule("a", withKey("ka"), renamed()), newRule("b", withKey("kb"))},
			prior:     []ioaRuleModel{a, b},
			want:      ids("", ""),
			wantError: `rules[0] ("renamed"): its name does not match the current rule "a"`,
		},
		{
			name:      "adopting keys: enabled change fails",
			planned:   []ioaRuleModel{newRule("a", withKey("ka")), newRule("b", withKey("kb"), withEnabled(false))},
			prior:     []ioaRuleModel{a, b},
			want:      ids("", ""),
			wantError: `rules[1] ("b"): its enabled does not match`,
		},
		{
			name:      "adopting keys: file_type change fails",
			planned:   []ioaRuleModel{newRule("a", withKey("ka"), withFileType("PDF"))},
			prior:     []ioaRuleModel{a},
			want:      ids(""),
			wantError: `its file_type does not match`,
		},
		{
			name:      "adopting keys: exclude change fails",
			planned:   []ioaRuleModel{newRule("a", withKey("ka"), withImageFilename(types.StringValue(".*a.*"), types.StringValue("ex")))},
			prior:     []ioaRuleModel{a},
			want:      ids(""),
			wantError: `its image_filename does not match`,
		},
		{
			name:      "adopting keys: type change fails",
			planned:   []ioaRuleModel{newRule("a", withKey("ka"), asDomainRule(".*a.*"))},
			prior:     []ioaRuleModel{a},
			want:      ids(""),
			wantError: `its type does not match`,
		},
		{
			name:      "adopting keys: insert fails",
			planned:   []ioaRuleModel{newRule("a", withKey("ka")), newRule("b", withKey("kb")), newRule("new", withKey("kn"))},
			prior:     []ioaRuleModel{a, b},
			want:      ids("", "", ""),
			wantError: `rules[2] ("new"): the current state has no rule at that position`,
		},
		{
			name:      "adopting keys: remove fails",
			planned:   []ioaRuleModel{newRule("a", withKey("ka"))},
			prior:     []ioaRuleModel{a, b},
			want:      ids(""),
			wantError: `the current rule "b" at rules[1]: it is missing from the configuration`,
		},
		{
			name:      "adopting keys: reorder fails",
			planned:   []ioaRuleModel{newRule("b", withKey("kb")), newRule("a", withKey("ka"))},
			prior:     []ioaRuleModel{a, b},
			want:      ids("", ""),
			wantError: `rules[0] ("b"): its name does not match the current rule "a"`,
		},
		{
			name:    "adopting keys: unknown value still matches by index",
			planned: []ioaRuleModel{newRule("a", withKey("ka"), withUnknownName()), newRule("b", withKey("kb"))},
			prior:   []ioaRuleModel{a, b},
			want:    ids("1", "2"),
		},
		{
			name:    "adopting keys: unknown type leaves the ID unknown without a warning",
			planned: []ioaRuleModel{newRule("a", withKey("ka"), withUnknownType())},
			prior:   []ioaRuleModel{a},
			want:    ids(""),
		},
		{
			name:    "adopting keys: unknown include still matches by index",
			planned: []ioaRuleModel{newRule("a", withKey("ka"), withImageFilename(types.StringUnknown(), types.StringNull()))},
			prior:   []ioaRuleModel{a},
			want:    ids("1"),
		},
		{
			name:      "adopting keys: a known difference fails despite an unknown value",
			planned:   []ioaRuleModel{newRule("a", withKey("ka"), withUnknownName()), newRule("b", withKey("kb"), withDescription("edited"))},
			prior:     []ioaRuleModel{a, b},
			want:      ids("", ""),
			wantError: `rules[1] ("b"): its description does not match`,
		},
		{
			name:      "adopting keys: insert fails despite an unknown value",
			planned:   []ioaRuleModel{newRule("a", withKey("ka"), withUnknownName()), newRule("new", withKey("kn"))},
			prior:     []ioaRuleModel{a},
			want:      ids("", ""),
			wantError: `rules[1] ("new"): the current state has no rule at that position`,
		},

		// Case 4: every rule has a key and there are no prior rules.
		{
			name:    "keys with no prior rules: every rule is new",
			planned: []ioaRuleModel{newRule("a", withKey("ka")), newRule("b", withKey("kb"))},
			prior:   nil,
			want:    ids("", ""),
		},

		// Any key unknown: every ID stays unknown until the keys are known.
		{
			name:    "unknown key: a value key does not match",
			planned: []ioaRuleModel{newRule("a", withKey("ka")), newRule("b", withUnknownKey())},
			prior:   []ioaRuleModel{ka, kb},
			want:    ids("", ""),
		},
		{
			name:    "unknown key: adopting keys is not checked",
			planned: []ioaRuleModel{newRule("a", withKey("ka"), renamed()), newRule("b", withUnknownKey())},
			prior:   []ioaRuleModel{a, b},
			want:    ids("", ""),
		},
		{
			name:    "every key unknown with keyed prior rules: every ID unknown",
			planned: []ioaRuleModel{newRule("a", withUnknownKey()), newRule("b", withUnknownKey())},
			prior:   []ioaRuleModel{ka, kb},
			want:    ids("", ""),
		},
		{
			name:    "every key unknown with partly keyed prior rules: every ID unknown",
			planned: []ioaRuleModel{newRule("a", withUnknownKey()), newRule("b", withUnknownKey())},
			prior:   []ioaRuleModel{ka, b},
			want:    ids("", ""),
		},
		{
			name:    "every key unknown with unkeyed prior rules: type change is not warned",
			planned: []ioaRuleModel{newRule("a", withUnknownKey()), newRule("b", withUnknownKey(), asDomainRule(".*b.*"))},
			prior:   []ioaRuleModel{a, b},
			want:    ids("", ""),
		},
		{
			name:    "every key unknown with no prior rules: every rule is new",
			planned: []ioaRuleModel{newRule("a", withUnknownKey())},
			prior:   nil,
			want:    ids(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, diags := pairRules(tt.planned, tt.prior)

			if len(got) != len(tt.want) {
				t.Fatalf("got %d instance IDs, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if !got[i].Equal(tt.want[i]) {
					t.Errorf("rules[%d] (%s): got instance ID %s, want %s", i, tt.planned[i].Name, got[i], tt.want[i])
				}
			}

			checkWarnings(t, diags, tt.warnings)

			errs := diags.Errors()
			switch {
			case tt.wantError == "" && len(errs) > 0:
				t.Errorf("unexpected error: %s: %s", errs[0].Summary(), errs[0].Detail())
			case tt.wantError != "" && len(errs) != 1:
				t.Errorf("got %d errors, want 1 containing %q", len(errs), tt.wantError)
			case tt.wantError != "":
				if !strings.Contains(errs[0].Detail(), tt.wantError) {
					t.Errorf("error detail %q does not contain %q", errs[0].Detail(), tt.wantError)
				}
				if !strings.Contains(errs[0].Detail(), "Rule keys must be added in their own apply, with the rules in the same order and with the same values as the current state.") {
					t.Errorf("error detail %q does not explain how to add keys", errs[0].Detail())
				}
				if strings.Contains(errs[0].Detail(), "\n") {
					t.Errorf("error detail %q is not a single line", errs[0].Detail())
				}
			}
		})
	}
}

func checkWarnings(t *testing.T, diags diag.Diagnostics, want []int) {
	t.Helper()

	warnings := diags.Warnings()
	if len(warnings) != len(want) {
		t.Fatalf("got %d warnings, want %d: %v", len(warnings), len(want), warnings)
	}
	for i, w := range warnings {
		if w.Summary() != "IOA rule will be recreated" {
			t.Errorf("warning %d: got summary %q", i, w.Summary())
		}
		withPath, ok := w.(diag.DiagnosticWithPath)
		if !ok || !withPath.Path().Equal(path.Root("rules").AtListIndex(want[i])) {
			t.Errorf("warning %d: want path rules[%d], got %v", i, want[i], w)
		}
	}
}

// TestPairRulesKnownIDsStable plans each scenario twice: with values unknown,
// as at plan time, and with them resolved, as during apply. Terraform rejects
// an apply that changes any instance ID the earlier plan already knew.
func TestPairRulesKnownIDsStable(t *testing.T) {
	a, b := stateRule("a", "1"), stateRule("b", "2")
	ka, kb := stateRule("a", "1", withKey("ka")), stateRule("b", "2", withKey("kb"))

	tests := []struct {
		name  string
		prior []ioaRuleModel
		plan  []ioaRuleModel
		apply []ioaRuleModel
	}{
		{
			name:  "every unknown key resolves to null with unkeyed prior rules",
			prior: []ioaRuleModel{a, b},
			plan:  []ioaRuleModel{newRule("a", withUnknownKey()), newRule("b", withUnknownKey())},
			apply: []ioaRuleModel{newRule("a", withNullKey()), newRule("b", withNullKey())},
		},
		{
			name:  "every unknown key resolves to null with keyed prior rules",
			prior: []ioaRuleModel{ka, kb},
			plan:  []ioaRuleModel{newRule("b", withUnknownKey()), newRule("a", withUnknownKey())},
			apply: []ioaRuleModel{newRule("b", withNullKey()), newRule("a", withNullKey())},
		},
		{
			name:  "every unknown key resolves to null with no prior rules",
			prior: nil,
			plan:  []ioaRuleModel{newRule("a", withUnknownKey())},
			apply: []ioaRuleModel{newRule("a", withNullKey())},
		},
		{
			name:  "unknown key resolves to its existing key",
			prior: []ioaRuleModel{ka, kb},
			plan:  []ioaRuleModel{newRule("a", withKey("ka")), newRule("b", withUnknownKey())},
			apply: []ioaRuleModel{newRule("a", withKey("ka")), newRule("b", withKey("kb"))},
		},
		{
			name:  "unknown key resolves to a new key",
			prior: []ioaRuleModel{ka},
			plan:  []ioaRuleModel{newRule("new", withUnknownKey()), newRule("a", withKey("ka"))},
			apply: []ioaRuleModel{newRule("new", withKey("kn")), newRule("a", withKey("ka"))},
		},
		{
			name:  "unknown type resolves to another type without keys",
			prior: []ioaRuleModel{a, b},
			plan:  []ioaRuleModel{newRule("a", withUnknownType()), newRule("b")},
			apply: []ioaRuleModel{newRule("a", asDomainRule(".*a.*")), newRule("b")},
		},
		{
			name:  "unknown type resolves to the same type with keys",
			prior: []ioaRuleModel{ka, kb},
			plan:  []ioaRuleModel{newRule("a", withKey("ka")), newRule("b", withKey("kb"), withUnknownType())},
			apply: []ioaRuleModel{newRule("a", withKey("ka")), newRule("b", withKey("kb"))},
		},
		{
			name:  "unknown name after an inserted rule without keys",
			prior: []ioaRuleModel{a, b},
			plan:  []ioaRuleModel{newRule("new"), newRule("a", withUnknownName()), newRule("b")},
			apply: []ioaRuleModel{newRule("new"), newRule("a"), newRule("b")},
		},
		{
			name:  "unknown name while adopting keys resolves to the current name",
			prior: []ioaRuleModel{a, b},
			plan:  []ioaRuleModel{newRule("a", withKey("ka"), withUnknownName()), newRule("b", withKey("kb"))},
			apply: []ioaRuleModel{newRule("a", withKey("ka")), newRule("b", withKey("kb"))},
		},
		{
			name:  "unknown name while adopting keys resolves to a new name",
			prior: []ioaRuleModel{a, b},
			plan:  []ioaRuleModel{newRule("a", withKey("ka"), withUnknownName()), newRule("b", withKey("kb"))},
			apply: []ioaRuleModel{newRule("a", withKey("ka"), renamed()), newRule("b", withKey("kb"))},
		},
		{
			name:  "null and unknown keys resolve to null with keyed prior rules",
			prior: []ioaRuleModel{ka, kb},
			plan:  []ioaRuleModel{newRule("b"), newRule("a", withUnknownKey())},
			apply: []ioaRuleModel{newRule("b"), newRule("a", withNullKey())},
		},
		{
			name:  "every unknown key resolves to its existing key",
			prior: []ioaRuleModel{ka, kb},
			plan:  []ioaRuleModel{newRule("b", withUnknownKey()), newRule("a", withUnknownKey())},
			apply: []ioaRuleModel{newRule("b", withKey("kb")), newRule("a", withKey("ka"))},
		},
		{
			name:  "every unknown key resolves to a key while adopting keys",
			prior: []ioaRuleModel{a, b},
			plan:  []ioaRuleModel{newRule("a", withUnknownKey()), newRule("b", withUnknownKey())},
			apply: []ioaRuleModel{newRule("a", withKey("ka")), newRule("b", withKey("kb"))},
		},
		{
			name:  "every unknown key with a rename resolves to null",
			prior: []ioaRuleModel{a, b},
			plan:  []ioaRuleModel{newRule("a", withUnknownKey(), renamed()), newRule("b", withUnknownKey())},
			apply: []ioaRuleModel{newRule("a", withNullKey(), renamed()), newRule("b", withNullKey())},
		},
		{
			name:  "every unknown key with a rename resolves to a key, which fails",
			prior: []ioaRuleModel{a, b},
			plan:  []ioaRuleModel{newRule("a", withUnknownKey(), renamed()), newRule("b", withUnknownKey())},
			apply: []ioaRuleModel{newRule("a", withKey("ka"), renamed()), newRule("b", withKey("kb"))},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			planned, diags := pairRules(tt.plan, tt.prior)
			if diags.HasError() {
				t.Fatalf("plan failed: %v", diags.Errors())
			}

			applied, diags := pairRules(tt.apply, tt.prior)
			if diags.HasError() {
				// A failed apply produces no final plan to contradict this one.
				return
			}

			for i, id := range planned {
				if !id.IsUnknown() && !id.Equal(applied[i]) {
					t.Errorf("rules[%d]: planned instance ID %s, but apply planned %s", i, id, applied[i])
				}
			}
		})
	}
}

func TestExcludableDiffers(t *testing.T) {
	str := types.StringValue
	null := types.StringNull()
	unknown := types.StringUnknown()

	tests := []struct {
		name    string
		planned types.Object
		prior   types.Object
		want    bool
	}{
		{"unconfigured accepts any prior", types.ObjectNull(excludableFieldAttrTypes), excludable(str(".*"), null), false},
		{"unconfigured accepts null prior", types.ObjectNull(excludableFieldAttrTypes), types.ObjectNull(excludableFieldAttrTypes), false},
		{"unknown field", types.ObjectUnknown(excludableFieldAttrTypes), excludable(str(".*"), null), false},
		{"configured against null prior", excludable(str("x"), null), types.ObjectNull(excludableFieldAttrTypes), true},
		{"equal include", excludable(str("x"), null), excludable(str("x"), null), false},
		{"different include", excludable(str("x"), null), excludable(str("y"), null), true},
		{"unconfigured include accepts prior include", excludable(null, str("ex")), excludable(str(".*"), str("ex")), false},
		{"unknown include", excludable(unknown, null), excludable(str("x"), null), false},
		{"unknown exclude", excludable(str("x"), unknown), excludable(str("x"), null), false},
		{"unknown include with different exclude", excludable(unknown, str("ex")), excludable(str("x"), null), true},
		{"exclude removed", excludable(str("x"), null), excludable(str("x"), str("ex")), true},
		{"exclude added", excludable(str("x"), str("ex")), excludable(str("x"), null), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := excludableDiffers(tt.planned, tt.prior); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasNonWildcardInclude(t *testing.T) {
	str, null, unknown := types.StringValue, types.StringNull(), types.StringUnknown()
	wildcard := withImageFilename(str(".*"), null)

	tests := []struct {
		name string
		rule ioaRuleModel
		want bool
	}{
		{"specific include", newRule("a"), true},
		{"wildcard include only", newRule("a", wildcard), false},
		{"unknown include", newRule("a", withImageFilename(unknown, null)), true},
		{"unknown field", newRule("a", func(r *ioaRuleModel) { r.ImageFilename = types.ObjectUnknown(excludableFieldAttrTypes) }), true},
		{"unknown file_type", newRule("a", wildcard, func(r *ioaRuleModel) { r.FileType = types.SetUnknown(types.StringType) }), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, diags := tt.rule.hasNonWildcardInclude(context.Background())
			if diags.HasError() {
				t.Fatalf("unexpected error: %v", diags.Errors())
			}
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// TestPartialStateNextPlan fails an update partway, saves the partial state,
// and plans the same configuration again. The saved state must be fully known,
// and the next plan must pair the rules that exist with the IDs the update
// used, without an error.
func TestPartialStateNextPlan(t *testing.T) {
	ka, kb := stateRule("a", "1", withKey("ka")), stateRule("b", "2", withKey("kb"))
	a, b := stateRule("a", "1"), stateRule("b", "2")

	tests := []struct {
		name   string
		prior  []ioaRuleModel
		config []ioaRuleModel
		// ids[i] is the instance ID the update used for config[i], or "" when
		// that rule was not created; applied is how many rules it finished.
		ids     []string
		applied int
		// api is the rules that exist after the failure.
		api []ioaRuleModel
		// wantState is each saved rule as "instance_id key comment", "-" for null.
		wantState []string
	}{
		{
			name:      "keys: creating a rule fails after a key change recreated another",
			prior:     []ioaRuleModel{ka},
			config:    []ioaRuleModel{newRule("a2", withKey("ka2")), newRule("b", withKey("kb"))},
			ids:       []string{"5", ""},
			applied:   1,
			api:       []ioaRuleModel{stateRule("a2", "5")},
			wantState: []string{"5 ka2 -"},
		},
		{
			name:      "keys: deleting a removed rule fails",
			prior:     []ioaRuleModel{ka, kb},
			config:    []ioaRuleModel{newRule("b", withKey("kb"))},
			ids:       []string{"2"},
			api:       []ioaRuleModel{ka, kb},
			wantState: []string{"2 kb -", "1 ka -"},
		},
		{
			name:      "adopting keys: updating the second rule fails",
			prior:     []ioaRuleModel{a, b},
			config:    []ioaRuleModel{newRule("a", withKey("ka"), withComment("new")), newRule("b", withKey("kb"), withComment("new"))},
			ids:       []string{"1", "2"},
			applied:   1,
			api:       []ioaRuleModel{stateRule("a", "1", withComment("new")), b},
			wantState: []string{"1 ka new", "2 kb -"},
		},
		{
			name:      "no keys: updating fails after an insert at the front",
			prior:     []ioaRuleModel{a, b},
			config:    []ioaRuleModel{newRule("new"), newRule("a"), newRule("b")},
			ids:       []string{"1", "2", ""},
			applied:   1,
			api:       []ioaRuleModel{stateRule("new", "1"), b},
			wantState: []string{"1 - -", "2 - -"},
		},
		{
			name:      "no keys: recreating a rule with a new type fails after the delete",
			prior:     []ioaRuleModel{a, b},
			config:    []ioaRuleModel{newRule("a"), newRule("b", asDomainRule(".*b.*"))},
			ids:       []string{"1", ""},
			applied:   1,
			api:       []ioaRuleModel{a},
			wantState: []string{"1 - -"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := ids(tt.ids...)

			planned := slices.Clone(tt.config)
			for i, id := range mustPair(t, tt.config, tt.prior) {
				if utils.IsKnown(id) && !id.Equal(want[i]) {
					t.Fatalf("rules[%d]: planned instance ID %s, but the update used %s", i, id, want[i])
				}
				planned[i].InstanceID = id
			}

			state := savedRules(t, tt.api, partialTrackedRules(planned, tt.prior, tt.ids, tt.applied))
			gotState := make([]string, len(state))
			for i, r := range state {
				gotState[i] = orDash(r.InstanceID) + " " + orDash(r.LocalKey) + " " + orDash(r.Comment)
			}
			if !slices.Equal(gotState, tt.wantState) {
				t.Fatalf("saved rules %q, want %q", gotState, tt.wantState)
			}

			for i, id := range mustPair(t, tt.config, state) {
				if !id.Equal(want[i]) {
					t.Errorf("next plan rules[%d] (%s): got instance ID %s, want %s", i, tt.config[i].Name, id, want[i])
				}
			}
		})
	}
}

func mustPair(t *testing.T, planned, prior []ioaRuleModel) []types.String {
	t.Helper()
	got, diags := pairRules(planned, prior)
	if diags.HasError() {
		t.Fatalf("pairing rules: %v", diags.Errors())
	}
	return got
}

// savedRules wraps the API rules into the state savePartialState saves, and
// fails unless that state is fully known.
func savedRules(t *testing.T, api []ioaRuleModel, tracked []trackedRule) []ioaRuleModel {
	t.Helper()
	ctx := context.Background()

	apiRules := make([]*models.APIRuleV1, len(api))
	for i, m := range api {
		apiRules[i] = apiRule(ctx, t, m)
	}
	list, diags := wrapRules(ctx, apiRules, tracked)
	if diags.HasError() {
		t.Fatalf("wrapping rules: %v", diags.Errors())
	}
	raw, err := list.ToTerraformValue(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !raw.IsFullyKnown() {
		t.Fatalf("saved rules are not fully known: %s", raw)
	}
	return utils.ListTypeAs[ioaRuleModel](ctx, list, &diags)
}

// apiRule builds the API rule that a rule in state was read from.
func apiRule(ctx context.Context, t *testing.T, m ioaRuleModel) *models.APIRuleV1 {
	t.Helper()
	fieldValues, diags := expandRuleToFieldValues(ctx, m)
	if diags.HasError() {
		t.Fatalf("expanding %s: %v", m.Name, diags.Errors())
	}
	disposition := dispositionMap[m.Action.ValueString()]
	return &models.APIRuleV1{
		InstanceID:      m.InstanceID.ValueStringPointer(),
		Name:            m.Name.ValueStringPointer(),
		Description:     m.Description.ValueStringPointer(),
		Comment:         m.Comment.ValueStringPointer(),
		PatternSeverity: m.PatternSeverity.ValueStringPointer(),
		RuletypeName:    m.Type.ValueStringPointer(),
		DispositionID:   &disposition,
		Enabled:         m.Enabled.ValueBoolPointer(),
		FieldValues:     fieldValues,
	}
}

func orDash(v types.String) string {
	if v.IsNull() {
		return "-"
	}
	return v.ValueString()
}
