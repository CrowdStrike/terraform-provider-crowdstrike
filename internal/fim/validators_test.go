package fim_test

import (
	"context"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/fim"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// The FileVantage API answers a character violation on a rule group or policy
// name/description with an opaque HTTP 500, so these patterns exist to catch the
// violation at plan time instead. Every character below was observed against the
// live API one at a time; the two fields deliberately disagree on `@` and newline,
// which description accepts and name rejects.
//
// Sourced from the pattern the API leaked in a 400 from its own backing service:
//
//	^[\w\p{L}\p{M}\- :;,\.!()&\[\]\n@]*$
const (
	// Accepted by both fields.
	sharedAccepted = ` !&(),-.:;[]_` +
		`0123456789` +
		`abcdefghijklmnopqrstuvwxyz` +
		`ABCDEFGHIJKLMNOPQRSTUVWXYZ`

	// Rejected by both fields. Note that U+2010 HYPHEN and U+2011 NON-BREAKING
	// HYPHEN are rejected while ASCII U+002D HYPHEN-MINUS is accepted, and that
	// U+200B ZERO WIDTH SPACE is rejected while being invisible in a config.
	sharedRejected = `"#$%'*+/<=>?\^` + "`" + `{|}~` +
		"\t\r\v\f" +
		"—–‒‑‐−" + // dashes that are not hyphen-minus
		"’‘“”…" + // curly quotes, ellipsis
		"\u00a0\u200b" + // no-break space, zero width space
		"\U0001f600" + // emoji
		"°€©×·•®→"

	// Unicode letters and marks, accepted by both fields.
	sharedAcceptedUnicode = "éñ中ЖΩאا" + "é"
)

// acceptedByDescriptionOnly are the two characters where the fields diverge.
const acceptedByDescriptionOnly = "@\n"

func TestNamePattern(t *testing.T) {
	t.Parallel()

	for _, r := range sharedAccepted + sharedAcceptedUnicode {
		if got := fim.NamePattern.MatchString(string(r)); !got {
			t.Errorf("NamePattern rejected %q (U+%04X), want accepted", r, r)
		}
	}

	for _, r := range sharedRejected + acceptedByDescriptionOnly {
		if got := fim.NamePattern.MatchString(string(r)); got {
			t.Errorf("NamePattern accepted %q (U+%04X), want rejected", r, r)
		}
	}
}

func TestDescriptionPattern(t *testing.T) {
	t.Parallel()

	for _, r := range sharedAccepted + sharedAcceptedUnicode + acceptedByDescriptionOnly {
		if got := fim.DescriptionPattern.MatchString(string(r)); !got {
			t.Errorf("DescriptionPattern rejected %q (U+%04X), want accepted", r, r)
		}
	}

	for _, r := range sharedRejected {
		if got := fim.DescriptionPattern.MatchString(string(r)); got {
			t.Errorf("DescriptionPattern accepted %q (U+%04X), want rejected", r, r)
		}
	}
}

func TestPatternsAnchorWholeString(t *testing.T) {
	t.Parallel()

	// A single bad character anywhere must fail, not just at the boundaries.
	for _, tc := range []string{"—abc", "abc—", "ab—c"} {
		if fim.NamePattern.MatchString(tc) {
			t.Errorf("NamePattern accepted %q, want rejected", tc)
		}
		if fim.DescriptionPattern.MatchString(tc) {
			t.Errorf("DescriptionPattern accepted %q, want rejected", tc)
		}
	}
}

func TestPatternsAcceptEmptyString(t *testing.T) {
	t.Parallel()

	// The API accepts an empty description, and description is Optional.
	if !fim.NamePattern.MatchString("") {
		t.Error("NamePattern rejected the empty string, want accepted")
	}
	if !fim.DescriptionPattern.MatchString("") {
		t.Error("DescriptionPattern rejected the empty string, want accepted")
	}
}

func TestPatternsAcceptRealisticValues(t *testing.T) {
	t.Parallel()

	// The value from the customer report that triggered the 500 (em dash), and the
	// hyphen-minus rewrite that resolves it.
	const broken = "Shared FIM rule group — all four tokenization containers"
	const fixed = "Shared FIM rule group - all four tokenization containers"

	if fim.DescriptionPattern.MatchString(broken) {
		t.Errorf("DescriptionPattern accepted %q, want rejected", broken)
	}
	if !fim.DescriptionPattern.MatchString(fixed) {
		t.Errorf("DescriptionPattern rejected %q, want accepted", fixed)
	}

	// Multi-line descriptions with an email address are accepted by the API.
	const multiline = "Owned by platform-security.\nContact: secops@example.com"
	if !fim.DescriptionPattern.MatchString(multiline) {
		t.Errorf("DescriptionPattern rejected %q, want accepted", multiline)
	}
	if fim.NamePattern.MatchString(multiline) {
		t.Errorf("NamePattern accepted %q, want rejected", multiline)
	}
}

func TestLengthLimitsMatchAPI(t *testing.T) {
	t.Parallel()

	// Observed limits: name 100, description 500. Unlike the character rules the
	// API reports these as a descriptive 400.
	if fim.MaxNameLength != 100 {
		t.Errorf("MaxNameLength = %d, want 100", fim.MaxNameLength)
	}
	if fim.MaxDescriptionLength != 500 {
		t.Errorf("MaxDescriptionLength = %d, want 500", fim.MaxDescriptionLength)
	}

	// A value at the limit must still satisfy the character pattern, so the two
	// validators cannot contradict each other.
	atLimit := strings.Repeat("a", fim.MaxNameLength)
	if !fim.NamePattern.MatchString(atLimit) {
		t.Errorf("NamePattern rejected %d valid characters", len(atLimit))
	}
}

func TestPatternsRejectEveryNonLetterASCIISymbolNotAllowlisted(t *testing.T) {
	t.Parallel()

	// Guard against a future edit widening the class by accident: walk all of
	// printable ASCII and assert the accept set is exactly what the API allows.
	nameAllowed := sharedAccepted
	descAllowed := sharedAccepted + "@"

	for c := 0x20; c < 0x7f; c++ {
		s := string(rune(c))
		wantName := strings.Contains(nameAllowed, s)
		wantDesc := strings.Contains(descAllowed, s)

		if got := fim.NamePattern.MatchString(s); got != wantName {
			t.Errorf("NamePattern.MatchString(%q) = %v, want %v", s, got, wantName)
		}
		if got := fim.DescriptionPattern.MatchString(s); got != wantDesc {
			t.Errorf("DescriptionPattern.MatchString(%q) = %v, want %v", s, got, wantDesc)
		}
	}
}

// stringAttributeValidators pulls the validators off a top-level string attribute
// so the tests below assert the schema wiring, not just the patterns themselves.
func stringAttributeValidators(
	t *testing.T,
	res resource.Resource,
	name string,
) []validator.String {
	t.Helper()

	resp := &resource.SchemaResponse{}
	res.Schema(context.Background(), resource.SchemaRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("building schema: %v", resp.Diagnostics)
	}

	raw, ok := resp.Schema.Attributes[name]
	if !ok {
		t.Fatalf("schema has no attribute %q", name)
	}

	attr, ok := raw.(schema.StringAttribute)
	if !ok {
		t.Fatalf("attribute %q is %T, want schema.StringAttribute", name, raw)
	}

	return attr.Validators
}

// runStringValidators applies every validator and collects the diagnostics, the
// same way the framework does during plan.
func runStringValidators(
	validators []validator.String,
	attribute, value string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	for _, v := range validators {
		resp := &validator.StringResponse{}
		v.ValidateString(
			context.Background(),
			validator.StringRequest{
				Path:        path.Root(attribute),
				ConfigValue: types.StringValue(value),
			},
			resp,
		)
		diags.Append(resp.Diagnostics...)
	}

	return diags
}

// TestSchemaAttributesRejectInvalidValues asserts the validators are attached to
// the four attributes the FileVantage API constrains, and that they are the right
// validators for each field. A regression here means a plan-time error is replaced
// by an opaque HTTP 500 at apply.
func TestSchemaAttributesRejectInvalidValues(t *testing.T) {
	t.Parallel()

	ruleGroup := fim.NewFilevantageRuleGroupResource()
	policy := fim.NewFIMPolicyResource()

	tests := []struct {
		name      string
		res       resource.Resource
		attribute string
		value     string
		wantError bool
	}{
		// rule group name
		{"rule group name valid", ruleGroup, "name", "Prod files - tier [1]", false},
		{"rule group name em dash", ruleGroup, "name", "Prod files — tier 1", true},
		{"rule group name at sign", ruleGroup, "name", "owner@example.com", true},
		{"rule group name newline", ruleGroup, "name", "line one\nline two", true},
		{"rule group name apostrophe", ruleGroup, "name", "don't", true},
		{"rule group name at limit", ruleGroup, "name", strings.Repeat("a", 100), false},
		{"rule group name over limit", ruleGroup, "name", strings.Repeat("a", 101), true},

		// rule group description
		{"rule group desc valid", ruleGroup, "description", "Owned by secops.", false},
		{"rule group desc at sign", ruleGroup, "description", "Contact: a@example.com", false},
		{"rule group desc newline", ruleGroup, "description", "line one\nline two", false},
		{"rule group desc empty", ruleGroup, "description", "", false},
		{"rule group desc em dash", ruleGroup, "description", "tier 1 — prod", true},
		{"rule group desc curly quote", ruleGroup, "description", "don’t", true},
		{"rule group desc at limit", ruleGroup, "description", strings.Repeat("a", 500), false},
		{"rule group desc over limit", ruleGroup, "description", strings.Repeat("a", 501), true},

		// policy name
		{"policy name valid", policy, "name", "Linux prod policy", false},
		{"policy name em dash", policy, "name", "Linux — prod", true},
		{"policy name at sign", policy, "name", "owner@example.com", true},
		{"policy name over limit", policy, "name", strings.Repeat("a", 101), true},

		// policy description
		{"policy desc valid", policy, "description", "Contact: a@example.com", false},
		{"policy desc em dash", policy, "description", "tier 1 — prod", true},
		{"policy desc over limit", policy, "description", strings.Repeat("a", 501), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			validators := stringAttributeValidators(t, tt.res, tt.attribute)
			if len(validators) == 0 {
				t.Fatalf("attribute %q has no validators attached", tt.attribute)
			}

			diags := runStringValidators(validators, tt.attribute, tt.value)
			if got := diags.HasError(); got != tt.wantError {
				t.Errorf(
					"validating %q = error:%v, want error:%v (diags: %v)",
					tt.value,
					got,
					tt.wantError,
					diags,
				)
			}
		})
	}
}

// TestRuleLevelDescriptionIsNotPatternConstrained guards the deliberate decision to
// leave the rule-level description alone. The API accepts characters there that it
// rejects on the rule group itself, so applying the pattern would reject values the
// API stores fine.
func TestRuleLevelDescriptionIsNotPatternConstrained(t *testing.T) {
	t.Parallel()

	resp := &resource.SchemaResponse{}
	fim.NewFilevantageRuleGroupResource().
		Schema(context.Background(), resource.SchemaRequest{}, resp)

	rules, ok := resp.Schema.Attributes["rules"].(schema.ListNestedAttribute)
	if !ok {
		t.Fatalf("rules is %T, want schema.ListNestedAttribute", resp.Schema.Attributes["rules"])
	}

	desc, ok := rules.NestedObject.Attributes["description"].(schema.StringAttribute)
	if !ok {
		t.Fatal("rules.description is not a schema.StringAttribute")
	}

	// An em dash is legal in a rule description even though it is not legal in the
	// rule group description.
	diags := runStringValidators(desc.Validators, "description", "tier 1 — prod")
	if diags.HasError() {
		t.Errorf("rule-level description rejected an em dash, but the API accepts it: %v", diags)
	}
}
