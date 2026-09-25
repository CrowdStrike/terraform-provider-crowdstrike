package fusionsoar

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"gopkg.in/yaml.v3"
)

var (
	_ basetypes.StringTypable                    = definitionType{}
	_ basetypes.StringValuableWithSemanticEquals = definitionValue{}
)

// definitionType is the attribute type for a workflow definition YAML document.
//
// The Fusion SOAR API rewrites a stored definition: it re-indents it, reorders
// keys, prefixes a comment header, adds keys the user never wrote (every
// action gains default_name, and actions without a name gain one), and
// replaces the trigger's name and each action's default_name with its own.
// Semantic equality therefore treats the API's copy as equal to the configured
// copy when every configured value is present in it, ignoring keys only the
// API sets and the values it replaces.
type definitionType struct {
	basetypes.StringType
}

func (t definitionType) String() string {
	return "fusionsoar.definitionType"
}

func (t definitionType) ValueType(_ context.Context) attr.Value {
	return definitionValue{}
}

func (t definitionType) Equal(o attr.Type) bool {
	other, ok := o.(definitionType)
	if !ok {
		return false
	}

	return t.StringType.Equal(other.StringType)
}

func (t definitionType) ValueFromString(_ context.Context, in basetypes.StringValue) (basetypes.StringValuable, diag.Diagnostics) {
	return definitionValue{StringValue: in}, nil
}

func (t definitionType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	attrValue, err := t.StringType.ValueFromTerraform(ctx, in)
	if err != nil {
		return nil, err
	}

	stringValue, ok := attrValue.(basetypes.StringValue)
	if !ok {
		return nil, fmt.Errorf("unexpected value type of %T", attrValue)
	}

	stringValuable, diags := t.ValueFromString(ctx, stringValue)
	if diags.HasError() {
		return nil, fmt.Errorf("unexpected error converting StringValue to StringValuable: %v", diags)
	}

	return stringValuable, nil
}

// definitionValue is a workflow definition YAML document.
type definitionValue struct {
	basetypes.StringValue
}

func newDefinitionValue(s string) definitionValue {
	return definitionValue{StringValue: basetypes.NewStringValue(s)}
}

func (v definitionValue) Type(_ context.Context) attr.Type {
	return definitionType{}
}

func (v definitionValue) Equal(o attr.Value) bool {
	other, ok := o.(definitionValue)
	if !ok {
		return false
	}

	return v.StringValue.Equal(other.StringValue)
}

// StringSemanticEquals reports whether v contains every value set in
// priorValuable. The framework calls it on the value returned by the API, with
// the prior state or plan as priorValuable, and keeps the prior value when this
// returns true. Keys the API adds are therefore ignored, while a changed or
// missing configured value is reported as a difference.
func (v definitionValue) StringSemanticEquals(_ context.Context, priorValuable basetypes.StringValuable) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics

	priorValue, ok := priorValuable.(definitionValue)
	if !ok {
		diags.AddError(
			"Semantic Equality Check Error",
			fmt.Sprintf("An unexpected value type was received while performing semantic equality checks. Please report this to the provider developers.\n\nExpected Value Type: %T\nGot Value Type: %T", v, priorValuable),
		)
		return false, diags
	}

	if v.ValueString() == priorValue.ValueString() {
		return true, diags
	}

	mismatch, err := definitionDiff(priorValue.ValueString(), v.ValueString())
	if err != nil {
		return false, diags
	}

	return mismatch == nil, diags
}

// parseDefinition decodes a workflow definition YAML document. The top level
// must be a mapping.
func parseDefinition(definition string) (map[string]any, error) {
	var doc any
	if err := yaml.Unmarshal([]byte(definition), &doc); err != nil {
		return nil, fmt.Errorf("definition is not valid YAML: %w", err)
	}

	mapping, ok := stringKeys(doc).(map[string]any)
	if !ok {
		return nil, fmt.Errorf("definition must be a YAML mapping at the top level")
	}

	return mapping, nil
}

// stringKeys converts every mapping in v to map[string]any, the only mapping
// type valueDiff compares key by key. yaml.v3 decodes a mapping with any
// non-string key, such as `1:`, as map[any]any.
func stringKeys(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			t[k] = stringKeys(child)
		}
		return t
	case map[any]any:
		m := make(map[string]any, len(t))
		for k, child := range t {
			m[fmt.Sprint(k)] = stringKeys(child)
		}
		return m
	case []any:
		for i, child := range t {
			t[i] = stringKeys(child)
		}
		return t
	default:
		return v
	}
}

// definitionWithID returns the definition with its top-level `id` set to id,
// which the update endpoint requires in the body. An existing top-level `id`
// is replaced. Everything else in the document is kept as written.
func definitionWithID(definition, id string) (string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(definition), &doc); err != nil {
		return "", fmt.Errorf("definition is not valid YAML: %w", err)
	}

	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return "", fmt.Errorf("definition must be a YAML mapping at the top level")
	}
	root := doc.Content[0]

	idValue := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: id}
	replaced := false
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "id" {
			root.Content[i+1] = idValue
			replaced = true
			break
		}
	}
	if !replaced {
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "id"}, idValue)
	}

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return "", fmt.Errorf("encoding definition: %w", err)
	}
	return string(out), nil
}

// definitionMismatch is the first configured value a stored definition does
// not contain.
type definitionMismatch struct {
	path       string
	configured any
	stored     any
	// missing is set when the stored definition does not have the key at all.
	missing bool
}

// detail describes the mismatch for a diagnostic.
func (m definitionMismatch) detail() string {
	if m.missing {
		return fmt.Sprintf("The API did not store `%s`, which the configuration sets. The API drops keys it does not recognize, so check that the key is spelled correctly and is valid at that location.", m.path)
	}

	return fmt.Sprintf("The API stored a different value at `%s` than the configuration sets.\n\nConfigured:\n%s\n\nStored:\n%s", m.path, formatValue(m.configured), formatValue(m.stored))
}

func formatValue(v any) string {
	out, err := yaml.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return strings.TrimSpace(string(out))
}

// definitionDiff returns the first value in want that got does not contain, or
// nil when got contains all of want. Keys present only in got are ignored, as
// are the values the API sets itself (see apiOwned).
func definitionDiff(want, got string) (*definitionMismatch, error) {
	wantDoc, err := parseDefinition(want)
	if err != nil {
		return nil, err
	}

	gotDoc, err := parseDefinition(got)
	if err != nil {
		return nil, err
	}

	return valueDiff(wantDoc, gotDoc, nil), nil
}

// apiOwned reports whether key, in the mapping at path, is a value the API
// sets itself, replacing whatever the definition gives: the trigger's display
// name, which the API derives from the trigger, and each action's
// default_name, which is the activity's display name.
func apiOwned(path []string, key string) bool {
	switch key {
	case "name":
		return slices.Equal(path, []string{"trigger"})
	case "default_name":
		return len(path) >= 2 && path[len(path)-2] == "actions"
	default:
		return false
	}
}

func valueDiff(want, got any, path []string) *definitionMismatch {
	mismatch := func() *definitionMismatch {
		return &definitionMismatch{path: formatPath(path), configured: want, stored: got}
	}

	switch w := want.(type) {
	case nil:
		return nil
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return mismatch()
		}

		for _, k := range slices.Sorted(maps.Keys(w)) {
			if apiOwned(path, k) {
				continue
			}
			childPath := append(slices.Clip(path), k)
			gv, ok := g[k]
			if !ok {
				if isEmpty(w[k]) {
					continue
				}
				return &definitionMismatch{path: formatPath(childPath), missing: true}
			}
			if m := valueDiff(w[k], gv, childPath); m != nil {
				return m
			}
		}
		return nil
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return mismatch()
		}

		for i := range w {
			if m := valueDiff(w[i], g[i], append(slices.Clip(path), fmt.Sprintf("[%d]", i))); m != nil {
				return m
			}
		}
		return nil
	default:
		if scalarsEqual(want, got) {
			return nil
		}
		return mismatch()
	}
}

// isEmpty reports whether a configured value carries no data, so an API that
// omits the key is treated as matching it.
func isEmpty(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case map[string]any:
		return len(t) == 0
	case []any:
		return len(t) == 0
	default:
		return false
	}
}

func scalarsEqual(a, b any) bool {
	if af, ok := toFloat(a); ok {
		bf, ok := toFloat(b)
		return ok && af == bf
	}

	return reflect.DeepEqual(a, b)
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint64:
		return float64(n), true
	case float64:
		return n, true
	default:
		return 0, false
	}
}

// formatPath renders a path such as actions.Sleep.next[0].
func formatPath(path []string) string {
	var b strings.Builder
	for i, segment := range path {
		if i > 0 && !strings.HasPrefix(segment, "[") {
			b.WriteByte('.')
		}
		b.WriteString(segment)
	}
	return b.String()
}
