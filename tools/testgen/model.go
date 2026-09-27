package main

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

type kind int

const (
	kindUnsupported kind = iota
	kindString
	kindBool
	kindInt64
	kindInt32
	kindFloat64
	kindFloat32
	kindList
	kindSet
	kindObject
)

type replaceMode int

const (
	replaceNever replaceMode = iota
	replaceAlways
	// replaceConditional is a RequiresReplaceIf with provider-defined logic the
	// generator cannot evaluate, so plan actions on this attribute are not asserted.
	replaceConditional
)

// requiresReplaceDescription is the description of the unconditional
// RequiresReplace plan modifier in every *planmodifier package. RequiresReplaceIf
// shares its concrete type, so the description is what tells them apart.
const requiresReplaceDescription = "If the value of this attribute changes, Terraform will destroy and recreate the resource."

// attribute is the generator's view of one schema attribute.
type attribute struct {
	name string
	path []string

	kind        kind
	unsupported string // reason, when kind is kindUnsupported

	elem     *attribute            // list and set element
	children map[string]*attribute // object attributes

	required, optional, computed bool
	deprecated, writeOnly        bool

	enum     []string
	intEnum  []int64
	lo, hi   *float64
	exclude  []float64 // numeric NoneOf values
	minSize  int
	maxSize  int // 0 means no limit
	replace  replaceMode
	defaults *value
}

func (a *attribute) settable() bool { return a.required || a.optional }

func (a *attribute) computedOnly() bool { return a.computed && !a.optional && !a.required }

func (a *attribute) dotted() string { return strings.Join(a.path, ".") }

// sortedChildren returns object children ordered by name.
func (a *attribute) sortedChildren() []*attribute {
	out := make([]*attribute, 0, len(a.children))
	for _, c := range a.children {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func buildAttributes(ctx context.Context, attrs map[string]schema.Attribute, parent []string) (map[string]*attribute, error) {
	out := make(map[string]*attribute, len(attrs))
	for name, a := range attrs {
		m, err := buildAttribute(ctx, name, a, parent)
		if err != nil {
			return nil, err
		}
		out[name] = m
	}
	return out, nil
}

func buildAttribute(ctx context.Context, name string, a schema.Attribute, parent []string) (*attribute, error) {
	m := &attribute{
		name:       name,
		path:       append(append([]string{}, parent...), name),
		required:   a.IsRequired(),
		optional:   a.IsOptional(),
		computed:   a.IsComputed(),
		deprecated: a.GetDeprecationMessage() != "",
		writeOnly:  a.IsWriteOnly(),
	}

	switch t := a.(type) {
	case schema.StringAttribute:
		m.kind = kindString
	case schema.BoolAttribute:
		m.kind = kindBool
	case schema.Int64Attribute:
		m.kind = kindInt64
	case schema.Int32Attribute:
		m.kind = kindInt32
	case schema.Float64Attribute:
		m.kind = kindFloat64
	case schema.Float32Attribute:
		m.kind = kindFloat32
	case schema.ListAttribute:
		m.kind = kindList
		m.elem = elementAttribute(t.ElementType, m.path)
	case schema.SetAttribute:
		m.kind = kindSet
		m.elem = elementAttribute(t.ElementType, m.path)
	case schema.SingleNestedAttribute:
		m.kind = kindObject
		children, err := buildAttributes(ctx, t.Attributes, m.path)
		if err != nil {
			return nil, err
		}
		m.children = children
	case schema.ListNestedAttribute:
		m.kind = kindList
		elem, err := nestedElement(ctx, t.NestedObject, m.path)
		if err != nil {
			return nil, err
		}
		m.elem = elem
	case schema.SetNestedAttribute:
		m.kind = kindSet
		elem, err := nestedElement(ctx, t.NestedObject, m.path)
		if err != nil {
			return nil, err
		}
		m.elem = elem
	default:
		m.unsupported = fmt.Sprintf("%T attributes are not supported yet", a)
	}
	if m.elem != nil && m.elem.kind == kindUnsupported {
		m.unsupported = m.elem.unsupported
	}
	if m.unsupported != "" {
		m.kind = kindUnsupported
	}

	for _, v := range sliceField(a, "Validators") {
		applyValidator(ctx, m, v)
	}
	for _, pm := range sliceField(a, "PlanModifiers") {
		applyPlanModifier(ctx, m, pm)
	}
	if m.kind != kindUnsupported {
		d, err := defaultValue(ctx, m, a)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", m.dotted(), err)
		}
		m.defaults = d
	}
	return m, nil
}

// elementAttribute models the element of a list or set of primitives.
func elementAttribute(t attr.Type, parent []string) *attribute {
	e := &attribute{name: parent[len(parent)-1], path: parent, required: true}
	switch t.(type) {
	case basetypes.StringTypable:
		e.kind = kindString
	case basetypes.BoolTypable:
		e.kind = kindBool
	case basetypes.Int64Typable:
		e.kind = kindInt64
	case basetypes.Int32Typable:
		e.kind = kindInt32
	case basetypes.Float64Typable:
		e.kind = kindFloat64
	case basetypes.Float32Typable:
		e.kind = kindFloat32
	default:
		e.unsupported = fmt.Sprintf("collections of %s are not supported yet", t)
	}
	return e
}

func nestedElement(ctx context.Context, obj schema.NestedAttributeObject, parent []string) (*attribute, error) {
	children, err := buildAttributes(ctx, obj.Attributes, parent)
	if err != nil {
		return nil, err
	}
	return &attribute{
		name:     parent[len(parent)-1],
		path:     parent,
		kind:     kindObject,
		required: true,
		children: children,
	}, nil
}

// sliceField reads a slice field such as Validators or PlanModifiers from any
// schema attribute struct.
func sliceField(a any, name string) []any {
	f := reflect.ValueOf(a).FieldByName(name)
	if !f.IsValid() || f.Kind() != reflect.Slice {
		return nil
	}
	out := make([]any, f.Len())
	for i := range out {
		out[i] = f.Index(i).Interface()
	}
	return out
}

type describer interface {
	Description(context.Context) string
}

var (
	quotedRE     = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
	oneOfRE      = regexp.MustCompile(`value must be one of: \[([^\]]*)\]`)
	noneOfRE     = regexp.MustCompile(`value must be none of: \[([^\]]*)\]`)
	betweenRE    = regexp.MustCompile(`^value must be between (\S+) and (\S+)$`)
	atLeastRE    = regexp.MustCompile(`^value must be at least (\S+)$`)
	atMostRE     = regexp.MustCompile(`^value must be at most (\S+)$`)
	sizeAtLeast  = regexp.MustCompile(`must contain at least (\d+) elements`)
	sizeAtMostRE = regexp.MustCompile(`at most (\d+) elements`)
)

// applyValidator records the facts the generator needs from a validator.
// Validators are identified by concrete type; their values come from the
// description because the fields holding them are unexported.
func applyValidator(ctx context.Context, m *attribute, v any) {
	d, ok := v.(describer)
	if !ok {
		return
	}
	desc := d.Description(ctx)
	typ := fmt.Sprintf("%T", v)

	switch {
	case typ == "stringvalidator.oneOfValidator" || typ == "stringvalidator.oneOfCaseInsensitiveValidator":
		m.enum = parseQuoted(desc)
	case typ == "int64validator.oneOfValidator" || typ == "int32validator.oneOfValidator":
		for _, s := range parseQuoted(desc) {
			if n, err := strconv.ParseInt(s, 10, 64); err == nil {
				m.intEnum = append(m.intEnum, n)
			}
		}
	case strings.HasSuffix(typ, "validator.noneOfValidator") && typ != "stringvalidator.noneOfValidator":
		if g := noneOfRE.FindStringSubmatch(desc); g != nil {
			for _, q := range parseQuoted(g[0]) {
				if f := parseFloat(q); f != nil {
					m.exclude = append(m.exclude, *f)
				}
			}
		}
	case strings.HasSuffix(typ, "validator.betweenValidator"):
		if g := betweenRE.FindStringSubmatch(desc); g != nil {
			m.lo, m.hi = parseFloat(g[1]), parseFloat(g[2])
		}
	case strings.HasSuffix(typ, "validator.atLeastValidator"):
		if g := atLeastRE.FindStringSubmatch(desc); g != nil {
			m.lo = parseFloat(g[1])
		}
	case strings.HasSuffix(typ, "validator.atMostValidator"):
		if g := atMostRE.FindStringSubmatch(desc); g != nil {
			m.hi = parseFloat(g[1])
		}
	case strings.HasSuffix(typ, "validator.sizeAtLeastValidator"),
		strings.HasSuffix(typ, "validator.sizeAtMostValidator"),
		strings.HasSuffix(typ, "validator.sizeBetweenValidator"):
		if g := sizeAtLeast.FindStringSubmatch(desc); g != nil {
			m.minSize, _ = strconv.Atoi(g[1])
		}
		if g := sizeAtMostRE.FindStringSubmatch(desc); g != nil {
			m.maxSize, _ = strconv.Atoi(g[1])
		}
	case strings.HasSuffix(typ, "validator.valueStringsAreValidator"):
		if m.elem != nil {
			if g := oneOfRE.FindStringSubmatch(desc); g != nil {
				m.elem.enum = parseQuoted(g[0])
			}
		}
	}
}

func applyPlanModifier(ctx context.Context, m *attribute, pm any) {
	if !strings.HasSuffix(fmt.Sprintf("%T", pm), "planmodifier.requiresReplaceIfModifier") {
		return
	}
	mode := replaceConditional
	if d, ok := pm.(describer); ok && d.Description(ctx) == requiresReplaceDescription {
		mode = replaceAlways
	}
	if mode > m.replace {
		m.replace = mode
	}
}

func parseQuoted(s string) []string {
	var out []string
	for _, q := range quotedRE.FindAllString(s, -1) {
		if u, err := strconv.Unquote(q); err == nil {
			out = append(out, u)
		}
	}
	return out
}

func parseFloat(s string) *float64 {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil
	}
	return &f
}

// defaultValue evaluates the attribute's Default, if any. Every defaults.X
// interface has a single Default<X>(ctx, req, *resp) method whose response
// carries a PlanValue, so it is called by reflection.
func defaultValue(ctx context.Context, m *attribute, a schema.Attribute) (*value, error) {
	f := reflect.ValueOf(a).FieldByName("Default")
	if !f.IsValid() || f.IsNil() {
		return nil, nil
	}
	d := f.Elem()
	var method reflect.Value
	for i := 0; i < d.NumMethod(); i++ {
		if name := d.Type().Method(i).Name; strings.HasPrefix(name, "Default") {
			method = d.Method(i)
		}
	}
	if !method.IsValid() {
		return nil, fmt.Errorf("default %T has no Default method", d.Interface())
	}
	req := reflect.New(method.Type().In(1)).Elem()
	resp := reflect.New(method.Type().In(2).Elem())
	method.Call([]reflect.Value{reflect.ValueOf(ctx), req, resp})
	pv, ok := resp.Elem().FieldByName("PlanValue").Interface().(attr.Value)
	if !ok {
		return nil, fmt.Errorf("default %T returned no PlanValue", d.Interface())
	}
	v, err := fromFramework(ctx, m, pv)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// fromFramework converts a framework value into a generator value.
func fromFramework(ctx context.Context, m *attribute, v attr.Value) (value, error) {
	if v.IsNull() {
		return value{null: true}, nil
	}
	switch t := v.(type) {
	case types.String:
		return value{str: t.ValueString()}, nil
	case types.Bool:
		return value{prim: t.ValueBool()}, nil
	case types.Int64:
		return value{prim: t.ValueInt64()}, nil
	case types.Int32:
		return value{prim: int64(t.ValueInt32())}, nil
	case types.Float64:
		return value{prim: t.ValueFloat64()}, nil
	case types.Float32:
		return value{prim: float64(t.ValueFloat32())}, nil
	case types.List:
		return elementsFrom(ctx, m, t.Elements())
	case types.Set:
		return elementsFrom(ctx, m, t.Elements())
	case types.Object:
		out := value{fields: map[string]value{}}
		for k, child := range t.Attributes() {
			if child.IsNull() {
				continue
			}
			c, err := fromFramework(ctx, m.children[k], child)
			if err != nil {
				return value{}, err
			}
			out.fields[k] = c
		}
		return out, nil
	}
	return value{}, fmt.Errorf("unsupported default value type %T", v)
}

func elementsFrom(ctx context.Context, m *attribute, elems []attr.Value) (value, error) {
	out := value{elems: []value{}}
	for _, e := range elems {
		c, err := fromFramework(ctx, m.elem, e)
		if err != nil {
			return value{}, err
		}
		out.elems = append(out.elems, c)
	}
	return out, nil
}
