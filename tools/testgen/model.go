package main

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"path"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"unsafe"

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
func (a *attribute) sortedChildren() []*attribute { return sortedAttrs(a.children) }

// sortedAttrs returns attributes ordered by name.
func sortedAttrs(attrs map[string]*attribute) []*attribute {
	return slices.SortedFunc(maps.Values(attrs), func(x, y *attribute) int { return cmp.Compare(x.name, y.name) })
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
		if err := applyValidator(m, v); err != nil {
			return nil, fmt.Errorf("%s: %w", m.dotted(), err)
		}
	}
	for _, pm := range sliceField(a, "PlanModifiers") {
		if err := applyPlanModifier(m, pm); err != nil {
			return nil, fmt.Errorf("%s: %w", m.dotted(), err)
		}
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

const (
	validatorsPkg    = "github.com/hashicorp/terraform-plugin-framework-validators/"
	planModifiersPkg = "github.com/hashicorp/terraform-plugin-framework/resource/schema/"
)

// applyValidator records the facts the generator needs from a
// terraform-plugin-framework-validators validator. Validators are identified
// by concrete type and their values are read from the unexported struct
// fields, so a library change that renames a field fails loudly.
func applyValidator(m *attribute, v any) error {
	t := reflect.TypeOf(v)
	if !strings.HasPrefix(t.PkgPath(), validatorsPkg) {
		return nil
	}
	name := t.Name()
	pkg := path.Base(t.PkgPath())
	num := func(field string) (*float64, error) {
		f, err := readField(v, field)
		if err != nil {
			return nil, err
		}
		n, ok := toFloat(f)
		if !ok {
			return nil, fmt.Errorf("%s.%s.%s is %T, not a number", pkg, name, field, f)
		}
		return &n, nil
	}
	size := func(field string, dst *int) error {
		n, err := num(field)
		if err == nil {
			*dst = int(*n)
		}
		return err
	}

	var err error
	switch {
	case name == "oneOfValidator" || name == "oneOfCaseInsensitiveValidator":
		var f any
		if f, err = readField(v, "values"); err != nil {
			return err
		}
		switch vals := f.(type) {
		case []types.String:
			for _, s := range vals {
				m.enum = append(m.enum, s.ValueString())
			}
		case []types.Int64:
			for _, n := range vals {
				m.intEnum = append(m.intEnum, n.ValueInt64())
			}
		case []types.Int32:
			for _, n := range vals {
				m.intEnum = append(m.intEnum, int64(n.ValueInt32()))
			}
		}
	case name == "noneOfValidator" && pkg != "stringvalidator":
		var f any
		if f, err = readField(v, "values"); err != nil {
			return err
		}
		rv := reflect.ValueOf(f)
		for i := range rv.Len() {
			if n, ok := toFloat(rv.Index(i).Interface()); ok {
				m.exclude = append(m.exclude, n)
			}
		}
	case name == "betweenValidator":
		if m.lo, err = num("min"); err != nil {
			return err
		}
		m.hi, err = num("max")
	case name == "atLeastValidator":
		m.lo, err = num("min")
	case name == "atMostValidator":
		m.hi, err = num("max")
	case name == "sizeAtLeastValidator":
		err = size("min", &m.minSize)
	case name == "sizeAtMostValidator":
		err = size("max", &m.maxSize)
	case name == "sizeBetweenValidator":
		if err = size("min", &m.minSize); err != nil {
			return err
		}
		err = size("max", &m.maxSize)
	case strings.HasPrefix(name, "value") && strings.HasSuffix(name, "sAreValidator"):
		if m.elem == nil {
			return nil
		}
		var f any
		if f, err = readField(v, "elementValidators"); err != nil {
			return err
		}
		rv := reflect.ValueOf(f)
		for i := range rv.Len() {
			if err := applyValidator(m.elem, rv.Index(i).Interface()); err != nil {
				return err
			}
		}
	}
	return err
}

// applyPlanModifier records whether a plan modifier forces replacement.
// RequiresReplace is RequiresReplaceIf with a closure that always returns
// true, so the closure's symbol name is what tells them apart.
func applyPlanModifier(m *attribute, pm any) error {
	t := reflect.TypeOf(pm)
	if !strings.HasPrefix(t.PkgPath(), planModifiersPkg) || t.Name() != "requiresReplaceIfModifier" {
		return nil
	}
	f, err := readField(pm, "ifFunc")
	if err != nil {
		return err
	}
	fn := runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()
	mode := replaceConditional
	if strings.HasPrefix(fn, t.PkgPath()+".RequiresReplace.func") {
		mode = replaceAlways
	}
	m.replace = max(m.replace, mode)
	return nil
}

// readField returns the value of a struct field, exported or not.
func readField(v any, field string) (any, error) {
	rv := reflect.ValueOf(v)
	c := reflect.New(rv.Type()).Elem()
	c.Set(rv)
	f := c.FieldByName(field)
	if !f.IsValid() {
		return nil, fmt.Errorf("%s has no field %q; update testgen for this library version", rv.Type(), field)
	}
	return reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Interface(), nil //nolint:gosec // reading unexported validator fields
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case float32:
		return float64(n), true
	case float64:
		return n, true
	case types.Int32:
		return float64(n.ValueInt32()), true
	case types.Int64:
		return float64(n.ValueInt64()), true
	case types.Float32:
		return float64(n.ValueFloat32()), true
	case types.Float64:
		return n.ValueFloat64(), true
	}
	return 0, false
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
