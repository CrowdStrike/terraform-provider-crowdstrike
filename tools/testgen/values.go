package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/testgen"
)

// value is a test value for an attribute. How it is read depends on the
// attribute's kind: strings use str (appended to rName when rName is set),
// bools and numbers use prim, lists and sets use elems, objects use fields.
type value struct {
	null   bool
	str    string
	rName  bool
	prim   any // bool, int64, or float64
	elems  []value
	fields map[string]value
}

var rNameValues = []value{{rName: true}, {rName: true, str: "-updated"}}

// pools resolves value pools for attributes, preferring spec values and
// falling back to what the schema implies.
type pools struct {
	spec    map[string]testgen.Attribute
	missing map[string]bool
}

func newPools(spec map[string]testgen.Attribute) *pools {
	return &pools{spec: spec, missing: map[string]bool{}}
}

// missingPaths lists the attributes that needed values the generator could
// not derive and the spec did not supply.
func (p *pools) missingPaths() []string {
	out := make([]string, 0, len(p.missing))
	for k := range p.missing {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// pool returns the values an attribute draws from. For lists and sets it
// returns the element pool. It records the attribute as missing and returns
// nil when no values are available.
func (p *pools) pool(a *attribute) ([]value, error) {
	if s, ok := p.spec[a.dotted()]; ok && len(s.Values) > 0 {
		target := a
		if a.kind == kindList || a.kind == kindSet {
			target = a.elem
		}
		out := make([]value, 0, len(s.Values))
		for _, raw := range s.Values {
			v, err := convertSpec(target, raw)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", a.dotted(), err)
			}
			out = append(out, v)
		}
		return dedupe(target, out), nil
	}

	switch a.kind {
	case kindString:
		switch {
		case len(a.enum) > 0:
			out := make([]value, len(a.enum))
			for i, e := range a.enum {
				out[i] = value{str: e}
			}
			return out, nil
		case a.name == "name" || a.name == "description":
			return rNameValues, nil
		}
	case kindBool:
		return []value{{prim: true}, {prim: false}}, nil
	case kindInt64, kindInt32:
		if len(a.intEnum) > 0 {
			out := make([]value, len(a.intEnum))
			for i, n := range a.intEnum {
				out[i] = value{prim: n}
			}
			return out, nil
		}
		if lo, hi, ok := bounds(a, 1); ok {
			return dedupe(a, []value{{prim: int64(lo)}, {prim: int64(hi)}}), nil
		}
	case kindFloat64, kindFloat32:
		if lo, hi, ok := bounds(a, 1); ok {
			return dedupe(a, []value{{prim: lo}, {prim: hi}}), nil
		}
	case kindList, kindSet:
		return p.pool(a.elem)
	case kindObject:
		return p.objectPool(a)
	}
	p.missing[a.dotted()] = true
	return nil, nil
}

// bounds returns two values inside the attribute's numeric range. With only
// one bound it steps by step away from it. Values excluded by a NoneOf
// validator are stepped past toward the other bound.
func bounds(a *attribute, step float64) (float64, float64, bool) {
	var lo, hi float64
	switch {
	case a.lo != nil && a.hi != nil:
		lo, hi = *a.lo, *a.hi
	case a.lo != nil:
		lo, hi = *a.lo, *a.lo+step
	case a.hi != nil:
		lo, hi = *a.hi-step, *a.hi
	default:
		return 0, 0, false
	}
	for excluded(a, lo) && lo < hi {
		lo += step
	}
	for excluded(a, hi) && hi > lo {
		hi -= step
	}
	return lo, hi, !excluded(a, lo)
}

func excluded(a *attribute, f float64) bool {
	for _, e := range a.exclude {
		if e == f {
			return true
		}
	}
	return false
}

// objectPool builds object values from the object's required children, or
// from its first settable child when none are required.
func (p *pools) objectPool(a *attribute) ([]value, error) {
	var chosen []*attribute
	for _, c := range a.sortedChildren() {
		if c.required {
			chosen = append(chosen, c)
		}
	}
	if len(chosen) == 0 {
		for _, c := range a.sortedChildren() {
			if c.optional && c.kind != kindUnsupported && !c.deprecated && !c.writeOnly {
				chosen = append(chosen, c)
				break
			}
		}
	}

	childPools := map[string][]value{}
	size := 1
	for _, c := range chosen {
		if c.kind == kindUnsupported {
			return nil, fmt.Errorf("%s: required attribute: %s", c.dotted(), c.unsupported)
		}
		cp, err := p.pool(c)
		if err != nil {
			return nil, err
		}
		if cp == nil {
			continue
		}
		if c.kind == kindList || c.kind == kindSet {
			cp = []value{collectionOf(c, cp)}
		}
		childPools[c.name] = cp
		size = max(size, len(cp))
	}
	if len(childPools) < len(chosen) {
		return nil, nil
	}

	out := make([]value, size)
	for i := range out {
		fields := map[string]value{}
		for name, cp := range childPools {
			fields[name] = cp[i%len(cp)]
		}
		out[i] = value{fields: fields}
	}
	return dedupe(a, out), nil
}

// collectionOf returns the smallest valid collection from an element pool.
func collectionOf(a *attribute, pool []value) value {
	n := max(a.minSize, 1)
	n = min(n, len(pool))
	return value{elems: append([]value{}, pool[:n]...)}
}

func dedupe(a *attribute, vs []value) []value {
	var out []value
	for _, v := range vs {
		seen := false
		for _, o := range out {
			if equal(a, v, o) {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, v)
		}
	}
	return out
}

func convertSpec(a *attribute, raw any) (value, error) {
	switch a.kind {
	case kindString:
		s, ok := raw.(string)
		if !ok {
			return value{}, fmt.Errorf("want string value, got %T", raw)
		}
		return value{str: s}, nil
	case kindBool:
		b, ok := raw.(bool)
		if !ok {
			return value{}, fmt.Errorf("want bool value, got %T", raw)
		}
		return value{prim: b}, nil
	case kindInt64, kindInt32:
		switch n := raw.(type) {
		case int:
			return value{prim: int64(n)}, nil
		case int64:
			return value{prim: n}, nil
		case int32:
			return value{prim: int64(n)}, nil
		}
		return value{}, fmt.Errorf("want integer value, got %T", raw)
	case kindFloat64, kindFloat32:
		switch n := raw.(type) {
		case float64:
			return value{prim: n}, nil
		case int:
			return value{prim: float64(n)}, nil
		}
		return value{}, fmt.Errorf("want float value, got %T", raw)
	case kindList, kindSet:
		items, ok := raw.([]any)
		if !ok {
			return value{}, fmt.Errorf("want []any value, got %T", raw)
		}
		out := value{elems: []value{}}
		for _, item := range items {
			e, err := convertSpec(a.elem, item)
			if err != nil {
				return value{}, err
			}
			out.elems = append(out.elems, e)
		}
		return out, nil
	case kindObject:
		obj, ok := raw.(map[string]any)
		if !ok {
			return value{}, fmt.Errorf("want map[string]any value, got %T", raw)
		}
		out := value{fields: map[string]value{}}
		for k, item := range obj {
			c, ok := a.children[k]
			if !ok || !c.settable() {
				return value{}, fmt.Errorf("%q is not a settable attribute", k)
			}
			v, err := convertSpec(c, item)
			if err != nil {
				return value{}, fmt.Errorf("%s: %w", k, err)
			}
			out.fields[k] = v
		}
		return out, nil
	}
	return value{}, fmt.Errorf("%s attributes are not supported", a.dotted())
}

func equal(a *attribute, x, y value) bool {
	if x.null || y.null {
		return x.null == y.null
	}
	switch a.kind {
	case kindString:
		return x.str == y.str && x.rName == y.rName
	case kindList:
		if len(x.elems) != len(y.elems) {
			return false
		}
		for i := range x.elems {
			if !equal(a.elem, x.elems[i], y.elems[i]) {
				return false
			}
		}
		return true
	case kindSet:
		if len(x.elems) != len(y.elems) {
			return false
		}
		for _, xe := range x.elems {
			found := false
			for _, ye := range y.elems {
				if equal(a.elem, xe, ye) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	case kindObject:
		keys := map[string]bool{}
		for k := range x.fields {
			keys[k] = true
		}
		for k := range y.fields {
			keys[k] = true
		}
		for k := range keys {
			xv, xok := x.fields[k]
			yv, yok := y.fields[k]
			if !xok {
				xv = value{null: true}
			}
			if !yok {
				yv = value{null: true}
			}
			if !equal(a.children[k], xv, yv) {
				return false
			}
		}
		return true
	}
	return x.prim == y.prim
}

type action int

const (
	actionNone action = iota
	actionUpdate
	actionReplace
	// actionUnknown means a conditional plan modifier decides, so no plan check is emitted.
	actionUnknown
)

// change returns the plan action for moving an attribute from x to y.
func change(a *attribute, x, y value) action {
	if equal(a, x, y) {
		return actionNone
	}
	switch a.replace {
	case replaceAlways:
		return actionReplace
	case replaceConditional:
		return actionUnknown
	}
	switch a.kind {
	case kindObject:
		if x.null || y.null {
			return worst(actionUpdate, subtreeReplace(a))
		}
		out := actionUpdate
		for name, c := range a.children {
			xv, ok := x.fields[name]
			if !ok {
				xv = value{null: true}
			}
			yv, ok := y.fields[name]
			if !ok {
				yv = value{null: true}
			}
			if ch := change(c, xv, yv); ch != actionNone {
				out = worst(out, ch)
			}
		}
		return out
	case kindList, kindSet:
		return worst(actionUpdate, subtreeReplace(a.elem))
	}
	return actionUpdate
}

// subtreeReplace reports actionUnknown when any descendant can force
// replacement, because which one changes is not tracked across elements.
func subtreeReplace(a *attribute) action {
	if a == nil {
		return actionUpdate
	}
	if a.replace != replaceNever {
		return actionUnknown
	}
	for _, c := range a.children {
		if subtreeReplace(c) == actionUnknown {
			return actionUnknown
		}
	}
	return subtreeReplace(a.elem)
}

func worst(x, y action) action {
	if x == actionUnknown || y == actionUnknown {
		return actionUnknown
	}
	return max(x, y)
}

// camel converts an attribute name to the test suffix form: host_groups -> hostGroups.
func camel(name string) string {
	parts := strings.Split(name, "_")
	for i := 1; i < len(parts); i++ {
		if parts[i] != "" {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, "")
}
