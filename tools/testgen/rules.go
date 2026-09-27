package main

import (
	"fmt"
	"sort"
)

// testCase is one generated test function.
type testCase struct {
	name   string // TestAccCIDGroupResource_basic
	suffix string // basic
	skip   string // t.Skip reason; a skipped case has no steps or testdata
	note   string // comment emitted above the test function
	attr   string // attribute under test; empty for basic
	vars   []*attribute
	steps  []step
}

type checkKind int

const (
	checkExact checkKind = iota
	checkNull
	checkNotNull
	checkEmpty
)

type check struct {
	attr *attribute
	kind checkKind
	v    value
}

type step struct {
	values map[string]value // variable values by attribute name; absent means null
	checks []check
	// planned is the plan action to assert before apply. It is ignored on
	// the first step, which always creates.
	planned action
	// importState makes this an import step verifying the prior step's state.
	importState bool
	// omit marks the step that removes the attribute under test.
	omit bool
	// disappears deletes the resource outside Terraform after apply and
	// expects the refreshed plan to recreate it.
	disappears bool
}

// buildCases returns every test case for a resource.
func buildCases(r *resourceInfo) ([]testCase, error) {
	p := newPools(r.spec.Attributes)

	base, err := requiredValues(r, p, "")
	if err != nil {
		return nil, err
	}
	if err := applySpecValues(r, "Base", r.spec.Base, base); err != nil {
		return nil, err
	}

	known := map[string]bool{"basic": true}
	cases := []testCase{basicCase(r, base)}
	if c, ok := disappearsCase(r, base); ok {
		known[c.suffix] = true
		cases = append(cases, c)
	}
	for _, sub := range subjects(r, p, base) {
		known[sub.suffix] = true
		// Skipped cases never resolve values, so a Skip entry is enough for
		// attributes the generator cannot handle yet.
		if _, ok := r.spec.Skip[sub.suffix]; ok {
			cases = append(cases, testCase{name: r.testPrefix + "_" + sub.suffix, suffix: sub.suffix})
			continue
		}
		c, err := attributeCase(r, p, base, sub)
		if err != nil {
			return nil, err
		}
		cases = append(cases, c)
	}

	for suffix, reason := range r.spec.Skip {
		if !known[suffix] {
			return nil, fmt.Errorf("%s: Skip names unknown test suffix %q", r.typeName, suffix)
		}
		for i := range cases {
			if cases[i].suffix == suffix {
				cases[i] = testCase{name: cases[i].name, suffix: suffix, skip: reason}
			}
		}
	}

	if missing := p.missingPaths(); len(missing) > 0 {
		return nil, fmt.Errorf("%s: no test values for %v; add them to Attributes in %s/testgen.go", r.typeName, missing, r.dir)
	}
	return cases, nil
}

func topLevel(attrs map[string]*attribute) []*attribute {
	out := make([]*attribute, 0, len(attrs))
	for _, a := range attrs {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// requiredValues picks the first value of every required attribute except
// the one named by exclude.
func requiredValues(r *resourceInfo, p *pools, exclude string) (map[string]value, error) {
	out := map[string]value{}
	for _, a := range topLevel(r.attrs) {
		if !a.required || a.name == exclude {
			continue
		}
		if a.kind == kindUnsupported {
			return nil, fmt.Errorf("%s: required attribute %s: %s", r.typeName, a.name, a.unsupported)
		}
		pool, err := p.pool(a)
		if err != nil {
			return nil, err
		}
		if len(pool) == 0 {
			continue
		}
		if a.kind == kindList || a.kind == kindSet {
			out[a.name] = collectionOf(a, pool)
		} else {
			out[a.name] = pool[0]
		}
	}
	return out, nil
}

// basicCase sets only required attributes, checks every computed-only
// attribute is populated, and verifies import.
func basicCase(r *resourceInfo, base map[string]value) testCase {
	c := testCase{name: r.testPrefix + "_basic", suffix: "basic", vars: varsFor(r, base)}
	first := step{values: base}
	for _, a := range topLevel(r.attrs) {
		if a.computedOnly() {
			first.checks = append(first.checks, check{attr: a, kind: checkNotNull})
		}
	}
	c.steps = append(c.steps, first)
	if r.importable {
		c.steps = append(c.steps, step{values: base, importState: true})
	}
	return c
}

// disappearsCase applies the _basic config, deletes the resource outside
// Terraform, and expects a plan to recreate it rather than a Read error.
func disappearsCase(r *resourceInfo, base map[string]value) (testCase, bool) {
	if r.spec.NoDisappears {
		return testCase{}, false
	}
	return testCase{
		name:   r.testPrefix + "_disappears",
		suffix: "disappears",
		vars:   varsFor(r, base),
		steps:  []step{{values: base, disappears: true}},
	}, true
}

// subject is an attribute that gets its own test: a top-level attribute, or
// an optional child of a top-level single nested attribute. Required children
// are covered by their parent's test.
type subject struct {
	attr   *attribute // attribute under test
	top    *attribute // top-level attribute holding it; attr itself when top-level
	suffix string     // test name suffix
	// parent is the value the parent object keeps while a child is tested.
	parent *value
}

// wrap returns the top-level value for a subject value; nil omits it.
func (s subject) wrap(v *value) *value {
	if s.parent == nil {
		return v
	}
	obj := value{fields: map[string]value{}}
	for k, f := range s.parent.fields {
		obj.fields[k] = f
	}
	if v != nil {
		obj.fields[s.attr.name] = *v
	} else {
		delete(obj.fields, s.attr.name)
	}
	return &obj
}

// subjects returns every attribute that gets its own test, in name order.
func subjects(r *resourceInfo, p *pools, base map[string]value) []subject {
	var out []subject
	for _, a := range topLevel(r.attrs) {
		if !a.settable() || a.deprecated {
			continue
		}
		out = append(out, subject{attr: a, top: a, suffix: camel(a.name)})
		if a.kind != kindObject || a.replace != replaceNever {
			continue
		}
		parent, ok := base[a.name]
		if !ok {
			pool, err := p.objectPool(a)
			if err != nil || len(pool) == 0 {
				continue
			}
			parent = pool[0]
		}
		for _, c := range a.sortedChildren() {
			if !c.optional || c.deprecated {
				continue
			}
			if _, set := parent.fields[c.name]; set {
				continue
			}
			pv := parent
			out = append(out, subject{attr: c, top: a, suffix: camel(a.name + "_" + c.name), parent: &pv})
		}
	}
	return out
}

// attributeCase adds one attribute to the basic config and walks it through
// its lifecycle: set, update, (for collections) reorder and remove elements,
// empty, and omit.
func attributeCase(r *resourceInfo, p *pools, base map[string]value, sub subject) (testCase, error) {
	a := sub.attr
	c := testCase{name: r.testPrefix + "_" + sub.suffix, suffix: sub.suffix, attr: a.dotted()}
	switch {
	case a.kind == kindUnsupported:
		c.skip = "testgen: " + a.unsupported
		return c, nil
	case a.writeOnly:
		c.skip = "testgen: write-only attributes are not stored in state"
		return c, nil
	}

	pool, err := p.pool(a)
	if err != nil {
		return c, err
	}
	if len(pool) == 0 {
		return c, nil
	}

	var seq []value
	if a.kind == kindList || a.kind == kindSet {
		seq = lifecycle(a, pool)
	} else {
		seq = pool
	}

	others := map[string]value{}
	for k, v := range base {
		if k != sub.top.name {
			others[k] = v
		}
	}
	requires := r.spec.Attributes[a.dotted()].Requires
	if _, ok := requires[sub.top.name]; ok {
		return c, fmt.Errorf("%s: %s Requires names the attribute itself", r.typeName, a.dotted())
	}
	if err := applySpecValues(r, a.dotted()+" Requires", requires, others); err != nil {
		return c, err
	}
	with := func(v *value) map[string]value {
		out := map[string]value{}
		for k, ov := range others {
			out[k] = ov
		}
		if tv := sub.wrap(v); tv != nil {
			out[sub.top.name] = *tv
		}
		return out
	}
	// planned is the plan action between two subject values, judged on the
	// top-level attribute so parent plan modifiers apply too.
	planned := func(prev, next *value) action {
		null := value{null: true}
		pt, nt := sub.wrap(prev), sub.wrap(next)
		if pt == nil {
			pt = &null
		}
		if nt == nil {
			nt = &null
		}
		return change(sub.top, *pt, *nt)
	}

	allVars := map[string]value{sub.top.name: {}}
	for k, v := range others {
		allVars[k] = v
	}
	c.vars = varsFor(r, allVars)

	var prev *value
	for i := range seq {
		v := seq[i]
		c.steps = append(c.steps, step{
			values:  with(&v),
			checks:  []check{{attr: a, kind: checkExact, v: v}},
			planned: planned(prev, &v),
		})
		prev = &v
	}

	if a.optional && (a.kind == kindList || a.kind == kindSet) && a.minSize == 0 {
		empty := value{elems: []value{}}
		c.steps = append(c.steps, step{
			values:  with(&empty),
			checks:  []check{{attr: a, kind: checkEmpty}},
			planned: planned(prev, &empty),
		})
		prev = &empty
	}

	if !a.required {
		switch {
		case a.defaults != nil:
			c.steps = append(c.steps, step{
				values:  with(nil),
				checks:  []check{defaultCheck(a)},
				planned: planned(prev, a.defaults),
				omit:    true,
			})
		case !a.computed:
			c.steps = append(c.steps, step{
				values:  with(nil),
				checks:  []check{{attr: a, kind: checkNull}},
				planned: planned(prev, nil),
				omit:    true,
			})
		}
	}

	if r.importable {
		last := c.steps[len(c.steps)-1]
		c.steps = append(c.steps, step{values: last.values, importState: true})
	}
	return c, nil
}

// applySpecValues converts spec-supplied attribute values into into. A nil
// value removes the attribute.
func applySpecValues(r *resourceInfo, field string, values map[string]any, into map[string]value) error {
	for name, raw := range values {
		a, ok := r.attrs[name]
		if !ok || !a.settable() {
			return fmt.Errorf("%s: %s names unknown or unsettable attribute %q", r.typeName, field, name)
		}
		if raw == nil {
			delete(into, name)
			continue
		}
		v, err := convertSpec(a, raw)
		if err != nil {
			return fmt.Errorf("%s: %s %s: %w", r.typeName, field, name, err)
		}
		into[name] = v
	}
	return nil
}

func defaultCheck(a *attribute) check {
	d := *a.defaults
	switch {
	case d.null:
		return check{attr: a, kind: checkNull}
	case (a.kind == kindList || a.kind == kindSet) && len(d.elems) == 0:
		return check{attr: a, kind: checkEmpty}
	}
	return check{attr: a, kind: checkExact, v: d}
}

// lifecycle returns the collection values a list or set attribute steps
// through: create, add an element, reorder, remove a middle element.
func lifecycle(a *attribute, pool []value) []value {
	n := len(pool)
	if a.maxSize > 0 {
		n = min(n, a.maxSize)
	}
	col := func(idx ...int) value {
		v := value{elems: []value{}}
		for _, i := range idx {
			v.elems = append(v.elems, pool[i])
		}
		return v
	}

	var seq []value
	switch {
	case n >= 3:
		seq = []value{col(0, 1), col(0, 1, 2), col(2, 0, 1), col(2, 1)}
	case n == 2:
		seq = []value{col(0), col(0, 1), col(1, 0), col(1)}
	default:
		seq = []value{col(0)}
	}

	out := seq[:0]
	for _, v := range seq {
		if len(v.elems) >= max(a.minSize, 1) {
			out = append(out, v)
		}
	}
	return out
}

// varsFor returns the attributes bound to Terraform variables, sorted by name.
func varsFor(r *resourceInfo, values map[string]value) []*attribute {
	out := make([]*attribute, 0, len(values))
	for name := range values {
		out = append(out, r.attrs[name])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}
