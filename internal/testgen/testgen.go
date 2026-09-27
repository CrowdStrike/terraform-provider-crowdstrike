// Package testgen holds the per-resource inputs for the acceptance test
// generator in tools/testgen.
//
// A resource opts into generated tests by calling Register from a
// `testgen.go` file in its package guarded by the `testgen` build tag, so the
// specs are only compiled into the generator and never into the provider:
//
//	//go:build testgen
//
//	package cidgroup
//
//	import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/testgen"
//
//	func init() {
//		testgen.Register("crowdstrike_cid_group", testgen.Resource{})
//	}
package testgen

import (
	"fmt"
	"sort"
)

// Resource is the generator input for one resource type. The zero value opts
// the resource in with everything derived from its schema.
type Resource struct {
	// Attributes supplies test values for attributes whose values the
	// generator cannot derive from the schema. Keys are attribute names;
	// nested attributes use dotted paths such as "schedule.interval".
	Attributes map[string]Attribute

	// Base sets attributes in every generated config, including _basic, for
	// resources whose provider validation requires more than their Required
	// attributes (for example a type that makes another attribute required).
	// Values use the same forms as Attribute.Values entries.
	Base map[string]any

	// Skip lists generated tests to emit as t.Skip, keyed by test suffix
	// ("basic", "description", "hostGroups"). The value is the reason and is
	// printed by the skipped test.
	Skip map[string]string

	// ImportIgnore lists attributes the import step must not verify because
	// the provider sets them outside Read, such as last_updated.
	ImportIgnore []string

	// Serial runs the resource's tests with resource.Test instead of
	// resource.ParallelTest. Use it for singleton resources, such as default
	// policies, where parallel tests would modify the same remote object.
	Serial bool

	// NoDisappears leaves out the _disappears test, for resources whose
	// Delete does not remove the remote object, such as default policies
	// whose Delete only removes them from state.
	NoDisappears bool
}

// Attribute supplies test values for one attribute.
type Attribute struct {
	// Values is the pool of values the generator draws from, in order.
	// Primitive attributes take Go primitives (string, bool, int, float64).
	// List and set attributes take a pool of element values. Nested
	// attributes take map[string]any objects keyed by child attribute name.
	// Collections need at least two values; three enable every lifecycle step.
	Values []any

	// Requires sets other top-level attributes in this attribute's own test,
	// for attributes that are only valid alongside others (for example a
	// threshold that requires its feature to be enabled). Keys are attribute
	// names; values use the same forms as Values entries. A nil value unsets
	// an attribute that Base would otherwise set.
	Requires map[string]any
}

var registry = map[string]Resource{}

// Register opts a resource type into test generation. It panics if the type
// is registered twice.
func Register(typeName string, r Resource) {
	if _, ok := registry[typeName]; ok {
		panic(fmt.Sprintf("testgen: %s registered twice", typeName))
	}
	registry[typeName] = r
}

// Registered returns the registered resource type names in sorted order.
func Registered() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Lookup returns the registration for a resource type.
func Lookup(typeName string) (Resource, bool) {
	r, ok := registry[typeName]
	return r, ok
}
