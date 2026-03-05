package flex

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ExpandSetAs converts a Terraform Framework types.Set into a Go slice of the specified type.
// If the set is null or unknown, it returns an empty slice.
func ExpandSetAs[T any](
	ctx context.Context,
	set types.Set,
	diags *diag.Diagnostics,
) []T {
	if set.IsNull() || set.IsUnknown() {
		return []T{}
	}

	var elements []T

	diags.Append(set.ElementsAs(ctx, &elements, false)...)
	return elements
}

// ExpandSetWithConverter converts a Terraform Framework types.Set into a Go slice
// using a converter function to transform each element from the Terraform model type
// to the desired output type.
// If the set is null or unknown, it returns an empty slice.
func ExpandSetWithConverter[TSource any, TDest any](
	ctx context.Context,
	set types.Set,
	converter func(TSource) (TDest, diag.Diagnostics),
) ([]TDest, diag.Diagnostics) {
	var diags diag.Diagnostics

	if set.IsNull() || set.IsUnknown() {
		return []TDest{}, nil
	}

	var sources []TSource
	diags.Append(set.ElementsAs(ctx, &sources, false)...)
	if diags.HasError() {
		return []TDest{}, diags
	}

	destinations := make([]TDest, 0, len(sources))
	for _, source := range sources {
		dest, convertDiags := converter(source)
		diags.Append(convertDiags...)
		destinations = append(destinations, dest)
	}

	if diags.HasError() {
		return []TDest{}, diags
	}

	return destinations, diags
}

// MergeStringSet combines two sets and returns a new set containing unique items from both.
func MergeStringSet(
	ctx context.Context,
	a types.Set,
	b types.Set,
	diags *diag.Diagnostics,
) types.Set {
	aItems := ExpandSetAs[types.String](ctx, a, diags)
	if diags.HasError() {
		return types.SetNull(types.StringType)
	}

	bItems := ExpandSetAs[types.String](ctx, b, diags)
	if diags.HasError() {
		return types.SetNull(types.StringType)
	}

	allItems := make([]types.String, 0, len(aItems)+len(bItems))
	allItems = append(allItems, aItems...)
	allItems = append(allItems, bItems...)
	uniqueItems := Unique(allItems)

	mergedSet, mergeDiags := types.SetValueFrom(ctx, types.StringType, uniqueItems)
	diags.Append(mergeDiags...)

	return mergedSet
}

// DiffStringSet returns items that exist in a but not in b (set difference: a - b).
func DiffStringSet(
	ctx context.Context,
	a types.Set,
	b types.Set,
	diags *diag.Diagnostics,
) []types.String {
	if a.IsNull() {
		return nil
	}

	aItems := ExpandSetAs[types.String](ctx, a, diags)
	if diags.HasError() {
		return nil
	}

	if b.IsNull() {
		return aItems
	}

	bItems := ExpandSetAs[types.String](ctx, b, diags)
	if diags.HasError() {
		return nil
	}

	bMap := make(map[string]bool)
	for _, item := range bItems {
		bMap[item.ValueString()] = true
	}

	var diff []types.String
	for _, item := range aItems {
		if !bMap[item.ValueString()] {
			diff = append(diff, item)
		}
	}

	return diff
}

// FlattenStringValueSet converts a slice of strings to a Terraform set of strings.
// Returns null if the slice is empty or nil.
func FlattenStringValueSet(
	ctx context.Context,
	values []string,
) (types.Set, diag.Diagnostics) {
	if len(values) == 0 {
		return types.SetNull(types.StringType), nil
	}

	return types.SetValueFrom(ctx, types.StringType, values)
}

// FlattenObjectValueSetFrom converts a slice of source objects to a Terraform set of objects
// using a converter function to transform each element.
// Returns null if the slice is empty or nil, or if diagnostics has errors.
func FlattenObjectValueSetFrom[TSource any, TDest any](
	ctx context.Context,
	objectType types.ObjectType,
	sources []TSource,
	converter func(TSource) (TDest, diag.Diagnostics),
) (types.Set, diag.Diagnostics) {
	var diags diag.Diagnostics

	if len(sources) == 0 {
		return types.SetNull(objectType), nil
	}

	destinations := make([]TDest, 0, len(sources))
	for _, source := range sources {
		dest, convertDiags := converter(source)
		diags.Append(convertDiags...)
		destinations = append(destinations, dest)
	}

	if diags.HasError() {
		return types.SetNull(objectType), diags
	}

	set, setDiags := types.SetValueFrom(ctx, objectType, destinations)
	diags.Append(setDiags...)

	if diags.HasError() {
		return types.SetNull(objectType), diags
	}

	return set, diags
}
