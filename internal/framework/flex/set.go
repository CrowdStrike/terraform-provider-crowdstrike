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
