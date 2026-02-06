package flex

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ExpandListAs converts a Terraform Framework types.List into a Go slice of the specified type.
// If the list is null or unknown, it returns an empty slice.
func ExpandListAs[T any](
	ctx context.Context,
	list types.List,
	diags *diag.Diagnostics,
) []T {
	if list.IsNull() || list.IsUnknown() {
		return []T{}
	}

	var elements []T

	diags.Append(list.ElementsAs(ctx, &elements, false)...)
	return elements
}

// FlattenStringValueList converts a slice of strings to a Terraform list of strings.
// Returns null if the slice is empty or nil.
func FlattenStringValueList(
	ctx context.Context,
	values []string,
) (types.List, diag.Diagnostics) {
	if len(values) == 0 {
		return types.ListNull(types.StringType), nil
	}

	return types.ListValueFrom(ctx, types.StringType, values)
}
