package utils

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// IsKnown returns true if an attribute value is known and not null.
func IsKnown(value attr.Value) bool {
	return !value.IsNull() && !value.IsUnknown()
}

// ListTypeAs converts a types.List into a known []T.
func ListTypeAs[T any](
	ctx context.Context,
	list types.List,
	diags *diag.Diagnostics,
) []T {
	if !IsKnown(list) {
		return nil
	}

	var elements []T

	diags.Append(list.ElementsAs(ctx, &elements, false)...)
	return elements
}
