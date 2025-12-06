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
