package types

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// OptionalString converts a Go string to a types.String, returning StringNull
// if the input is an empty string, otherwise returning StringValue with the input.
func OptionalString(s string) types.String {
	if s == "" {
		return types.StringNull()
	}
	return types.StringValue(s)
}

// OptionalStringList converts a Go string slice to a types.List, returning ListNull
// if the input slice is empty, otherwise returning a ListValueFrom with the input.
func OptionalStringList(ctx context.Context, s []string) (types.List, diag.Diagnostics) {
	if len(s) == 0 {
		return types.ListNull(types.StringType), nil
	}
	return types.ListValueFrom(ctx, types.StringType, s)
}
