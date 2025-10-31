package containerregistry

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// stringFromPointer safely converts a string pointer to types.String.
func stringFromPointer(ptr *string) types.String {
	if ptr == nil {
		return types.StringNull()
	}
	return types.StringValue(*ptr)
}

// int64FromPointer safely converts an int32 pointer to types.Int64.
func int64FromPointer(ptr *int32) types.Int64 {
	if ptr == nil {
		return types.Int64Null()
	}
	return types.Int64Value(int64(*ptr))
}

// boolFromPointer safely converts a bool pointer to types.Bool.
func boolFromPointer(ptr *bool) types.Bool {
	if ptr == nil {
		return types.BoolNull()
	}
	return types.BoolValue(*ptr)
}
