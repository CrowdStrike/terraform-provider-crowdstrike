package flex

import "github.com/hashicorp/terraform-plugin-framework/types"

// Int32PointerToFramework converts an int32 pointer to a Terraform framework types.Int32.
// A nil pointer returns a null types.Int32.
func Int32PointerToFramework(v *int32) types.Int32 {
	if v == nil {
		return types.Int32Null()
	}
	return types.Int32Value(*v)
}

// FrameworkToInt32Pointer converts a Terraform framework types.Int32 to an int32 pointer.
// If the framework int32 is null or unknown, it returns nil.
func FrameworkToInt32Pointer(v types.Int32) *int32 {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	val := v.ValueInt32()
	return &val
}
