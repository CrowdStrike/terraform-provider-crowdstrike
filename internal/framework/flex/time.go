package flex

import "github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"

// RFC3339ValueToFramework converts a string to a Terraform framework timetypes.RFC3339.
// An empty string returns a null timetypes.RFC3339.
func RFC3339ValueToFramework[T ~string](v T) timetypes.RFC3339 {
	if v == "" {
		return timetypes.NewRFC3339Null()
	}
	rfc3339Value, _ := timetypes.NewRFC3339Value(string(v))
	return rfc3339Value
}

// RFC3339PointerToFramework converts a string pointer to a Terraform framework timetypes.RFC3339.
// A nil pointer or empty string returns a null timetypes.RFC3339.
func RFC3339PointerToFramework(v *string) timetypes.RFC3339 {
	if v == nil || *v == "" {
		return timetypes.NewRFC3339Null()
	}
	rfc3339Value, _ := timetypes.NewRFC3339Value(*v)
	return rfc3339Value
}

// FrameworkToRFC3339Pointer converts a Terraform framework timetypes.RFC3339 to a string pointer.
// If the framework RFC3339 is null or unknown, it returns a pointer to an empty string.
func FrameworkToRFC3339Pointer(v timetypes.RFC3339) *string {
	if v.IsNull() || v.IsUnknown() {
		emptyString := ""
		return &emptyString
	}
	val := v.ValueString()
	return &val
}
