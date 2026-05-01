package flex

import "github.com/hashicorp/terraform-plugin-framework/types"

// StringValueToFramework converts a string to a Terraform framework types.String.
// An empty string returns a null types.String.
//
// Pair with a validator (e.g. StringNotWhitespace) that prevents users from setting
// empty strings. When the API returns "" for unset fields, normalizing "" to null
// ensures state matches config and prevents inconsistent result after apply errors.
func StringValueToFramework[T ~string](v T) types.String {
	if v == "" {
		return types.StringNull()
	}
	return types.StringValue(string(v))
}

// StringPointerToFramework converts a string pointer to a Terraform framework types.String.
// A nil pointer or empty string returns a null types.String.
//
// Pair with a validator (e.g. StringNotWhitespace) that prevents users from setting
// empty strings. When the API returns "" for unset fields, normalizing "" to null
// ensures state matches config and prevents inconsistent result after apply errors.
func StringPointerToFramework(v *string) types.String {
	if v == nil || *v == "" {
		return types.StringNull()
	}
	return types.StringValue(*v)
}

// FrameworkToStringPointer converts a Terraform framework types.String to a string pointer.
// If the framework string is null or unknown, it returns a pointer to an empty string.
func FrameworkToStringPointer(v types.String) *string {
	if v.IsNull() || v.IsUnknown() {
		emptyString := ""
		return &emptyString
	}
	val := v.ValueString()
	return &val
}
