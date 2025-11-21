package flex

import "github.com/hashicorp/terraform-plugin-framework/types"

// StringValueToFramework converts a string to a Terraform framework types.String.
// An empty input returns a null types.String.
func StringValueToFramework[T ~string](v T) types.String {
	if v == "" {
		return types.StringNull()
	}
	return types.StringValue(string(v))
}
