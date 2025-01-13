package utils

import "github.com/hashicorp/terraform-plugin-framework/attr"

// IsKnown returns true if an attribute value is known and not null.
func IsKnown(value attr.Value) bool {
	return !value.IsNull() && !value.IsUnknown()
}
