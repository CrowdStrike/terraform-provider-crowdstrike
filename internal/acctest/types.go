package acctest

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// StringListOrNull creates a string list (types.List) from the provided values.
// Returns a null string list if no values are provided.
// Test use only - panics on error via types.ListValueMust.
func StringListOrNull(values ...string) types.List {
	if len(values) == 0 {
		return types.ListNull(types.StringType)
	}

	attrs := make([]attr.Value, len(values))
	for i, v := range values {
		attrs[i] = types.StringValue(v)
	}
	return types.ListValueMust(types.StringType, attrs)
}
