package acctest

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// StringSetOrNull creates a string set (types.Set) from the provided values.
// Returns a null string set if no values are provided.
// Test use only - panics on error via types.SetValueMust.
func StringSetOrNull(values ...string) types.Set {
	if len(values) == 0 {
		return types.SetNull(types.StringType)
	}

	attrs := make([]attr.Value, len(values))
	for i, v := range values {
		attrs[i] = types.StringValue(v)
	}
	return types.SetValueMust(types.StringType, attrs)
}
