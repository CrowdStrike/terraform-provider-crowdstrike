package acctest

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// StringMapOrEmpty creates a string map (types.Map) from the provided values.
// Returns an empty string map if no values are provided.
// Test use only - panics on error via types.MapValueMust.
func StringMapOrEmpty(values map[string]string) types.Map {
	attrs := make(map[string]attr.Value, len(values))
	for k, v := range values {
		attrs[k] = types.StringValue(v)
	}
	return types.MapValueMust(types.StringType, attrs)
}
