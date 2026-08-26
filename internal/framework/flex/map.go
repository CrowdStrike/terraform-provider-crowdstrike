package flex

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// FlattenStringValueMapOrEmpty converts a map of strings to a Terraform map of
// strings. Returns an empty map, never null, if the map is empty or nil.
func FlattenStringValueMapOrEmpty(
	ctx context.Context,
	values map[string]string,
) (types.Map, diag.Diagnostics) {
	if values == nil {
		values = map[string]string{}
	}

	return types.MapValueFrom(ctx, types.StringType, values)
}
