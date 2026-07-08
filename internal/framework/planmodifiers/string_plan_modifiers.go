package planmodifiers

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
)

// RequiresReplaceIfCleared returns a plan modifier that triggers resource
// replacement when an attribute that was previously set is cleared from the
// configuration. This is intended for API fields that accept a value on
// create/update but cannot be unset afterward — the only way to remove the
// value is to destroy and recreate the resource.
//
// The modifier is a no-op during initial creation (state is null) and when
// the attribute was never set (state value is null or empty). It only fires
// when the state holds a non-empty value and the config removes it.
func RequiresReplaceIfCleared(summary, detail string) planmodifier.String {
	return stringplanmodifier.RequiresReplaceIf(
		func(_ context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
			if req.State.Raw.IsNull() {
				return
			}

			if !req.StateValue.IsNull() && req.StateValue.ValueString() != "" {
				if req.ConfigValue.IsNull() || req.ConfigValue.ValueString() == "" {
					resp.RequiresReplace = true
				}
			}
		},
		summary,
		detail,
	)
}
