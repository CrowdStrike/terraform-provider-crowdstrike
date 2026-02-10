package planmodifiers

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// StringRequiresReplaceIfCleared returns a plan modifier that requires replacement
// if a string attribute is cleared after being set. This is useful for backend APIs
// that don't support clearing string fields once they have a value.
// Uses a default message about backend API limitations.
func StringRequiresReplaceIfCleared() planmodifier.String {
	return StringRequiresReplaceIfClearedWithMessage(
		"Requires replacement when cleared after being set",
		"Requires replacement when cleared after being set",
	)
}

// StringRequiresReplaceIfClearedWithMessage returns a plan modifier that requires replacement
// if a string attribute is cleared after being set, with custom description messages.
func StringRequiresReplaceIfClearedWithMessage(description, markdownDescription string) planmodifier.String {
	return stringplanmodifier.RequiresReplaceIf(
		func(ctx context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
			if req.State.Raw.IsNull() {
				return
			}

			var stateValue types.String
			diags := req.State.GetAttribute(ctx, req.Path, &stateValue)
			if diags.HasError() {
				return
			}

			if !stateValue.IsNull() && stateValue.ValueString() != "" {
				if req.ConfigValue.IsNull() || req.ConfigValue.ValueString() == "" {
					resp.RequiresReplace = true
				}
			}
		},
		description,
		markdownDescription,
	)
}
