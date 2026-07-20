package planmodifiers

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
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

// NormalizeTrailingNewlines returns a plan modifier that trims trailing newline
// characters from the planned value. Use this when the API strips trailing
// newlines from a field, which would otherwise cause "inconsistent result after
// apply" errors.
func NormalizeTrailingNewlines() planmodifier.String {
	return normalizeTrailingNewlinesModifier{}
}

type normalizeTrailingNewlinesModifier struct{}

func (m normalizeTrailingNewlinesModifier) Description(_ context.Context) string {
	return "Trims trailing newline characters to match API normalization."
}

func (m normalizeTrailingNewlinesModifier) MarkdownDescription(_ context.Context) string {
	return "Trims trailing newline characters to match API normalization."
}

func (m normalizeTrailingNewlinesModifier) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}

	resp.PlanValue = types.StringValue(strings.TrimRight(req.PlanValue.ValueString(), "\n"))
}
