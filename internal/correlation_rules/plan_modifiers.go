package correlationrules

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// useStateUnlessMitreChanged preserves the state value for computed attributes
// that are derived from mitre_attack (tactic, technique).  When mitre_attack
// hasn't changed the value is stable and we avoid "(known after apply)" noise.
// When it has changed the value must be recomputed from the API response.
type useStateUnlessMitreChanged struct{}

func (m useStateUnlessMitreChanged) Description(_ context.Context) string {
	return "Uses the state value unless mitre_attack has changed."
}

func (m useStateUnlessMitreChanged) MarkdownDescription(_ context.Context) string {
	return "Uses the state value unless mitre_attack has changed."
}

func (m useStateUnlessMitreChanged) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// Only act when the planned value is unknown (i.e. Computed, not set by user).
	if !req.PlanValue.IsUnknown() {
		return
	}
	// On create there is no state to preserve.
	if req.StateValue.IsNull() {
		return
	}

	var planMitre, stateMitre types.List
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("mitre_attack"), &planMitre)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("mitre_attack"), &stateMitre)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if planMitre.Equal(stateMitre) {
		resp.PlanValue = req.StateValue
	}
}

// normalizeEmptyToNull converts an empty string plan value to null.
// This prevents perpetual diffs for optional fields where the API drops
// empty strings (omitempty) and the read path maps the absent value to null.
type normalizeEmptyToNull struct{}

func (m normalizeEmptyToNull) Description(_ context.Context) string {
	return "Normalizes empty string to null to match API behavior."
}

func (m normalizeEmptyToNull) MarkdownDescription(_ context.Context) string {
	return "Normalizes empty string to null to match API behavior."
}

func (m normalizeEmptyToNull) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}
	if req.PlanValue.ValueString() == "" {
		resp.PlanValue = types.StringNull()
	}
}

// requiresReplaceIfCleared forces replacement when an optional string field is
// cleared.  The gofalcon PATCH model uses omitempty, so an empty string is
// never sent to the API.
func requiresReplaceIfCleared() planmodifier.String {
	return stringplanmodifier.RequiresReplaceIf(
		func(_ context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
			if !req.StateValue.IsNull() && req.StateValue.ValueString() != "" &&
				(req.PlanValue.IsNull() || req.PlanValue.ValueString() == "") {
				resp.RequiresReplace = true
			}
		},
		"Requires replacement when clearing this field due to an API limitation.",
		"Requires replacement when clearing this field due to an API limitation.",
	)
}
