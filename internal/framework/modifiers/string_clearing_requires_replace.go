package modifiers

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// stringClearingRequiresReplaceModifier implements the plan modifier interface.
// It allows string updates but forces replacement when a string is cleared.
type stringClearingRequiresReplaceModifier struct {
	fieldName string
}

// Description returns a human-readable description of the plan modifier.
func (m stringClearingRequiresReplaceModifier) Description(_ context.Context) string {
	if m.fieldName != "" {
		return fmt.Sprintf("Clearing %s requires resource replacement", m.fieldName)
	}
	return "Clearing field requires resource replacement"
}

// MarkdownDescription returns a markdown description of the plan modifier.
func (m stringClearingRequiresReplaceModifier) MarkdownDescription(_ context.Context) string {
	if m.fieldName != "" {
		return fmt.Sprintf("Clearing `%s` requires resource replacement", m.fieldName)
	}
	return "Clearing field requires resource replacement"
}

// PlanModifyString implements the plan modification logic.
func (m stringClearingRequiresReplaceModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// If the resource is being created, allow any value
	if req.State.Raw.IsNull() {
		return
	}

	// Get the current state value
	var stateValue types.String
	diags := req.State.GetAttribute(ctx, req.Path, &stateValue)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// If the field was previously set (not null and not empty) and is now being cleared
	// (config value is null or empty), require replacement
	if !stateValue.IsNull() && stateValue.ValueString() != "" {
		// Check if the new config value is null or empty
		if req.ConfigValue.IsNull() || req.ConfigValue.ValueString() == "" {
			resp.RequiresReplace = true
		}
	}
}

// StringClearingRequiresReplace returns a plan modifier that allows string updates
// but forces resource replacement when a string field is cleared (set to null or empty).
//
// This modifier is useful for fields where:
// - Users can update the string value normally (non-empty to non-empty)
// - Users can set the string initially (null/empty to non-empty)
// - When users clear the string (non-empty to null/empty), it forces a replacement
//
// Example usage:
//
//	PlanModifiers: []planmodifier.String{
//	    modifiers.StringClearingRequiresReplace("Field Name"), // friendly display name for description
//	}
//
// Parameters:
//   - fieldName: The display name of the field for descriptions (e.g., "API Token", "License Key").
//     If empty, will use generic descriptions.
func StringClearingRequiresReplace(fieldName string) planmodifier.String {
	return stringClearingRequiresReplaceModifier{
		fieldName: fieldName,
	}
}
