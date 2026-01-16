package modifiers

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// preventStringClearingModifier implements the plan modifier interface.
// It prevents any string field from being cleared once it's set.
type preventStringClearingModifier struct {
	fieldName string
}

// Description returns a human-readable description of the plan modifier.
func (m preventStringClearingModifier) Description(_ context.Context) string {
	if m.fieldName != "" {
		return fmt.Sprintf("Prevents %s from being cleared once set", m.fieldName)
	}
	return "Prevents field from being cleared once set"
}

// MarkdownDescription returns a markdown description of the plan modifier.
func (m preventStringClearingModifier) MarkdownDescription(_ context.Context) string {
	if m.fieldName != "" {
		return fmt.Sprintf("Prevents `%s` from being cleared once set", m.fieldName)
	}
	return "Prevents field from being cleared once set"
}

// PlanModifyString implements the plan modification logic.
func (m preventStringClearingModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
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
	// (config value is null or empty), prevent the change
	if !stateValue.IsNull() && stateValue.ValueString() != "" {
		// Check if the new config value is null or empty
		if req.ConfigValue.IsNull() || req.ConfigValue.ValueString() == "" {
			fieldDisplayName := m.fieldName
			if fieldDisplayName == "" {
				fieldDisplayName = req.Path.String()
			}

			resp.Diagnostics.AddAttributeError(
				req.Path,
				fmt.Sprintf("Cannot Clear %s", fieldDisplayName),
				fmt.Sprintf("The %s field cannot be cleared once it has been set. "+
					"Current value: '%s'. To change the value, provide a new non-empty value.",
					fieldDisplayName, stateValue.ValueString()),
			)
			return
		}
	}
}

// PreventStringClearing returns a plan modifier that prevents any string field
// from being cleared once it's been set. This is a generic modifier that can be
// used for any string field throughout the codebase.
//
// Example usage:
//
//	PlanModifiers: []planmodifier.String{
//	    modifiers.PreventStringClearing("Field Name"), // friendly display name for error messages
//	}
//
// Parameters:
//   - fieldName: The display name of the field for error messages (e.g., "API Token", "License Key").
//     If empty, will use the field path from Terraform.
func PreventStringClearing(fieldName string) planmodifier.String {
	return preventStringClearingModifier{
		fieldName: fieldName,
	}
}
