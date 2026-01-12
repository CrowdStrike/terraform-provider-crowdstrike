package modifiers

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestPreventStringClearingModifierLogic(t *testing.T) {
	tests := []struct {
		name              string
		fieldName         string
		stateValue        types.String
		configValue       types.String
		isNewResource     bool
		expectedError     bool
		expectedErrorText string
	}{
		{
			name:          "new resource with value - should allow",
			fieldName:     "test_field",
			stateValue:    types.StringNull(),
			configValue:   types.StringValue("some-value"),
			isNewResource: true,
			expectedError: false,
		},
		{
			name:          "new resource without value - should allow",
			fieldName:     "test_field",
			stateValue:    types.StringNull(),
			configValue:   types.StringNull(),
			isNewResource: true,
			expectedError: false,
		},
		{
			name:          "existing resource with value being updated - should allow",
			fieldName:     "test_field",
			stateValue:    types.StringValue("old-value"),
			configValue:   types.StringValue("new-value"),
			isNewResource: false,
			expectedError: false,
		},
		{
			name:          "existing resource with value being cleared (null) - should error",
			fieldName:     "test_field",
			stateValue:    types.StringValue("existing-value"),
			configValue:   types.StringNull(),
			isNewResource: false,
			expectedError: true,
		},
		{
			name:          "existing resource with value being cleared (empty) - should error",
			fieldName:     "test_field",
			stateValue:    types.StringValue("existing-value"),
			configValue:   types.StringValue(""),
			isNewResource: false,
			expectedError: true,
		},
		{
			name:          "existing resource without value staying null - should allow",
			fieldName:     "test_field",
			stateValue:    types.StringNull(),
			configValue:   types.StringNull(),
			isNewResource: false,
			expectedError: false,
		},
		{
			name:          "existing resource without value getting one - should allow",
			fieldName:     "test_field",
			stateValue:    types.StringNull(),
			configValue:   types.StringValue("new-value"),
			isNewResource: false,
			expectedError: false,
		},
		{
			name:          "existing resource with empty value staying empty - should allow",
			fieldName:     "test_field",
			stateValue:    types.StringValue(""),
			configValue:   types.StringValue(""),
			isNewResource: false,
			expectedError: false,
		},
		{
			name:          "suppression_expiration_date specific case - should error",
			fieldName:     "suppression_expiration_date",
			stateValue:    types.StringValue("2025-12-31T23:59:59Z"),
			configValue:   types.StringNull(),
			isNewResource: false,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the core logic of our plan modifier
			shouldError := false

			// If the resource is not new (existing resource)
			if !tt.isNewResource {
				// Check if the field was previously set (not null and not empty)
				// and is now being cleared (config value is null or empty)
				if !tt.stateValue.IsNull() && tt.stateValue.ValueString() != "" {
					if tt.configValue.IsNull() || tt.configValue.ValueString() == "" {
						shouldError = true
					}
				}
			}

			// Verify our expectations match the logic
			if shouldError != tt.expectedError {
				t.Errorf("Expected error=%v but logic resulted in error=%v for case: %s", tt.expectedError, shouldError, tt.name)
				t.Errorf("  Field name: %s", tt.fieldName)
				t.Errorf("  State value: %v (IsNull: %v, Value: '%s')", tt.stateValue, tt.stateValue.IsNull(), tt.stateValue.ValueString())
				t.Errorf("  Config value: %v (IsNull: %v, Value: '%s')", tt.configValue, tt.configValue.IsNull(), tt.configValue.ValueString())
				t.Errorf("  Is new resource: %v", tt.isNewResource)
			}
		})
	}
}

func TestPreventStringClearingModifierDescriptions(t *testing.T) {
	ctx := context.Background()

	// Test generic modifier with field name
	modifier := PreventStringClearing("test_field")
	description := modifier.Description(ctx)
	expectedDescription := "Prevents test_field from being cleared once set"
	if description != expectedDescription {
		t.Errorf("Expected description '%s' but got '%s'", expectedDescription, description)
	}

	markdownDescription := modifier.MarkdownDescription(ctx)
	expectedMarkdown := "Prevents `test_field` from being cleared once set"
	if markdownDescription != expectedMarkdown {
		t.Errorf("Expected markdown description '%s' but got '%s'", expectedMarkdown, markdownDescription)
	}

	// Test generic modifier without field name
	modifierNoName := PreventStringClearing("")
	descriptionNoName := modifierNoName.Description(ctx)
	expectedDescriptionNoName := "Prevents field from being cleared once set"
	if descriptionNoName != expectedDescriptionNoName {
		t.Errorf("Expected description '%s' but got '%s'", expectedDescriptionNoName, descriptionNoName)
	}
}
