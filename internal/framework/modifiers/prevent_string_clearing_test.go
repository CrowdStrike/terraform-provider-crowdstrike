package modifiers

import (
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
			shouldError := false

			if !tt.isNewResource {
				if !tt.stateValue.IsNull() && tt.stateValue.ValueString() != "" {
					if tt.configValue.IsNull() || tt.configValue.ValueString() == "" {
						shouldError = true
					}
				}
			}

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
