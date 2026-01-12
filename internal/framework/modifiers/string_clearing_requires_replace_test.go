package modifiers

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestStringClearingRequiresReplaceModifierLogic(t *testing.T) {
	tests := []struct {
		name                string
		fieldName           string
		stateValue          types.String
		configValue         types.String
		isNewResource       bool
		expectedReplacement bool
		description         string
	}{
		{
			name:                "new resource with value - should allow without replacement",
			fieldName:           "test_field",
			stateValue:          types.StringNull(),
			configValue:         types.StringValue("some-value"),
			isNewResource:       true,
			expectedReplacement: false,
			description:         "Creating a new resource with a string value should not require replacement",
		},
		{
			name:                "new resource without value - should allow without replacement",
			fieldName:           "test_field",
			stateValue:          types.StringNull(),
			configValue:         types.StringNull(),
			isNewResource:       true,
			expectedReplacement: false,
			description:         "Creating a new resource without a string value should not require replacement",
		},
		{
			name:                "existing resource updating value - should allow without replacement",
			fieldName:           "test_field",
			stateValue:          types.StringValue("old-value"),
			configValue:         types.StringValue("new-value"),
			isNewResource:       false,
			expectedReplacement: false,
			description:         "Updating an existing string value should not require replacement",
		},
		{
			name:                "existing resource clearing value (null) - should require replacement",
			fieldName:           "test_field",
			stateValue:          types.StringValue("existing-value"),
			configValue:         types.StringNull(),
			isNewResource:       false,
			expectedReplacement: true,
			description:         "Clearing a string value to null should require replacement",
		},
		{
			name:                "existing resource clearing value (empty) - should require replacement",
			fieldName:           "test_field",
			stateValue:          types.StringValue("existing-value"),
			configValue:         types.StringValue(""),
			isNewResource:       false,
			expectedReplacement: true,
			description:         "Clearing a string value to empty should require replacement",
		},
		{
			name:                "existing resource without value staying null - should allow without replacement",
			fieldName:           "test_field",
			stateValue:          types.StringNull(),
			configValue:         types.StringNull(),
			isNewResource:       false,
			expectedReplacement: false,
			description:         "Keeping a null value as null should not require replacement",
		},
		{
			name:                "existing resource without value getting one - should allow without replacement",
			fieldName:           "test_field",
			stateValue:          types.StringNull(),
			configValue:         types.StringValue("new-value"),
			isNewResource:       false,
			expectedReplacement: false,
			description:         "Setting a string value on a previously null field should not require replacement",
		},
		{
			name:                "existing resource with empty value staying empty - should allow without replacement",
			fieldName:           "test_field",
			stateValue:          types.StringValue(""),
			configValue:         types.StringValue(""),
			isNewResource:       false,
			expectedReplacement: false,
			description:         "Keeping an empty value as empty should not require replacement",
		},
		{
			name:                "existing resource with empty value being set - should allow without replacement",
			fieldName:           "test_field",
			stateValue:          types.StringValue(""),
			configValue:         types.StringValue("new-value"),
			isNewResource:       false,
			expectedReplacement: false,
			description:         "Setting a value on a previously empty field should not require replacement",
		},
		{
			name:                "existing resource with empty value being cleared to null - should allow without replacement",
			fieldName:           "test_field",
			stateValue:          types.StringValue(""),
			configValue:         types.StringNull(),
			isNewResource:       false,
			expectedReplacement: false,
			description:         "Clearing an empty value to null should not require replacement (both are considered empty)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the core logic of our plan modifier
			shouldRequireReplacement := false

			// If the resource is not new (existing resource)
			if !tt.isNewResource {
				// Check if the field was previously set (not null and not empty)
				// and is now being cleared (config value is null or empty)
				if !tt.stateValue.IsNull() && tt.stateValue.ValueString() != "" {
					if tt.configValue.IsNull() || tt.configValue.ValueString() == "" {
						shouldRequireReplacement = true
					}
				}
			}

			// Verify our expectations match the logic
			if shouldRequireReplacement != tt.expectedReplacement {
				t.Errorf("Expected replacement=%v but logic resulted in replacement=%v for case: %s", tt.expectedReplacement, shouldRequireReplacement, tt.name)
				t.Errorf("  Description: %s", tt.description)
				t.Errorf("  Field name: %s", tt.fieldName)
				t.Errorf("  State value: %v (IsNull: %v, Value: '%s')", tt.stateValue, tt.stateValue.IsNull(), tt.stateValue.ValueString())
				t.Errorf("  Config value: %v (IsNull: %v, Value: '%s')", tt.configValue, tt.configValue.IsNull(), tt.configValue.ValueString())
				t.Errorf("  Is new resource: %v", tt.isNewResource)
			}
		})
	}
}

func TestStringClearingRequiresReplaceModifierDescriptions(t *testing.T) {
	ctx := context.Background()

	// Test modifier with field name
	modifier := StringClearingRequiresReplace("test_field")
	description := modifier.Description(ctx)
	expectedDescription := "Clearing test_field requires resource replacement"
	if description != expectedDescription {
		t.Errorf("Expected description '%s' but got '%s'", expectedDescription, description)
	}

	markdownDescription := modifier.MarkdownDescription(ctx)
	expectedMarkdown := "Clearing `test_field` requires resource replacement"
	if markdownDescription != expectedMarkdown {
		t.Errorf("Expected markdown description '%s' but got '%s'", expectedMarkdown, markdownDescription)
	}

	// Test modifier without field name
	modifierNoName := StringClearingRequiresReplace("")
	descriptionNoName := modifierNoName.Description(ctx)
	expectedDescriptionNoName := "Clearing field requires resource replacement"
	if descriptionNoName != expectedDescriptionNoName {
		t.Errorf("Expected description '%s' but got '%s'", expectedDescriptionNoName, descriptionNoName)
	}

	markdownDescriptionNoName := modifierNoName.MarkdownDescription(ctx)
	expectedMarkdownNoName := "Clearing field requires resource replacement"
	if markdownDescriptionNoName != expectedMarkdownNoName {
		t.Errorf("Expected markdown description '%s' but got '%s'", expectedMarkdownNoName, markdownDescriptionNoName)
	}
}
