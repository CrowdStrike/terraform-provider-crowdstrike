package validators

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

func TestBoolRequiresBool(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		attrValue         types.Bool
		requiredAttrValue types.Bool
		attrName          string
		requiredAttrName  string
		expectError       bool
	}{
		{
			name:              "both enabled - valid",
			attrValue:         types.BoolValue(true),
			requiredAttrValue: types.BoolValue(true),
			attrName:          "falcon_scripts",
			requiredAttrName:  "custom_scripts",
			expectError:       false,
		},
		{
			name:              "both disabled - valid",
			attrValue:         types.BoolValue(false),
			requiredAttrValue: types.BoolValue(false),
			attrName:          "falcon_scripts",
			requiredAttrName:  "custom_scripts",
			expectError:       false,
		},
		{
			name:              "attr enabled, required disabled - invalid",
			attrValue:         types.BoolValue(true),
			requiredAttrValue: types.BoolValue(false),
			attrName:          "falcon_scripts",
			requiredAttrName:  "custom_scripts",
			expectError:       true,
		},
		{
			name:              "attr disabled, required enabled - valid",
			attrValue:         types.BoolValue(false),
			requiredAttrValue: types.BoolValue(true),
			attrName:          "falcon_scripts",
			requiredAttrName:  "custom_scripts",
			expectError:       false,
		},
		{
			name:              "attr null - valid (skipped)",
			attrValue:         types.BoolNull(),
			requiredAttrValue: types.BoolValue(false),
			attrName:          "falcon_scripts",
			requiredAttrName:  "custom_scripts",
			expectError:       false,
		},
		{
			name:              "required null - valid (skipped)",
			attrValue:         types.BoolValue(true),
			requiredAttrValue: types.BoolNull(),
			attrName:          "falcon_scripts",
			requiredAttrName:  "custom_scripts",
			expectError:       false,
		},
		{
			name:              "attr unknown - valid (skipped)",
			attrValue:         types.BoolUnknown(),
			requiredAttrValue: types.BoolValue(false),
			attrName:          "falcon_scripts",
			requiredAttrName:  "custom_scripts",
			expectError:       false,
		},
		{
			name:              "required unknown - valid (skipped)",
			attrValue:         types.BoolValue(true),
			requiredAttrValue: types.BoolUnknown(),
			attrName:          "falcon_scripts",
			requiredAttrName:  "custom_scripts",
			expectError:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diags := BoolRequiresBool(tt.attrValue, tt.requiredAttrValue, tt.attrName, tt.requiredAttrName)

			if tt.expectError {
				assert.True(t, diags.HasError(), "Expected error but got none")
				assert.Len(t, diags, 1, "Expected exactly one diagnostic")
			} else {
				assert.False(t, diags.HasError(), "Expected no error but got: %v", diags)
				assert.Len(t, diags, 0, "Expected no diagnostics")
			}
		})
	}
}
