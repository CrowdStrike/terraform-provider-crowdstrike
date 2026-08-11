package validators

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
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

func TestAttributeRequiresBool(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		attrValue         attr.Value
		requiredAttrValue types.Bool
		attrName          string
		requiredAttrName  string
		expectError       bool
	}{
		{
			name:              "string attr configured, required enabled - valid",
			attrValue:         types.StringValue("50"),
			requiredAttrValue: types.BoolValue(true),
			attrName:          "file_size_threshold",
			requiredAttrName:  "file_scanning",
			expectError:       false,
		},
		{
			name:              "string attr configured, required disabled - invalid",
			attrValue:         types.StringValue("50"),
			requiredAttrValue: types.BoolValue(false),
			attrName:          "file_size_threshold",
			requiredAttrName:  "file_scanning",
			expectError:       true,
		},
		{
			name:              "float attr configured, required enabled - valid",
			attrValue:         types.Float64Value(2),
			requiredAttrValue: types.BoolValue(true),
			attrName:          "match_count",
			requiredAttrName:  "content_scanning",
			expectError:       false,
		},
		{
			name:              "float attr configured, required disabled - invalid",
			attrValue:         types.Float64Value(2),
			requiredAttrValue: types.BoolValue(false),
			attrName:          "match_count",
			requiredAttrName:  "content_scanning",
			expectError:       true,
		},
		{
			name:              "list attr configured, required disabled - invalid",
			attrValue:         types.ListValueMust(types.StringType, []attr.Value{types.StringValue("a")}),
			requiredAttrValue: types.BoolValue(false),
			attrName:          "rule_ids",
			requiredAttrName:  "content_scanning",
			expectError:       true,
		},
		{
			name:              "required null - valid (skipped)",
			attrValue:         types.StringValue("50"),
			requiredAttrValue: types.BoolNull(),
			attrName:          "file_size_threshold",
			requiredAttrName:  "file_scanning",
			expectError:       false,
		},
		{
			name:              "required unknown - valid (skipped)",
			attrValue:         types.StringValue("50"),
			requiredAttrValue: types.BoolUnknown(),
			attrName:          "file_size_threshold",
			requiredAttrName:  "file_scanning",
			expectError:       false,
		},
		{
			name:              "attr null - valid (skipped)",
			attrValue:         types.StringNull(),
			requiredAttrValue: types.BoolValue(false),
			attrName:          "file_size_threshold",
			requiredAttrName:  "file_scanning",
			expectError:       false,
		},
		{
			name:              "attr unknown - valid (skipped)",
			attrValue:         types.Float64Unknown(),
			requiredAttrValue: types.BoolValue(false),
			attrName:          "match_count",
			requiredAttrName:  "content_scanning",
			expectError:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diags := AttributeRequiresBool(tt.attrValue, tt.requiredAttrValue, tt.attrName, tt.requiredAttrName)

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

func TestBoolRequiresStringValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		attrValue        types.Bool
		controllingValue types.String
		attrName         string
		controllingName  string
		requiredValue    string
		expectError      bool
	}{
		{
			name:             "attr enabled, controlling matches - valid",
			attrValue:        types.BoolValue(true),
			controllingValue: types.StringValue("strict"),
			attrName:         "block_everything",
			controllingName:  "mode",
			requiredValue:    "strict",
			expectError:      false,
		},
		{
			name:             "attr enabled, controlling differs - invalid",
			attrValue:        types.BoolValue(true),
			controllingValue: types.StringValue("permissive"),
			attrName:         "block_everything",
			controllingName:  "mode",
			requiredValue:    "strict",
			expectError:      true,
		},
		{
			// Switching a feature off never constrains what enables it, so an
			// explicit false must apply whatever the controlling value is.
			name:             "attr disabled, controlling differs - valid",
			attrValue:        types.BoolValue(false),
			controllingValue: types.StringValue("permissive"),
			attrName:         "block_everything",
			controllingName:  "mode",
			requiredValue:    "strict",
			expectError:      false,
		},
		{
			name:             "controlling null - valid (skipped)",
			attrValue:        types.BoolValue(true),
			controllingValue: types.StringNull(),
			attrName:         "block_everything",
			controllingName:  "mode",
			requiredValue:    "strict",
			expectError:      false,
		},
		{
			name:             "controlling unknown - valid (skipped)",
			attrValue:        types.BoolValue(true),
			controllingValue: types.StringUnknown(),
			attrName:         "block_everything",
			controllingName:  "mode",
			requiredValue:    "strict",
			expectError:      false,
		},
		{
			name:             "attr null - valid (skipped)",
			attrValue:        types.BoolNull(),
			controllingValue: types.StringValue("permissive"),
			attrName:         "block_everything",
			controllingName:  "mode",
			requiredValue:    "strict",
			expectError:      false,
		},
		{
			name:             "attr unknown - valid (skipped)",
			attrValue:        types.BoolUnknown(),
			controllingValue: types.StringValue("permissive"),
			attrName:         "block_everything",
			controllingName:  "mode",
			requiredValue:    "strict",
			expectError:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diags := BoolRequiresStringValue(
				tt.attrValue,
				tt.controllingValue,
				tt.attrName,
				tt.controllingName,
				tt.requiredValue,
			)

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
