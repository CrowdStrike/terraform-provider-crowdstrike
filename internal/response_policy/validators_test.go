package responsepolicy

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

func TestBoolRequiresPlatform(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		attrValue      types.Bool
		platformValue  types.String
		attrName       string
		validPlatforms []string
		expectError    bool
	}{
		{
			name:           "enabled on valid platform (Windows) - valid",
			attrValue:      types.BoolValue(true),
			platformValue:  types.StringValue("Windows"),
			attrName:       "falcon_scripts",
			validPlatforms: []string{"Windows"},
			expectError:    false,
		},
		{
			name:           "enabled on invalid platform (Mac) - invalid",
			attrValue:      types.BoolValue(true),
			platformValue:  types.StringValue("Mac"),
			attrName:       "falcon_scripts",
			validPlatforms: []string{"Windows"},
			expectError:    true,
		},
		{
			name:           "enabled on valid platform (one of many) - valid",
			attrValue:      types.BoolValue(true),
			platformValue:  types.StringValue("Mac"),
			attrName:       "put_and_run_command",
			validPlatforms: []string{"Windows", "Mac"},
			expectError:    false,
		},
		{
			name:           "enabled on invalid platform (Linux) - invalid",
			attrValue:      types.BoolValue(true),
			platformValue:  types.StringValue("Linux"),
			attrName:       "put_and_run_command",
			validPlatforms: []string{"Windows", "Mac"},
			expectError:    true,
		},
		{
			name:           "disabled on invalid platform - valid",
			attrValue:      types.BoolValue(false),
			platformValue:  types.StringValue("Linux"),
			attrName:       "falcon_scripts",
			validPlatforms: []string{"Windows"},
			expectError:    false,
		},
		{
			name:           "attr null - valid (skipped)",
			attrValue:      types.BoolNull(),
			platformValue:  types.StringValue("Linux"),
			attrName:       "falcon_scripts",
			validPlatforms: []string{"Windows"},
			expectError:    false,
		},
		{
			name:           "platform null - valid (skipped)",
			attrValue:      types.BoolValue(true),
			platformValue:  types.StringNull(),
			attrName:       "falcon_scripts",
			validPlatforms: []string{"Windows"},
			expectError:    false,
		},
		{
			name:           "attr unknown - valid (skipped)",
			attrValue:      types.BoolUnknown(),
			platformValue:  types.StringValue("Linux"),
			attrName:       "falcon_scripts",
			validPlatforms: []string{"Windows"},
			expectError:    false,
		},
		{
			name:           "platform unknown - valid (skipped)",
			attrValue:      types.BoolValue(true),
			platformValue:  types.StringUnknown(),
			attrName:       "falcon_scripts",
			validPlatforms: []string{"Windows"},
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diags := boolRequiresPlatform(tt.attrValue, tt.platformValue, tt.attrName, tt.validPlatforms)

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
