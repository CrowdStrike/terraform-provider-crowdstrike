package flex_test

import (
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

func TestFlattenStringValueMapOrEmpty(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		values   map[string]string
		expected types.Map
	}{
		{
			name:     "nil map returns empty map",
			values:   nil,
			expected: acctest.StringMapOrEmpty(nil),
		},
		{
			name:     "empty map returns empty map",
			values:   map[string]string{},
			expected: acctest.StringMapOrEmpty(map[string]string{}),
		},
		{
			name:     "map with valid values returns map",
			values:   map[string]string{"env": "test", "team": "security"},
			expected: acctest.StringMapOrEmpty(map[string]string{"env": "test", "team": "security"}),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			result, diags := flex.FlattenStringValueMapOrEmpty(t.Context(), tc.values)

			assert.False(t, diags.HasError(), "unexpected diagnostics errors: %v", diags.Errors())
			assert.False(t, result.IsNull(), "expected a non-null map")
			assert.True(t, result.Equal(tc.expected), "expected %v, got %v", tc.expected, result)
		})
	}
}
