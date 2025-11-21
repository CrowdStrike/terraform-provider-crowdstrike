package flex

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

func TestStringValueToFramework(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    string
		expected types.String
	}{
		{
			name:     "empty string returns null",
			input:    "",
			expected: types.StringNull(),
		},
		{
			name:     "non-empty string returns value",
			input:    "test-value",
			expected: types.StringValue("test-value"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StringValueToFramework(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
