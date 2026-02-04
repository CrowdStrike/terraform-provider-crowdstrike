package flex

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

func TestInt32PointerToFramework(t *testing.T) {
	t.Parallel()
	var zero int32 = 0
	var positive int32 = 42
	var negative int32 = -10

	tests := []struct {
		name     string
		input    *int32
		expected types.Int32
	}{
		{
			name:     "nil pointer returns null",
			input:    nil,
			expected: types.Int32Null(),
		},
		{
			name:     "pointer to zero returns zero value",
			input:    &zero,
			expected: types.Int32Value(0),
		},
		{
			name:     "pointer to positive int32 returns value",
			input:    &positive,
			expected: types.Int32Value(42),
		},
		{
			name:     "pointer to negative int32 returns value",
			input:    &negative,
			expected: types.Int32Value(-10),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Int32PointerToFramework(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFrameworkToInt32Pointer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		input       types.Int32
		expectNil   bool
		expectValue int32
	}{
		{
			name:      "null int32 returns nil",
			input:     types.Int32Null(),
			expectNil: true,
		},
		{
			name:      "unknown int32 returns nil",
			input:     types.Int32Unknown(),
			expectNil: true,
		},
		{
			name:        "zero value returns pointer to zero",
			input:       types.Int32Value(0),
			expectNil:   false,
			expectValue: 0,
		},
		{
			name:        "positive int32 returns pointer to value",
			input:       types.Int32Value(42),
			expectNil:   false,
			expectValue: 42,
		},
		{
			name:        "negative int32 returns pointer to value",
			input:       types.Int32Value(-10),
			expectNil:   false,
			expectValue: -10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FrameworkToInt32Pointer(tt.input)
			if tt.expectNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, tt.expectValue, *result)
			}
		})
	}
}
