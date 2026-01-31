package types

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOptionalString(t *testing.T) {
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
			input:    "test",
			expected: types.StringValue("test"),
		},
		{
			name:     "whitespace string returns value",
			input:    "   ",
			expected: types.StringValue("   "),
		},
		{
			name:     "special characters returns value",
			input:    "test@example.com",
			expected: types.StringValue("test@example.com"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := OptionalString(tt.input)

			assert.Equal(t, tt.expected.IsNull(), result.IsNull())
			if !result.IsNull() {
				assert.Equal(t, tt.expected.ValueString(), result.ValueString())
			}
		})
	}
}

func TestOptionalStringList(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		input         []string
		expectNull    bool
		expectError   bool
		expectedValue []string
	}{
		{
			name:       "empty slice returns null",
			input:      []string{},
			expectNull: true,
		},
		{
			name:       "nil slice returns null",
			input:      nil,
			expectNull: true,
		},
		{
			name:          "single element returns value",
			input:         []string{"test"},
			expectNull:    false,
			expectedValue: []string{"test"},
		},
		{
			name:          "multiple elements returns value",
			input:         []string{"test1", "test2", "test3"},
			expectNull:    false,
			expectedValue: []string{"test1", "test2", "test3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, diags := OptionalStringList(ctx, tt.input)

			if tt.expectError {
				assert.True(t, diags.HasError(), "expected error but got none")
			} else {
				assert.False(t, diags.HasError(), "unexpected error: %v", diags)
			}

			assert.Equal(t, tt.expectNull, result.IsNull())

			if !tt.expectNull && !diags.HasError() {
				var actualValue []string
				diags := result.ElementsAs(ctx, &actualValue, false)
				require.False(t, diags.HasError(), "ElementsAs() error: %v", diags)
				assert.Equal(t, tt.expectedValue, actualValue)
			}
		})
	}
}

func TestOptionalStringSet(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		input         []string
		expectNull    bool
		expectError   bool
		expectedValue []string
	}{
		{
			name:       "empty slice returns null",
			input:      []string{},
			expectNull: true,
		},
		{
			name:       "nil slice returns null",
			input:      nil,
			expectNull: true,
		},
		{
			name:          "single element returns value",
			input:         []string{"test"},
			expectNull:    false,
			expectedValue: []string{"test"},
		},
		{
			name:          "multiple elements returns value",
			input:         []string{"test1", "test2", "test3"},
			expectNull:    false,
			expectedValue: []string{"test1", "test2", "test3"},
		},
		{
			name:        "duplicate elements return error",
			input:       []string{"test1", "test2", "test1"},
			expectNull:  false,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, diags := OptionalStringSet(ctx, tt.input)

			if tt.expectError {
				assert.True(t, diags.HasError(), "expected error but got none")
			} else {
				assert.False(t, diags.HasError(), "unexpected error: %v", diags)
			}

			assert.Equal(t, tt.expectNull, result.IsNull())

			if !tt.expectNull && !diags.HasError() {
				var actualValue []string
				diags := result.ElementsAs(ctx, &actualValue, false)
				require.False(t, diags.HasError(), "ElementsAs() error: %v", diags)
				assert.ElementsMatch(t, tt.expectedValue, actualValue)
			}
		})
	}
}
