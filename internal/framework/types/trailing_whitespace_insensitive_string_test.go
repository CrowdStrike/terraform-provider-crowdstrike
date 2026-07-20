package types

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func TestTrailingWhitespaceInsensitiveString_StringSemanticEquals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		current  string
		new      string
		expected bool
	}{
		{
			name:     "both have no trailing whitespace",
			current:  "hello world",
			new:      "hello world",
			expected: true,
		},
		{
			name:     "current has trailing newline, new doesn't",
			current:  "hello world\n",
			new:      "hello world",
			expected: true,
		},
		{
			name:     "new has trailing newline, current doesn't",
			current:  "hello world",
			new:      "hello world\n",
			expected: true,
		},
		{
			name:     "both have trailing newlines",
			current:  "hello world\n",
			new:      "hello world\n",
			expected: true,
		},
		{
			name:     "multiple trailing newlines",
			current:  "hello world\n\n\n",
			new:      "hello world",
			expected: true,
		},
		{
			name:     "trailing spaces",
			current:  "hello world   ",
			new:      "hello world",
			expected: true,
		},
		{
			name:     "trailing tabs",
			current:  "hello world\t\t",
			new:      "hello world",
			expected: true,
		},
		{
			name:     "mixed trailing whitespace",
			current:  "hello world \t\n\r",
			new:      "hello world",
			expected: true,
		},
		{
			name:     "vertical tab",
			current:  "hello world\v",
			new:      "hello world",
			expected: true,
		},
		{
			name:     "form feed",
			current:  "hello world\f",
			new:      "hello world",
			expected: true,
		},
		{
			name:     "different content",
			current:  "hello world",
			new:      "goodbye world",
			expected: false,
		},
		{
			name:     "different content with trailing whitespace",
			current:  "hello world\n",
			new:      "goodbye world\n",
			expected: false,
		},
		{
			name:     "whitespace in middle preserved",
			current:  "hello\nworld\n",
			new:      "hello\nworld",
			expected: true,
		},
		{
			name:     "whitespace in middle differs",
			current:  "hello\nworld",
			new:      "hello world",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			currentVal := TrailingWhitespaceInsensitiveString{
				StringValue: basetypes.NewStringValue(tt.current),
			}
			newVal := TrailingWhitespaceInsensitiveString{
				StringValue: basetypes.NewStringValue(tt.new),
			}

			equal, diags := currentVal.StringSemanticEquals(context.Background(), newVal)

			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags)
			}

			if equal != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, equal)
			}
		})
	}
}
