package mlexclusion

import "testing"

func TestIsMLExclusionSweepableTestPattern(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{
			name:     "basic test pattern",
			value:    "/tmp/tf-acc-test-abc123/*",
			expected: true,
		},
		{
			name:     "test pattern with suffix",
			value:    "/tmp/tf-acc-test-abc123-updated/*",
			expected: true,
		},
		{
			name:     "wrong directory",
			value:    "/var/tf-acc-test-abc123/*",
			expected: false,
		},
		{
			name:     "contains prefix only",
			value:    "/tmp/not-a-test-tf-acc-test-abc123/*",
			expected: false,
		},
		{
			name:     "missing wildcard suffix",
			value:    "/tmp/tf-acc-test-abc123",
			expected: false,
		},
		{
			name:     "nested path segment",
			value:    "/tmp/tf-acc-test-abc123/extra/*",
			expected: false,
		},
		{
			name:     "empty generated name",
			value:    "/tmp/tf-acc-test-/*",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if actual := isMLExclusionSweepableTestPattern(tt.value); actual != tt.expected {
				t.Fatalf("expected %t, got %t for %q", tt.expected, actual, tt.value)
			}
		})
	}
}
