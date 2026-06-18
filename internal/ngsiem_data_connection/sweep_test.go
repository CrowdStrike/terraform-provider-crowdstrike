package ngsiemdataconnection

import "testing"

// The list filter uses FQL `~` (a CONTAINS match), so the prefix check is the real guard against
// deleting a production connection whose name merely contains the test prefix. The "contains but does
// not start with" case is the one that matters.
func TestIsSweepableTestConnection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{name: "exact test prefix", value: "tf-acc-test-abc123", expected: true},
		{name: "test prefix with suffix", value: "tf-acc-test-abc123-updated", expected: true},
		{name: "contains prefix but does not start with it", value: "prod-tf-acc-test-abc123", expected: false},
		{name: "unrelated name", value: "my-real-connection", expected: false},
		{name: "empty name", value: "", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isSweepableTestConnection(tt.value); got != tt.expected {
				t.Fatalf("isSweepableTestConnection(%q) = %t, want %t", tt.value, got, tt.expected)
			}
		})
	}
}
