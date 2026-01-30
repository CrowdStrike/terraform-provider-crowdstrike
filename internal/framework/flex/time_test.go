package flex

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
)

func TestRFC3339ValueToFramework(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected func() timetypes.RFC3339
	}{
		{
			name:  "valid RFC3339 string",
			input: "2025-01-29T10:30:45Z",
			expected: func() timetypes.RFC3339 {
				val, _ := timetypes.NewRFC3339Value("2025-01-29T10:30:45Z")
				return val
			},
		},
		{
			name:  "valid RFC3339 string with timezone",
			input: "2025-01-29T10:30:45-05:00",
			expected: func() timetypes.RFC3339 {
				val, _ := timetypes.NewRFC3339Value("2025-01-29T10:30:45-05:00")
				return val
			},
		},
		{
			name:     "empty string returns null",
			input:    "",
			expected: timetypes.NewRFC3339Null,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, diags := RFC3339ValueToFramework(tt.input)
			expected := tt.expected()

			if diags.HasError() {
				t.Errorf("Unexpected diagnostics errors: %v", diags)
			}

			if result.IsNull() != expected.IsNull() {
				t.Errorf("IsNull() mismatch: got %v, want %v", result.IsNull(), expected.IsNull())
			}

			if !result.IsNull() && !expected.IsNull() {
				if result.ValueString() != expected.ValueString() {
					t.Errorf("ValueString() mismatch: got %v, want %v", result.ValueString(), expected.ValueString())
				}
			}
		})
	}
}

func TestRFC3339PointerToFramework(t *testing.T) {
	validTime := "2025-01-29T10:30:45Z"
	emptyString := ""

	tests := []struct {
		name     string
		input    *string
		expected func() timetypes.RFC3339
	}{
		{
			name:  "valid RFC3339 pointer",
			input: &validTime,
			expected: func() timetypes.RFC3339 {
				val, _ := timetypes.NewRFC3339Value(validTime)
				return val
			},
		},
		{
			name:     "nil pointer returns null",
			input:    nil,
			expected: timetypes.NewRFC3339Null,
		},
		{
			name:     "pointer to empty string returns null",
			input:    &emptyString,
			expected: timetypes.NewRFC3339Null,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, diags := RFC3339PointerToFramework(tt.input)
			expected := tt.expected()

			if diags.HasError() {
				t.Errorf("Unexpected diagnostics errors: %v", diags)
			}

			if result.IsNull() != expected.IsNull() {
				t.Errorf("IsNull() mismatch: got %v, want %v", result.IsNull(), expected.IsNull())
			}

			if !result.IsNull() && !expected.IsNull() {
				if result.ValueString() != expected.ValueString() {
					t.Errorf("ValueString() mismatch: got %v, want %v", result.ValueString(), expected.ValueString())
				}
			}
		})
	}
}

func TestFrameworkToRFC3339Pointer(t *testing.T) {
	validTime := "2025-01-29T10:30:45Z"
	validRFC3339, _ := timetypes.NewRFC3339Value(validTime)
	nullRFC3339 := timetypes.NewRFC3339Null()
	unknownRFC3339 := timetypes.NewRFC3339Unknown()

	tests := []struct {
		name     string
		input    timetypes.RFC3339
		expected *string
	}{
		{
			name:     "valid RFC3339 value",
			input:    validRFC3339,
			expected: &validTime,
		},
		{
			name:  "null RFC3339 returns pointer to empty string",
			input: nullRFC3339,
			expected: func() *string {
				empty := ""
				return &empty
			}(),
		},
		{
			name:  "unknown RFC3339 returns pointer to empty string",
			input: unknownRFC3339,
			expected: func() *string {
				empty := ""
				return &empty
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FrameworkToRFC3339Pointer(tt.input)

			if result == nil {
				t.Errorf("Expected non-nil pointer, got nil")
				return
			}

			if *result != *tt.expected {
				t.Errorf("Value mismatch: got %v, want %v", *result, *tt.expected)
			}
		})
	}
}

func TestRFC3339ValueToFramework_Generic(t *testing.T) {
	// Test with different string types
	type customString string

	customTime := customString("2025-01-29T10:30:45Z")
	result, diags := RFC3339ValueToFramework(customTime)

	if diags.HasError() {
		t.Errorf("Unexpected diagnostics errors: %v", diags)
	}

	if result.IsNull() {
		t.Errorf("Expected non-null value for custom string type")
	}

	if result.ValueString() != "2025-01-29T10:30:45Z" {
		t.Errorf("Value mismatch: got %v, want %v", result.ValueString(), "2025-01-29T10:30:45Z")
	}
}
