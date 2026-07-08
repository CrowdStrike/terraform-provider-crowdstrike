package itautomation

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

func TestDurationCanonicalValidator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		value        types.String
		expectError  bool
		errorSummary string
	}{
		{
			name:        "valid minutes",
			value:       types.StringValue("30m"),
			expectError: false,
		},
		{
			name:        "valid single minute minimum",
			value:       types.StringValue("1m"),
			expectError: false,
		},
		{
			name:        "valid hours",
			value:       types.StringValue("1h"),
			expectError: false,
		},
		{
			name:        "valid days",
			value:       types.StringValue("2d"),
			expectError: false,
		},
		{
			name:        "valid non-divisible minutes",
			value:       types.StringValue("90m"),
			expectError: false,
		},
		{
			name:        "valid non-divisible hours",
			value:       types.StringValue("25h"),
			expectError: false,
		},
		{
			name:         "invalid - below minimum seconds",
			value:        types.StringValue("30s"),
			expectError:  true,
			errorSummary: "Invalid duration",
		},
		{
			name:         "invalid - 1s below minimum",
			value:        types.StringValue("1s"),
			expectError:  true,
			errorSummary: "Invalid duration",
		},
		{
			name:         "invalid - 60s should be 1m",
			value:        types.StringValue("60s"),
			expectError:  true,
			errorSummary: "Duration not in canonical form",
		},
		{
			name:         "invalid - 60m should be 1h",
			value:        types.StringValue("60m"),
			expectError:  true,
			errorSummary: "Duration not in canonical form",
		},
		{
			name:         "invalid - 24h should be 1d",
			value:        types.StringValue("24h"),
			expectError:  true,
			errorSummary: "Duration not in canonical form",
		},
		{
			name:         "invalid - 120m should be 2h",
			value:        types.StringValue("120m"),
			expectError:  true,
			errorSummary: "Duration not in canonical form",
		},
		{
			name:        "valid - 90s above minimum and not divisible",
			value:       types.StringValue("90s"),
			expectError: false,
		},
		{
			name:         "invalid - decimal",
			value:        types.StringValue("1.5h"),
			expectError:  true,
			errorSummary: "Invalid duration",
		},
		{
			name:         "invalid - multi-unit",
			value:        types.StringValue("1h30m"),
			expectError:  true,
			errorSummary: "Invalid duration",
		},
		{
			name:         "invalid - leading zero",
			value:        types.StringValue("01m"),
			expectError:  true,
			errorSummary: "Invalid duration",
		},
		{
			name:         "invalid - zero value",
			value:        types.StringValue("0m"),
			expectError:  true,
			errorSummary: "Invalid duration",
		},
		{
			name:         "invalid - no unit",
			value:        types.StringValue("30"),
			expectError:  true,
			errorSummary: "Invalid duration",
		},
		{
			name:         "invalid - unknown unit",
			value:        types.StringValue("5w"),
			expectError:  true,
			errorSummary: "Invalid duration",
		},
		{
			name:         "invalid - empty string",
			value:        types.StringValue(""),
			expectError:  true,
			errorSummary: "Invalid duration",
		},
		{
			name:         "invalid - negative",
			value:        types.StringValue("-5m"),
			expectError:  true,
			errorSummary: "Invalid duration",
		},
		{
			name:        "null value",
			value:       types.StringNull(),
			expectError: false,
		},
		{
			name:        "unknown value",
			value:       types.StringUnknown(),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := validator.StringRequest{
				Path:           path.Root("test"),
				PathExpression: path.MatchRoot("test"),
				ConfigValue:    tt.value,
			}
			resp := &validator.StringResponse{}

			DurationCanonicalValidator().ValidateString(context.Background(), req, resp)

			if tt.expectError {
				assert.True(t, resp.Diagnostics.HasError(), "Expected error but got none for value: %q", tt.value.ValueString())
				if tt.errorSummary != "" {
					errors := resp.Diagnostics.Errors()
					summaries := make([]string, len(errors))
					for i, err := range errors {
						summaries[i] = err.Summary()
					}
					assert.Contains(t, summaries, tt.errorSummary, "Unexpected error summary for value: %q", tt.value.ValueString())
				}
			} else {
				assert.False(t, resp.Diagnostics.HasError(), "Unexpected error for value: %q", tt.value.ValueString())
			}
		})
	}
}

func TestCanonicalizeDuration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    string
		expected string
		ok       bool
	}{
		{name: "minute stays minute", value: "1m", expected: "1m", ok: true},
		{name: "30m stays 30m", value: "30m", expected: "30m", ok: true},
		{name: "60s rolls to 1m", value: "60s", expected: "1m", ok: true},
		{name: "120s rolls to 2m", value: "120s", expected: "2m", ok: true},
		{name: "60m rolls to 1h", value: "60m", expected: "1h", ok: true},
		{name: "120m rolls to 2h", value: "120m", expected: "2h", ok: true},
		{name: "90m stays 90m", value: "90m", expected: "90m", ok: true},
		{name: "24h rolls to 1d", value: "24h", expected: "1d", ok: true},
		{name: "48h rolls to 2d", value: "48h", expected: "2d", ok: true},
		{name: "25h stays 25h", value: "25h", expected: "25h", ok: true},
		{name: "1440m rolls to 1d", value: "1440m", expected: "1d", ok: true},
		{name: "3600s rolls to 1h", value: "3600s", expected: "1h", ok: true},
		{name: "below minimum 30s", value: "30s", expected: "", ok: false},
		{name: "below minimum 59s", value: "59s", expected: "", ok: false},
		{name: "zero", value: "0m", expected: "", ok: false},
		{name: "empty", value: "", expected: "", ok: false},
		{name: "single char", value: "m", expected: "", ok: false},
		{name: "non-numeric", value: "xm", expected: "", ok: false},
		{name: "unknown unit", value: "5w", expected: "", ok: false},
		{name: "negative", value: "-5m", expected: "", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := canonicalizeDuration(tt.value)
			assert.Equal(t, tt.ok, ok, "ok mismatch for value: %q", tt.value)
			assert.Equal(t, tt.expected, got, "canonical mismatch for value: %q", tt.value)
		})
	}
}
