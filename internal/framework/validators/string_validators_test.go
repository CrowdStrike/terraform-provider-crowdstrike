package validators

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

func TestStringNotWhitespaceValidator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		value       types.String
		expectError bool
	}{
		{
			name:        "valid string",
			value:       types.StringValue("test"),
			expectError: false,
		},
		{
			name:        "valid string with spaces",
			value:       types.StringValue("test value"),
			expectError: false,
		},
		{
			name:        "empty string",
			value:       types.StringValue(""),
			expectError: true,
		},
		{
			name:        "single space",
			value:       types.StringValue(" "),
			expectError: true,
		},
		{
			name:        "multiple spaces",
			value:       types.StringValue("   "),
			expectError: true,
		},
		{
			name:        "tabs only",
			value:       types.StringValue("\t\t"),
			expectError: true,
		},
		{
			name:        "newlines only",
			value:       types.StringValue("\n\n"),
			expectError: true,
		},
		{
			name:        "mixed whitespace",
			value:       types.StringValue(" \t\n "),
			expectError: true,
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

			StringNotWhitespace().ValidateString(context.Background(), req, resp)

			if tt.expectError {
				assert.True(t, resp.Diagnostics.HasError(), "Expected error but got none for value: %q", tt.value.ValueString())
			} else {
				assert.False(t, resp.Diagnostics.HasError(), "Unexpected error for value: %q", tt.value.ValueString())
			}
		})
	}
}

func TestStringIsEmailAddressValidator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		value       types.String
		expectError bool
	}{
		{
			name:        "valid simple email",
			value:       types.StringValue("user@example.com"),
			expectError: false,
		},
		{
			name:        "valid email with subdomain",
			value:       types.StringValue("test@mail.example.com"),
			expectError: false,
		},
		{
			name:        "valid email with plus",
			value:       types.StringValue("user+tag@example.com"),
			expectError: false,
		},
		{
			name:        "valid email with dots",
			value:       types.StringValue("first.last@example.com"),
			expectError: false,
		},
		{
			name:        "valid email with numbers",
			value:       types.StringValue("user123@example456.com"),
			expectError: false,
		},
		{
			name:        "valid email with underscore",
			value:       types.StringValue("user_name@example.com"),
			expectError: false,
		},
		{
			name:        "valid email with percent",
			value:       types.StringValue("user%test@example.com"),
			expectError: false,
		},
		{
			name:        "valid email with hyphen in domain",
			value:       types.StringValue("user@my-domain.com"),
			expectError: false,
		},
		{
			name:        "invalid - no at symbol",
			value:       types.StringValue("userexample.com"),
			expectError: true,
		},
		{
			name:        "invalid - missing domain",
			value:       types.StringValue("user@"),
			expectError: true,
		},
		{
			name:        "invalid - missing username",
			value:       types.StringValue("@example.com"),
			expectError: true,
		},
		{
			name:        "invalid - missing TLD",
			value:       types.StringValue("user@example"),
			expectError: true,
		},
		{
			name:        "invalid - double at",
			value:       types.StringValue("user@@example.com"),
			expectError: true,
		},
		{
			name:        "invalid - spaces",
			value:       types.StringValue("user @example.com"),
			expectError: true,
		},
		{
			name:        "invalid - just text",
			value:       types.StringValue("notanemail"),
			expectError: true,
		},
		{
			name:        "invalid - TLD too short",
			value:       types.StringValue("user@example.c"),
			expectError: true,
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

			StringIsEmailAddress().ValidateString(context.Background(), req, resp)

			if tt.expectError {
				assert.True(t, resp.Diagnostics.HasError(), "Expected error but got none for value: %q", tt.value.ValueString())
			} else {
				assert.False(t, resp.Diagnostics.HasError(), "Unexpected error for value: %q", tt.value.ValueString())
			}
		})
	}
}

func TestSortFieldValidator(t *testing.T) {
	t.Parallel()

	validFields := []string{"name", "created_at", "status"}

	tests := []struct {
		name        string
		value       types.String
		expectError bool
	}{
		{
			name:        "valid field with .asc",
			value:       types.StringValue("name.asc"),
			expectError: false,
		},
		{
			name:        "valid field with .desc",
			value:       types.StringValue("name.desc"),
			expectError: false,
		},
		{
			name:        "valid field created_at with .asc",
			value:       types.StringValue("created_at.asc"),
			expectError: false,
		},
		{
			name:        "valid field status with .desc",
			value:       types.StringValue("status.desc"),
			expectError: false,
		},
		{
			name:        "invalid - missing suffix",
			value:       types.StringValue("name"),
			expectError: true,
		},
		{
			name:        "invalid - wrong suffix",
			value:       types.StringValue("name.ascending"),
			expectError: true,
		},
		{
			name:        "invalid - invalid field name",
			value:       types.StringValue("invalid_field.asc"),
			expectError: true,
		},
		{
			name:        "invalid - empty string",
			value:       types.StringValue(""),
			expectError: true,
		},
		{
			name:        "invalid - only suffix",
			value:       types.StringValue(".asc"),
			expectError: true,
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

			SortField(validFields).ValidateString(context.Background(), req, resp)

			if tt.expectError {
				assert.True(t, resp.Diagnostics.HasError(), "Expected error but got none for value: %q", tt.value.ValueString())
			} else {
				assert.False(t, resp.Diagnostics.HasError(), "Unexpected error for value: %q", tt.value.ValueString())
			}
		})
	}
}

func TestSortFieldValidator_MultipleErrors(t *testing.T) {
	t.Parallel()

	validFields := []string{"name", "created_at", "status"}

	req := validator.StringRequest{
		Path:           path.Root("test"),
		PathExpression: path.MatchRoot("test"),
		ConfigValue:    types.StringValue("invalid_field"),
	}
	resp := &validator.StringResponse{}

	SortField(validFields).ValidateString(context.Background(), req, resp)

	assert.True(t, resp.Diagnostics.HasError(), "Expected errors for invalid field without suffix")
	assert.Equal(t, 2, resp.Diagnostics.ErrorsCount(), "Expected 2 errors: missing suffix and invalid field name")

	errors := resp.Diagnostics.Errors()
	errorMessages := make([]string, len(errors))
	for i, err := range errors {
		errorMessages[i] = err.Summary()
	}

	assert.Contains(t, errorMessages, "Invalid Sort Field Format", "Should contain format error")
	assert.Contains(t, errorMessages, "Invalid Sort Field", "Should contain invalid field error")
}
