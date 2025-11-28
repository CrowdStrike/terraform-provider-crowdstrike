package fcs

import (
	"context"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestIsValidAWSRegion(t *testing.T) {
	tests := []struct {
		name     string
		region   string
		expected bool
	}{
		// Valid commercial regions
		{"US East", "us-east-1", true},
		{"US West", "us-west-2", true},
		{"EU West", "eu-west-1", true},
		{"EU Central", "eu-central-1", true},
		{"AP Southeast", "ap-southeast-1", true},
		{"AP Northeast", "ap-northeast-2", true},
		{"CA Central", "ca-central-1", true},
		{"SA East", "sa-east-1", true},
		{"ME South", "me-south-1", true},
		{"AF South", "af-south-1", true},
		{"IL Central", "il-central-1", true},
		{"MX Central", "mx-central-1", true},

		// Valid GovCloud regions
		{"GovCloud West", "us-gov-west-1", true},
		{"GovCloud East", "us-gov-east-1", true},

		// Valid China regions
		{"China North", "cn-north-1", true},
		{"China Northwest", "cn-northwest-1", true},

		// Valid ISO regions
		{"ISO", "us-iso-east-1", true},
		{"ISOB", "us-isob-east-1", true},

		// Valid European Sovereign Cloud
		{"EUSC", "eusc-de-west-1", true},

		// Invalid regions
		{"Empty", "", false},
		{"Invalid prefix", "invalid-east-1", false},
		{"Missing direction", "us-1", false},
		{"Missing number", "us-east", false},
		{"Wrong format", "us_east_1", false},
		{"Too many parts", "us-east-1-extra", false},
		{"Wrong separator", "us.east.1", false},
		{"Invalid number format", "us-east-01", false},

		// Future regions that would be valid (demonstrating future-proofing)
		{"Future US region", "us-central-3", true},
		{"Future EU region", "eu-southeast-2", true},
		{"Future AP region", "ap-northwest-5", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidAWSRegion(tt.region)
			if result != tt.expected {
				t.Errorf("IsValidAWSRegion(%q) = %v; expected %v", tt.region, result, tt.expected)
			}
		})
	}
}

func TestRegexPatterns(t *testing.T) {
	// Test individual patterns
	tests := []struct {
		name    string
		pattern *regexp.Regexp
		valid   []string
		invalid []string
	}{
		{
			name:    "Commercial",
			pattern: CommercialRegionRegex,
			valid:   []string{"us-east-1", "eu-west-2", "ap-southeast-3", "ca-central-1"},
			invalid: []string{"us-gov-west-1", "cn-north-1", "invalid-region"},
		},
		{
			name:    "GovCloud",
			pattern: GovCloudRegionRegex,
			valid:   []string{"us-gov-west-1", "us-gov-east-1"},
			invalid: []string{"us-east-1", "eu-gov-west-1", "cn-gov-north-1"},
		},
		{
			name:    "China",
			pattern: ChinaRegionRegex,
			valid:   []string{"cn-north-1", "cn-northwest-1"},
			invalid: []string{"us-east-1", "cn-gov-west-1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, valid := range tt.valid {
				if !tt.pattern.MatchString(valid) {
					t.Errorf("%s pattern should match %q", tt.name, valid)
				}
			}

			for _, invalid := range tt.invalid {
				if tt.pattern.MatchString(invalid) {
					t.Errorf("%s pattern should NOT match %q", tt.name, invalid)
				}
			}
		})
	}
}

func TestAWSRegionValidator(t *testing.T) {
	tests := []struct {
		name          string
		region        string
		expectError   bool
		errorContains string
	}{
		{
			name:        "valid us-east-1",
			region:      "us-east-1",
			expectError: false,
		},
		{
			name:        "valid eu-west-1",
			region:      "eu-west-1",
			expectError: false,
		},
		{
			name:        "valid ap-southeast-1",
			region:      "ap-southeast-1",
			expectError: false,
		},
		{
			name:        "valid us-gov-west-1",
			region:      "us-gov-west-1",
			expectError: false,
		},
		{
			name:        "valid cn-north-1",
			region:      "cn-north-1",
			expectError: false,
		},
		{
			name:          "invalid region format",
			region:        "invalid-region",
			expectError:   true,
			errorContains: "not a valid AWS region",
		},
		{
			name:          "empty string",
			region:        "",
			expectError:   true,
			errorContains: "not a valid AWS region",
		},
		{
			name:          "wrong format underscore",
			region:        "us_east_1",
			expectError:   true,
			errorContains: "not a valid AWS region",
		},
		{
			name:        "future region that follows pattern",
			region:      "us-central-5",
			expectError: false,
		},
		{
			name:        "future EU region",
			region:      "eu-southeast-3",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := AWSRegionValidator()

			req := validator.StringRequest{
				Path:        path.Root("test"),
				ConfigValue: types.StringValue(tt.region),
			}

			resp := &validator.StringResponse{}

			v.ValidateString(context.Background(), req, resp)

			hasError := resp.Diagnostics.HasError()

			if tt.expectError && !hasError {
				t.Errorf("Expected validation error for region '%s', but got none", tt.region)
			}

			if !tt.expectError && hasError {
				t.Errorf("Expected no validation error for region '%s', but got: %v", tt.region, resp.Diagnostics.Errors())
			}

			if tt.expectError && hasError && tt.errorContains != "" {
				found := false
				for _, diag := range resp.Diagnostics.Errors() {
					if contains(diag.Summary(), tt.errorContains) || contains(diag.Detail(), tt.errorContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected error message to contain '%s', but got: %v", tt.errorContains, resp.Diagnostics.Errors())
				}
			}
		})
	}
}

func TestAWSRegionValidatorNullAndUnknown(t *testing.T) {
	v := AWSRegionValidator()

	// Test null value - should not error
	req := validator.StringRequest{
		Path:        path.Root("test"),
		ConfigValue: types.StringNull(),
	}
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Expected no error for null value, got: %v", resp.Diagnostics.Errors())
	}

	// Test unknown value - should not error
	req = validator.StringRequest{
		Path:        path.Root("test"),
		ConfigValue: types.StringUnknown(),
	}
	resp = &validator.StringResponse{}
	v.ValidateString(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Expected no error for unknown value, got: %v", resp.Diagnostics.Errors())
	}
}

// Helper function to check if a string contains a substring.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(substr) > 0 && indexOf(s, substr) >= 0))
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func TestAWSRegionsOrAllListValidator(t *testing.T) {
	tests := []struct {
		name          string
		regions       []string
		expectError   bool
		errorContains string
	}{
		{
			name:        "empty list is valid",
			regions:     []string{},
			expectError: false,
		},
		{
			name:        "single 'all' is valid",
			regions:     []string{"all"},
			expectError: false,
		},
		{
			name:        "single valid region",
			regions:     []string{"us-east-1"},
			expectError: false,
		},
		{
			name:        "multiple valid regions",
			regions:     []string{"us-east-1", "eu-west-1", "ap-southeast-1"},
			expectError: false,
		},
		{
			name:          "all mixed with other regions is invalid",
			regions:       []string{"all", "us-east-1"},
			expectError:   true,
			errorContains: "Cannot mix 'all' with specific regions",
		},
		{
			name:          "all mixed with other regions (different order) is invalid",
			regions:       []string{"us-east-1", "all"},
			expectError:   true,
			errorContains: "Cannot mix 'all' with specific regions",
		},
		{
			name:          "invalid region format",
			regions:       []string{"invalid-region"},
			expectError:   true,
			errorContains: "not a valid AWS region",
		},
		{
			name:          "mix of valid and invalid regions",
			regions:       []string{"us-east-1", "invalid-region"},
			expectError:   true,
			errorContains: "not a valid AWS region",
		},
		{
			name:        "multiple valid regions with different types",
			regions:     []string{"us-east-1", "eu-west-1", "us-gov-west-1", "cn-north-1"},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := AWSRegionsOrAllListValidator()

			// Convert string slice to list of types.String
			var elements []types.String
			for _, region := range tt.regions {
				elements = append(elements, types.StringValue(region))
			}

			listValue, diags := types.ListValueFrom(context.Background(), types.StringType, elements)
			if diags.HasError() {
				t.Fatalf("Failed to create list value: %v", diags.Errors())
			}

			req := validator.ListRequest{
				Path:        path.Root("test"),
				ConfigValue: listValue,
			}

			resp := &validator.ListResponse{}

			v.ValidateList(context.Background(), req, resp)

			hasError := resp.Diagnostics.HasError()

			if tt.expectError && !hasError {
				t.Errorf("Expected validation error for regions %v, but got none", tt.regions)
			}

			if !tt.expectError && hasError {
				t.Errorf("Expected no validation error for regions %v, but got: %v", tt.regions, resp.Diagnostics.Errors())
			}

			if tt.expectError && hasError && tt.errorContains != "" {
				found := false
				for _, diag := range resp.Diagnostics.Errors() {
					if contains(diag.Summary(), tt.errorContains) || contains(diag.Detail(), tt.errorContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected error message to contain '%s', but got: %v", tt.errorContains, resp.Diagnostics.Errors())
				}
			}
		})
	}
}

func TestAWSRegionsOrAllListValidatorNullAndUnknown(t *testing.T) {
	v := AWSRegionsOrAllListValidator()

	// Test null value - should not error
	req := validator.ListRequest{
		Path:        path.Root("test"),
		ConfigValue: types.ListNull(types.StringType),
	}
	resp := &validator.ListResponse{}
	v.ValidateList(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("Expected no error for null value, got: %v", resp.Diagnostics.Errors())
	}

	// Test unknown value - should not error
	req = validator.ListRequest{
		Path:        path.Root("test"),
		ConfigValue: types.ListUnknown(types.StringType),
	}
	resp = &validator.ListResponse{}
	v.ValidateList(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("Expected no error for unknown value, got: %v", resp.Diagnostics.Errors())
	}
}

func TestAWSRegionsOrAllNonEmptyListValidator(t *testing.T) {
	tests := []struct {
		name          string
		regions       []string
		expectError   bool
		errorContains string
	}{
		{
			name:          "empty list should error",
			regions:       []string{},
			expectError:   true,
			errorContains: "Empty Regions List Not Allowed",
		},
		{
			name:        "single 'all' is valid",
			regions:     []string{"all"},
			expectError: false,
		},
		{
			name:        "single valid region",
			regions:     []string{"us-east-1"},
			expectError: false,
		},
		{
			name:        "multiple valid regions",
			regions:     []string{"us-east-1", "eu-west-1", "ap-southeast-1"},
			expectError: false,
		},
		{
			name:          "all mixed with other regions is invalid",
			regions:       []string{"all", "us-east-1"},
			expectError:   true,
			errorContains: "Cannot mix 'all' with specific regions",
		},
		{
			name:          "all mixed with other regions (different order) is invalid",
			regions:       []string{"us-east-1", "all"},
			expectError:   true,
			errorContains: "Cannot mix 'all' with specific regions",
		},
		{
			name:          "invalid region format",
			regions:       []string{"invalid-region"},
			expectError:   true,
			errorContains: "not a valid AWS region",
		},
		{
			name:          "mix of valid and invalid regions",
			regions:       []string{"us-east-1", "invalid-region"},
			expectError:   true,
			errorContains: "not a valid AWS region",
		},
		{
			name:        "multiple valid regions with different types",
			regions:     []string{"us-east-1", "eu-west-1", "us-gov-west-1", "cn-north-1"},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := AWSRegionsOrAllNonEmptyListValidator()

			// Create list value from regions
			regionValues := make([]attr.Value, len(tt.regions))
			for i, region := range tt.regions {
				regionValues[i] = types.StringValue(region)
			}
			listValue := types.ListValueMust(types.StringType, regionValues)

			req := validator.ListRequest{
				Path:        path.Root("test"),
				ConfigValue: listValue,
			}
			resp := &validator.ListResponse{}

			v.ValidateList(context.Background(), req, resp)

			hasError := resp.Diagnostics.HasError()

			if tt.expectError && !hasError {
				t.Errorf("Expected validation error for regions %v, but got none", tt.regions)
			}

			if !tt.expectError && hasError {
				t.Errorf("Expected no validation error for regions %v, but got: %v", tt.regions, resp.Diagnostics.Errors())
			}

			if tt.expectError && hasError && tt.errorContains != "" {
				found := false
				for _, diag := range resp.Diagnostics.Errors() {
					if contains(diag.Summary(), tt.errorContains) || contains(diag.Detail(), tt.errorContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected error message to contain '%s', but got: %v", tt.errorContains, resp.Diagnostics.Errors())
				}
			}
		})
	}
}

func TestAWSRegionsOrAllNonEmptyListValidatorNullAndUnknown(t *testing.T) {
	v := AWSRegionsOrAllNonEmptyListValidator()

	// Test null value - should not error
	req := validator.ListRequest{
		Path:        path.Root("test"),
		ConfigValue: types.ListNull(types.StringType),
	}
	resp := &validator.ListResponse{}
	v.ValidateList(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("Expected no error for null value, got: %v", resp.Diagnostics.Errors())
	}

	// Test unknown value - should not error
	req = validator.ListRequest{
		Path:        path.Root("test"),
		ConfigValue: types.ListUnknown(types.StringType),
	}
	resp = &validator.ListResponse{}
	v.ValidateList(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("Expected no error for unknown value, got: %v", resp.Diagnostics.Errors())
	}
}
