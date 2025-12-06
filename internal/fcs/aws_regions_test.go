package fcs_test

import (
	"context"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/fcs"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

func TestIsValidAWSRegion(t *testing.T) {
	t.Parallel()
	testCases := []struct {
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

		// Future regions that would be valid
		{"Future US region", "us-central-3", true},
		{"Future EU region", "eu-southeast-2", true},
		{"Future AP region", "ap-northwest-5", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := fcs.IsValidAWSRegion(tc.region)
			assert.Equal(t, tc.expected, result, "IsValidAWSRegion(%q) should return %v", tc.region, tc.expected)
		})
	}
}

func TestRegexPatterns(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name    string
		pattern *regexp.Regexp
		valid   []string
		invalid []string
	}{
		{
			name:    "Commercial",
			pattern: fcs.CommercialRegionRegex,
			valid:   []string{"us-east-1", "eu-west-2", "ap-southeast-3", "ca-central-1"},
			invalid: []string{"us-gov-west-1", "cn-north-1", "invalid-region"},
		},
		{
			name:    "GovCloud",
			pattern: fcs.GovCloudRegionRegex,
			valid:   []string{"us-gov-west-1", "us-gov-east-1"},
			invalid: []string{"us-east-1", "eu-gov-west-1", "cn-gov-north-1"},
		},
		{
			name:    "China",
			pattern: fcs.ChinaRegionRegex,
			valid:   []string{"cn-north-1", "cn-northwest-1"},
			invalid: []string{"us-east-1", "cn-gov-west-1"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, valid := range tc.valid {
				assert.True(t, tc.pattern.MatchString(valid), "%s pattern should match %q", tc.name, valid)
			}

			for _, invalid := range tc.invalid {
				assert.False(t, tc.pattern.MatchString(invalid), "%s pattern should NOT match %q", tc.name, invalid)
			}
		})
	}
}

func TestAWSRegionValidator(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name          string
		region        types.String
		expectError   bool
		errorContains string
	}{
		{
			name:        "valid us-east-1",
			region:      types.StringValue("us-east-1"),
			expectError: false,
		},
		{
			name:        "valid eu-west-1",
			region:      types.StringValue("eu-west-1"),
			expectError: false,
		},
		{
			name:        "valid ap-southeast-1",
			region:      types.StringValue("ap-southeast-1"),
			expectError: false,
		},
		{
			name:        "valid us-gov-west-1",
			region:      types.StringValue("us-gov-west-1"),
			expectError: false,
		},
		{
			name:        "valid cn-north-1",
			region:      types.StringValue("cn-north-1"),
			expectError: false,
		},
		{
			name:          "invalid region format",
			region:        types.StringValue("invalid-region"),
			expectError:   true,
			errorContains: "not a valid AWS region",
		},
		{
			name:          "empty string",
			region:        types.StringValue(""),
			expectError:   true,
			errorContains: "not a valid AWS region",
		},
		{
			name:          "wrong format underscore",
			region:        types.StringValue("us_east_1"),
			expectError:   true,
			errorContains: "not a valid AWS region",
		},
		{
			name:        "future region that follows pattern",
			region:      types.StringValue("us-central-5"),
			expectError: false,
		},
		{
			name:        "future EU region",
			region:      types.StringValue("eu-southeast-3"),
			expectError: false,
		},
		{
			name:        "null value",
			region:      types.StringNull(),
			expectError: false,
		},
		{
			name:        "unknown value",
			region:      types.StringUnknown(),
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v := fcs.AWSRegionValidator()
			req := validator.StringRequest{
				Path:        path.Root("test"),
				ConfigValue: tc.region,
			}
			resp := &validator.StringResponse{}
			v.ValidateString(context.Background(), req, resp)

			hasError := resp.Diagnostics.HasError()
			if tc.expectError {
				assert.True(t, hasError, "Expected validation error for region '%s'", tc.region)
				if tc.errorContains != "" {
					errs := resp.Diagnostics.Errors()
					assert.NotEmpty(t, errs)
					errorText := errs[0].Summary() + " " + errs[0].Detail()
					assert.Contains(t, errorText, tc.errorContains)
				}
			} else {
				assert.False(t, hasError, "Expected no validation error for region '%s', but got: %v", tc.region, resp.Diagnostics.Errors())
			}
		})
	}
}

func TestAWSRegionsOrAllListValidator(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		list          types.List
		expectError   bool
		errorContains string
	}{
		{
			name:        "empty list",
			list:        acctest.StringListOrNull(),
			expectError: false,
		},
		{
			name:        "single 'all' is valid",
			list:        acctest.StringListOrNull("all"),
			expectError: false,
		},
		{
			name:        "single valid region",
			list:        acctest.StringListOrNull("us-east-1"),
			expectError: false,
		},
		{
			name:        "multiple valid regions",
			list:        acctest.StringListOrNull("us-east-1", "eu-west-1", "ap-southeast-1"),
			expectError: false,
		},
		{
			name:          "all mixed with other regions is invalid",
			list:          acctest.StringListOrNull("all", "us-east-1"),
			expectError:   true,
			errorContains: "Cannot mix 'all' with specific regions",
		},
		{
			name:          "all mixed with other regions (different order) is invalid",
			list:          acctest.StringListOrNull("us-east-1", "all"),
			expectError:   true,
			errorContains: "Cannot mix 'all' with specific regions",
		},
		{
			name:          "invalid region format",
			list:          acctest.StringListOrNull("invalid-region"),
			expectError:   true,
			errorContains: "not a valid AWS region",
		},
		{
			name:          "mix of valid and invalid regions",
			list:          acctest.StringListOrNull("us-east-1", "invalid-region"),
			expectError:   true,
			errorContains: "not a valid AWS region",
		},
		{
			name:        "multiple valid regions with different types",
			list:        acctest.StringListOrNull("us-east-1", "eu-west-1", "us-gov-west-1", "cn-north-1"),
			expectError: false,
		},
		{
			name:        "null value",
			list:        types.ListNull(types.StringType),
			expectError: false,
		},
		{
			name:        "unknown value",
			list:        types.ListUnknown(types.StringType),
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v := fcs.AWSRegionsOrAllListValidator()
			req := validator.ListRequest{
				Path:        path.Root("test"),
				ConfigValue: tc.list,
			}
			resp := &validator.ListResponse{}
			v.ValidateList(context.Background(), req, resp)

			hasError := resp.Diagnostics.HasError()
			if tc.expectError {
				assert.True(t, hasError, "Expected validation error for list '%s'", tc.list)
				if tc.errorContains != "" {
					errs := resp.Diagnostics.Errors()
					assert.NotEmpty(t, errs)
					errorText := errs[0].Summary() + " " + errs[0].Detail()
					assert.Contains(t, errorText, tc.errorContains)
				}
			} else {
				assert.False(t, hasError, "Expected no validation error for list '%s', but got: %v", tc.list, resp.Diagnostics.Errors())
			}
		})
	}
}
