package validators

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// StringNotWhitespace returns a validator that ensures a string attribute is not
// empty or composed only of whitespace characters.
//
// The validator uses a regex pattern (\S) to check that the string contains at least
// one non-whitespace character. Null (unconfigured) and unknown (known after apply) values are skipped.
//
// Valid values: "test", "test value", "a"
// Invalid values: "", " ", "   ", "\t", "\n", " \t\n ".
func StringNotWhitespace() validator.String {
	return stringvalidator.RegexMatches(
		regexp.MustCompile(`\S`),
		"must not be empty or contain only whitespace",
	)
}

// StringIsEmailAddress returns a validator that ensures a string attribute is a
// valid email address format.
//
// The validator uses a regex pattern to check that the string conforms to a basic
// email address format. Null (unconfigured) and unknown (known after apply) values are skipped.
//
// Valid values: "user@example.com", "test.user+tag@domain.co.uk"
// Invalid values: "notanemail", "missing@domain", "@example.com", "user@".
func StringIsEmailAddress() validator.String {
	return stringvalidator.RegexMatches(
		regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`),
		"must be a valid email address",
	)
}

// sortFieldValidator validates that a string is a valid sort field with .asc or .desc suffix.
type sortFieldValidator struct {
	validFields []string
}

// Description returns a plain text description of the validator's behavior.
func (v sortFieldValidator) Description(_ context.Context) string {
	return fmt.Sprintf("must be one of the valid sort fields (%s) with either .asc or .desc suffix", strings.Join(v.validFields, ", "))
}

// MarkdownDescription returns a markdown formatted description of the validator's behavior.
func (v sortFieldValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v sortFieldValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	value := req.ConfigValue.ValueString()

	if !strings.HasSuffix(value, ".asc") && !strings.HasSuffix(value, ".desc") {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid Sort Field Format",
			fmt.Sprintf("Sort field must end with '.asc' or '.desc', got: %s", value),
		)
	}

	fieldName := strings.TrimSuffix(strings.TrimSuffix(value, ".asc"), ".desc")

	validField := false
	for _, field := range v.validFields {
		if field == fieldName {
			validField = true
			break
		}
	}

	if !validField {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid Sort Field",
			fmt.Sprintf("Sort field '%s' is not valid. Valid fields are: %s", fieldName, strings.Join(v.validFields, ", ")),
		)
	}
}

// SortField returns a validator that ensures a string is a valid sort field
// from the provided list with either .asc or .desc suffix.
//
// The validator checks that:
// 1. The string ends with either ".asc" or ".desc"
// 2. The field name (before the suffix) is in the list of valid fields
//
// Null (unconfigured) and unknown (known after apply) values are skipped.
func SortField(validFields []string) validator.String {
	return sortFieldValidator{
		validFields: validFields,
	}
}

// ValidateRFC3339 returns a validator that ensures a string attribute is either
// empty or in RFC3339 format.
//
// The validator uses a regex pattern to check that the string conforms to the
// RFC3339 date-time format. Null (unconfigured) and unknown (known after apply) values are skipped.
//
// Valid values: "2025-08-11T10:00:00Z", "" (empty string)
// Invalid values: "2025-08-11", "10:00:00Z", "2025-08-11 10:00:00".
func ValidateRFC3339() validator.String {
	return stringvalidator.All(
		stringvalidator.RegexMatches(
			regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)?$`),
			"must be in RFC3339 format (e.g., '2025-08-11T10:00:00Z') if defined",
		),
	)
}
