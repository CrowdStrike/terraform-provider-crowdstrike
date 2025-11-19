package validators

import (
	"regexp"

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
