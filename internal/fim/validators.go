package fim

import (
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// Limits the FileVantage API enforces on rule group and policy entities. Exceeding
// either returns a descriptive 400, unlike the character restrictions below.
const (
	maxNameLength        = 100
	maxDescriptionLength = 500
)

// The FileVantage API restricts name and description on rule group and policy
// entities to a fixed character set, and answers any violation with an opaque
// HTTP 500 rather than a validation error. Reproducing the server-side rules here
// turns that into a plan-time error naming the offending attribute.
//
// The two fields do not share a pattern: description additionally permits `@` and
// newlines, which name rejects. Both sets were confirmed against the live API a
// character at a time; see validators_test.go for the observed values.
var (
	namePattern        = regexp.MustCompile(`^[\w\p{L}\p{M}\- :;,.!()&\[\]]*$`)
	descriptionPattern = regexp.MustCompile(`^[\w\p{L}\p{M}\- :;,.!()&\[\]\n@]*$`)
)

const (
	nameCharacters        = `letters, digits, underscores, spaces, and - : ; , . ! ( ) & [ ]`
	descriptionCharacters = `letters, digits, underscores, spaces, newlines, and - : ; , . ! ( ) & [ ] @`
)

// Sentence fragments appended to schema descriptions so the generated docs carry
// the constraint. The API does not document it and reports violations as a 500.
var (
	nameConstraints = fmt.Sprintf(
		" Limited to %d characters, and may only contain %s.",
		maxNameLength,
		nameCharacters,
	)
	descriptionConstraints = fmt.Sprintf(
		" Limited to %d characters, and may only contain %s.",
		maxDescriptionLength,
		descriptionCharacters,
	)
)

// nameValidators returns the length and character validators the FileVantage API
// enforces on rule group and policy names.
func nameValidators() []validator.String {
	return []validator.String{
		stringvalidator.LengthAtMost(maxNameLength),
		stringvalidator.RegexMatches(
			namePattern,
			fmt.Sprintf("must contain only %s", nameCharacters),
		),
	}
}

// descriptionValidators returns the length and character validators the FileVantage
// API enforces on rule group and policy descriptions.
func descriptionValidators() []validator.String {
	return []validator.String{
		stringvalidator.LengthAtMost(maxDescriptionLength),
		stringvalidator.RegexMatches(
			descriptionPattern,
			fmt.Sprintf("must contain only %s", descriptionCharacters),
		),
	}
}
