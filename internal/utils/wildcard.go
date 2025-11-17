package utils

import (
	"regexp"
	"strings"
)

// MatchesWildcard checks if a text string matches a wildcard pattern.
// The pattern can contain asterisks (*) which match zero or more characters.
// Matching is case-insensitive.
// Examples:
//   - "admin*" matches "admin@example.com", "Administrator", "ADMIN"
//   - "*admin*" matches "system-admin@example.com", "Admin"
//   - "example*more" matches "example-test-more", "EXAMPLEMORE"
func MatchesWildcard(text, pattern string) bool {
	regexPattern := wildcardToRegex(pattern)
	matched, err := regexp.MatchString(regexPattern, text)
	if err != nil {
		return false
	}
	return matched
}

// wildcardToRegex converts a wildcard pattern to a regular expression pattern.
// It escapes all regex special characters, then converts * wildcards to .* regex patterns.
// The resulting pattern is anchored with ^ and $ for exact matching and includes (?i) for case-insensitive matching.
func wildcardToRegex(pattern string) string {
	escaped := regexp.QuoteMeta(pattern)
	regex := strings.ReplaceAll(escaped, `\*`, `.*`)
	return "(?i)^" + regex + "$"
}
