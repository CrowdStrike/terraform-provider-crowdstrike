package utils

import "testing"

func TestMatchesWildcard(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		pattern  string
		expected bool
	}{
		{
			name:     "exact_match_no_wildcard",
			text:     "admin@example.com",
			pattern:  "admin@example.com",
			expected: true,
		},
		{
			name:     "no_match_no_wildcard",
			text:     "user@example.com",
			pattern:  "admin@example.com",
			expected: false,
		},
		{
			name:     "prefix_wildcard_match",
			text:     "admin@example.com",
			pattern:  "admin*",
			expected: true,
		},
		{
			name:     "prefix_wildcard_match_longer",
			text:     "administrator@example.com",
			pattern:  "admin*",
			expected: true,
		},
		{
			name:     "prefix_wildcard_no_match",
			text:     "user@example.com",
			pattern:  "admin*",
			expected: false,
		},
		{
			name:     "suffix_wildcard_match",
			text:     "user@example.com",
			pattern:  "*example.com",
			expected: true,
		},
		{
			name:     "suffix_wildcard_no_match",
			text:     "user@test.org",
			pattern:  "*example.com",
			expected: false,
		},
		{
			name:     "contains_wildcard_match",
			text:     "system-admin@example.com",
			pattern:  "*admin*",
			expected: true,
		},
		{
			name:     "contains_wildcard_match_start",
			text:     "admin@example.com",
			pattern:  "*admin*",
			expected: true,
		},
		{
			name:     "contains_wildcard_match_end",
			text:     "user-admin",
			pattern:  "*admin*",
			expected: true,
		},
		{
			name:     "contains_wildcard_no_match",
			text:     "user@example.com",
			pattern:  "*admin*",
			expected: false,
		},
		{
			name:     "middle_wildcard_match",
			text:     "example-test-more",
			pattern:  "example*more",
			expected: true,
		},
		{
			name:     "middle_wildcard_match_empty",
			text:     "examplemore",
			pattern:  "example*more",
			expected: true,
		},
		{
			name:     "middle_wildcard_no_match_prefix",
			text:     "test-example-more",
			pattern:  "example*more",
			expected: false,
		},
		{
			name:     "middle_wildcard_no_match_suffix",
			text:     "example-test",
			pattern:  "example*more",
			expected: false,
		},
		{
			name:     "multiple_wildcards_match",
			text:     "user@example.com",
			pattern:  "*@*.com",
			expected: true,
		},
		{
			name:     "multiple_wildcards_no_match",
			text:     "user@example.org",
			pattern:  "*@*.com",
			expected: false,
		},
		{
			name:     "only_wildcard_matches_anything",
			text:     "anything-here",
			pattern:  "*",
			expected: true,
		},
		{
			name:     "only_wildcard_matches_empty",
			text:     "",
			pattern:  "*",
			expected: true,
		},
		{
			name:     "special_chars_in_pattern",
			text:     "user@example.com",
			pattern:  "user@*.com",
			expected: true,
		},
		{
			name:     "special_chars_exact_match",
			text:     "test.user+tag@example.com",
			pattern:  "test.user+tag@example.com",
			expected: true,
		},
		{
			name:     "special_chars_with_wildcard",
			text:     "test.user+tag@example.com",
			pattern:  "test.*@example.com",
			expected: true,
		},
		{
			name:     "admin_crowdstrike_prefix",
			text:     "admin@crowdstrike.com",
			pattern:  "admin*",
			expected: true,
		},
		{
			name:     "admin_example_prefix",
			text:     "admin@example.com",
			pattern:  "admin*",
			expected: true,
		},
		{
			name:     "case_insensitive_match_uppercase",
			text:     "Admin@example.com",
			pattern:  "admin*",
			expected: true,
		},
		{
			name:     "case_insensitive_match_lowercase",
			text:     "admin@example.com",
			pattern:  "admin*",
			expected: true,
		},
		{
			name:     "dot_before_wildcard",
			text:     "first.last@example.com",
			pattern:  "first.*",
			expected: true,
		},
		{
			name:     "case_insensitive_all_uppercase_text",
			text:     "ADMINISTRATOR",
			pattern:  "admin*",
			expected: true,
		},
		{
			name:     "case_insensitive_mixed_case_pattern",
			text:     "system-admin@example.com",
			pattern:  "*AdMiN*",
			expected: true,
		},
		{
			name:     "case_insensitive_all_uppercase_pattern",
			text:     "example-test-more",
			pattern:  "EXAMPLE*MORE",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchesWildcard(tt.text, tt.pattern)
			if result != tt.expected {
				t.Errorf("MatchesWildcard(%q, %q) = %v, want %v", tt.text, tt.pattern, result, tt.expected)
			}
		})
	}
}

func TestWildcardToRegex(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		expected string
	}{
		{
			name:     "no_wildcard",
			pattern:  "admin",
			expected: "(?i)^admin$",
		},
		{
			name:     "prefix_wildcard",
			pattern:  "admin*",
			expected: "(?i)^admin.*$",
		},
		{
			name:     "suffix_wildcard",
			pattern:  "*admin",
			expected: "(?i)^.*admin$",
		},
		{
			name:     "contains_wildcard",
			pattern:  "*admin*",
			expected: "(?i)^.*admin.*$",
		},
		{
			name:     "middle_wildcard",
			pattern:  "example*more",
			expected: "(?i)^example.*more$",
		},
		{
			name:     "multiple_wildcards",
			pattern:  "*@*.com",
			expected: "(?i)^.*@.*\\.com$",
		},
		{
			name:     "special_chars_escaped",
			pattern:  "user+tag@example.com",
			expected: "(?i)^user\\+tag@example\\.com$",
		},
		{
			name:     "special_chars_with_wildcard",
			pattern:  "user+*@*.com",
			expected: "(?i)^user\\+.*@.*\\.com$",
		},
		{
			name:     "dot_before_wildcard",
			pattern:  "user+.*@*.com",
			expected: "(?i)^user\\+\\..*@.*\\.com$",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := wildcardToRegex(tt.pattern)
			if result != tt.expected {
				t.Errorf("wildcardToRegex(%q) = %q, want %q", tt.pattern, result, tt.expected)
			}
		})
	}
}
