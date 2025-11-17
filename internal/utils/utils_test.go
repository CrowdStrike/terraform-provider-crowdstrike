package utils

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"golang.org/x/exp/slices"
)

func TestSetIDsToModify(t *testing.T) {
	tests := []struct {
		name           string
		plan           []string
		state          []string
		expectedAdd    []string
		expectedRemove []string
	}{
		{
			name:           "empty",
			plan:           []string{},
			state:          []string{},
			expectedAdd:    []string{},
			expectedRemove: []string{},
		},
		{
			name:           "add",
			plan:           []string{"a"},
			state:          []string{},
			expectedAdd:    []string{"a"},
			expectedRemove: []string{},
		},
		{
			name:           "remove",
			plan:           []string{},
			state:          []string{"a"},
			expectedAdd:    []string{},
			expectedRemove: []string{"a"},
		},
		{
			name:           "add and remove",
			plan:           []string{"a", "b"},
			state:          []string{"a", "c"},
			expectedAdd:    []string{"b"},
			expectedRemove: []string{"c"},
		},
		{
			name:           "no change",
			plan:           []string{"a"},
			state:          []string{"a"},
			expectedAdd:    []string{},
			expectedRemove: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan, _ := types.SetValueFrom(t.Context(), types.StringType, tt.plan)
			state, _ := types.SetValueFrom(t.Context(), types.StringType, tt.state)

			idsToAdd, idsToRemove, diags := SetIDsToModify(t.Context(), plan, state)

			if !slices.Equal(idsToAdd, tt.expectedAdd) {
				t.Errorf("idsToAdd = %v, want %v", idsToAdd, tt.expectedAdd)
			}
			if !slices.Equal(idsToRemove, tt.expectedRemove) {
				t.Errorf("idsToRemove = %v, want %v", idsToRemove, tt.expectedRemove)
			}
			if diags.HasError() {
				t.Errorf("diags = %v, want no error", diags)
			}
		})
	}
}

func TestProcessNameSearchPattern(t *testing.T) {
	tests := []struct {
		name                 string
		pattern              string
		expectedAPIQuery     string
		expectedNeedsFilter  bool
		testValue            string // Value to test the client filter against
		expectedFilterResult bool   // Expected result of the client filter
	}{
		{
			name:                 "name with wildcard - hyphenated word",
			pattern:              "foo-bar*",
			expectedAPIQuery:     "name:*'foo'",
			expectedNeedsFilter:  true,
			testValue:            "foo-bar test",
			expectedFilterResult: true,
		},
		{
			name:                 "name with wildcard - underscore separated",
			pattern:              "test_policy*",
			expectedAPIQuery:     "name:*'test'",
			expectedNeedsFilter:  true,
			testValue:            "test_policy example",
			expectedFilterResult: true,
		},
		{
			name:                 "name with wildcard - mixed separators",
			pattern:              "my-test_policy.v2*",
			expectedAPIQuery:     "name:*'my'",
			expectedNeedsFilter:  true,
			testValue:            "my-test_policy.v2 build",
			expectedFilterResult: true,
		},
		{
			name:                 "pattern 1 - exact match single word",
			pattern:              "production",
			expectedAPIQuery:     "name.raw:'production'",
			expectedNeedsFilter:  false,
			testValue:            "production",
			expectedFilterResult: true,
		},
		{
			name:                 "pattern 1 - exact match multiple words",
			pattern:              "foo bar",
			expectedAPIQuery:     "name.raw:'foo bar'",
			expectedNeedsFilter:  false,
			testValue:            "foo bar",
			expectedFilterResult: true,
		},
		{
			name:                 "pattern 2 - wildcard single word",
			pattern:              "production*",
			expectedAPIQuery:     "name:*'production'",
			expectedNeedsFilter:  true,
			testValue:            "production server",
			expectedFilterResult: true,
		},
		{
			name:                 "pattern 2 - wildcard multiple words",
			pattern:              "foo bar*",
			expectedAPIQuery:     "name:*'foo'",
			expectedNeedsFilter:  true,
			testValue:            "foo bar test",
			expectedFilterResult: true,
		},
		{
			name:                 "pattern 2 - wildcard multiple words no match",
			pattern:              "foo bar*",
			expectedAPIQuery:     "name:*'foo'",
			expectedNeedsFilter:  true,
			testValue:            "something else",
			expectedFilterResult: false,
		},
		{
			name:                 "pattern 2 - just asterisk",
			pattern:              "*",
			expectedAPIQuery:     "",
			expectedNeedsFilter:  false,
			testValue:            "any value",
			expectedFilterResult: true,
		},
		{
			name:                 "pattern 2 - case insensitive",
			pattern:              "foo bar*",
			expectedAPIQuery:     "name:*'foo'",
			expectedNeedsFilter:  true,
			testValue:            "FOO BAR TEST",
			expectedFilterResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ProcessNameSearchPattern(tt.pattern)

			if result.APIQuery != tt.expectedAPIQuery {
				t.Errorf("APIQuery = %q, want %q", result.APIQuery, tt.expectedAPIQuery)
			}

			if result.NeedsClientFilter != tt.expectedNeedsFilter {
				t.Errorf("NeedsClientFilter = %v, want %v", result.NeedsClientFilter, tt.expectedNeedsFilter)
			}

			if result.ClientFilter != nil {
				filterResult := result.ClientFilter(tt.testValue)
				if filterResult != tt.expectedFilterResult {
					t.Errorf("ClientFilter(%q) = %v, want %v", tt.testValue, filterResult, tt.expectedFilterResult)
				}
			}
		})
	}
}

func TestProcessDescriptionSearchPattern(t *testing.T) {
	tests := []struct {
		name                 string
		pattern              string
		expectedAPIQuery     string
		expectedNeedsFilter  bool
		testValue            string // Value to test the client filter against
		expectedFilterResult bool   // Expected result of the client filter
	}{
		{
			name:                 "empty pattern",
			pattern:              "",
			expectedAPIQuery:     "",
			expectedNeedsFilter:  false,
			testValue:            "any value",
			expectedFilterResult: true,
		},
		{
			name:                 "description with hyphenated word - exact",
			pattern:              "anti-malware",
			expectedAPIQuery:     "description:*'anti'",
			expectedNeedsFilter:  true,
			testValue:            "anti-malware",
			expectedFilterResult: true,
		},
		{
			name:                 "description with underscore - wildcard",
			pattern:              "threat_detection*",
			expectedAPIQuery:     "description:*'threat'",
			expectedNeedsFilter:  true,
			testValue:            "threat_detection system",
			expectedFilterResult: true,
		},
		{
			name:                 "description with mixed separators - wildcard",
			pattern:              "real-time_monitoring.v1*",
			expectedAPIQuery:     "description:*'real'",
			expectedNeedsFilter:  true,
			testValue:            "real-time_monitoring.v1 enabled",
			expectedFilterResult: true,
		},
		{
			name:                 "pattern 3 - exact match single word",
			pattern:              "malware",
			expectedAPIQuery:     "description:*'malware'",
			expectedNeedsFilter:  true,
			testValue:            "malware",
			expectedFilterResult: true,
		},
		{
			name:                 "pattern 3 - exact match multiple words",
			pattern:              "foo bar",
			expectedAPIQuery:     "description:*'foo'",
			expectedNeedsFilter:  true,
			testValue:            "foo bar",
			expectedFilterResult: true,
		},
		{
			name:                 "pattern 3 - exact match no match",
			pattern:              "foo bar",
			expectedAPIQuery:     "description:*'foo'",
			expectedNeedsFilter:  true,
			testValue:            "foo bar test",
			expectedFilterResult: false,
		},
		{
			name:                 "pattern 4 - wildcard single word",
			pattern:              "malware*",
			expectedAPIQuery:     "description:*'malware'",
			expectedNeedsFilter:  true,
			testValue:            "malware protection",
			expectedFilterResult: true,
		},
		{
			name:                 "pattern 4 - wildcard multiple words",
			pattern:              "foo bar*",
			expectedAPIQuery:     "description:*'foo'",
			expectedNeedsFilter:  true,
			testValue:            "foo bar test",
			expectedFilterResult: true,
		},
		{
			name:                 "pattern 4 - wildcard multiple words no match",
			pattern:              "foo bar*",
			expectedAPIQuery:     "description:*'foo'",
			expectedNeedsFilter:  true,
			testValue:            "something else",
			expectedFilterResult: false,
		},
		{
			name:                 "pattern 3 - case insensitive equals",
			pattern:              "foo bar",
			expectedAPIQuery:     "description:*'foo'",
			expectedNeedsFilter:  true,
			testValue:            "FOO BAR",
			expectedFilterResult: true,
		},
		{
			name:                 "pattern 4 - case insensitive contains",
			pattern:              "foo bar*",
			expectedAPIQuery:     "description:*'foo'",
			expectedNeedsFilter:  true,
			testValue:            "FOO BAR TEST",
			expectedFilterResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ProcessDescriptionSearchPattern(tt.pattern)

			if result.APIQuery != tt.expectedAPIQuery {
				t.Errorf("APIQuery = %q, want %q", result.APIQuery, tt.expectedAPIQuery)
			}

			if result.NeedsClientFilter != tt.expectedNeedsFilter {
				t.Errorf("NeedsClientFilter = %v, want %v", result.NeedsClientFilter, tt.expectedNeedsFilter)
			}

			if result.ClientFilter != nil {
				filterResult := result.ClientFilter(tt.testValue)
				if filterResult != tt.expectedFilterResult {
					t.Errorf("ClientFilter(%q) = %v, want %v", tt.testValue, filterResult, tt.expectedFilterResult)
				}
			}
		})
	}
}

func TestProcessUserFieldSearchPattern(t *testing.T) {
	tests := []struct {
		name                 string
		pattern              string
		fieldName            string
		expectedAPIQuery     string
		expectedNeedsFilter  bool
		testValue            string // Value to test the client filter against
		expectedFilterResult bool   // Expected result of the client filter
	}{
		{
			name:                 "empty pattern",
			pattern:              "",
			fieldName:            "created_by",
			expectedAPIQuery:     "",
			expectedNeedsFilter:  false,
			testValue:            "any value",
			expectedFilterResult: true,
		},
		{
			name:                 "user with hyphenated name - exact",
			pattern:              "john-doe@company.com",
			fieldName:            "created_by",
			expectedAPIQuery:     "created_by:'john-doe'",
			expectedNeedsFilter:  true,
			testValue:            "john-doe@company.com",
			expectedFilterResult: true,
		},
		{
			name:                 "user with underscore - wildcard",
			pattern:              "jane_smith*",
			fieldName:            "modified_by",
			expectedAPIQuery:     "modified_by:'jane_smith'",
			expectedNeedsFilter:  true,
			testValue:            "jane_smith@company.com",
			expectedFilterResult: true,
		},
		{
			name:                 "user with domain - exact",
			pattern:              "user@company.com",
			fieldName:            "created_by",
			expectedAPIQuery:     "created_by:'user'",
			expectedNeedsFilter:  true,
			testValue:            "user@company.com",
			expectedFilterResult: true,
		},
		{
			name:                 "exact match single word",
			pattern:              "admin",
			fieldName:            "created_by",
			expectedAPIQuery:     "created_by:'admin'",
			expectedNeedsFilter:  true,
			testValue:            "admin",
			expectedFilterResult: true,
		},
		{
			name:                 "exact match with wildcard single word",
			pattern:              "admin*",
			fieldName:            "created_by",
			expectedAPIQuery:     "created_by:'admin'",
			expectedNeedsFilter:  true,
			testValue:            "admin123",
			expectedFilterResult: true,
		},
		{
			name:                 "exact match no match",
			pattern:              "admin",
			fieldName:            "created_by",
			expectedAPIQuery:     "created_by:'admin'",
			expectedNeedsFilter:  true,
			testValue:            "administrator",
			expectedFilterResult: false,
		},
		{
			name:                 "wildcard match",
			pattern:              "admin*",
			fieldName:            "modified_by",
			expectedAPIQuery:     "modified_by:'admin'",
			expectedNeedsFilter:  true,
			testValue:            "administrator",
			expectedFilterResult: true,
		},
		{
			name:                 "wildcard no match",
			pattern:              "admin*",
			fieldName:            "created_by",
			expectedAPIQuery:     "created_by:'admin'",
			expectedNeedsFilter:  true,
			testValue:            "user",
			expectedFilterResult: false,
		},
		{
			name:                 "case sensitive exact match - no match",
			pattern:              "admin",
			fieldName:            "created_by",
			expectedAPIQuery:     "created_by:'admin'",
			expectedNeedsFilter:  true,
			testValue:            "ADMIN",
			expectedFilterResult: false,
		},
		{
			name:                 "case sensitive wildcard - no match",
			pattern:              "admin*",
			fieldName:            "modified_by",
			expectedAPIQuery:     "modified_by:'admin'",
			expectedNeedsFilter:  true,
			testValue:            "ADMINISTRATOR",
			expectedFilterResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ProcessUserFieldSearchPattern(tt.pattern, tt.fieldName)

			if result.APIQuery != tt.expectedAPIQuery {
				t.Errorf("APIQuery = %q, want %q", result.APIQuery, tt.expectedAPIQuery)
			}

			if result.NeedsClientFilter != tt.expectedNeedsFilter {
				t.Errorf("NeedsClientFilter = %v, want %v", result.NeedsClientFilter, tt.expectedNeedsFilter)
			}

			if result.ClientFilter != nil {
				filterResult := result.ClientFilter(tt.testValue)
				if filterResult != tt.expectedFilterResult {
					t.Errorf("ClientFilter(%q) = %v, want %v", tt.testValue, filterResult, tt.expectedFilterResult)
				}
			}
		})
	}
}
