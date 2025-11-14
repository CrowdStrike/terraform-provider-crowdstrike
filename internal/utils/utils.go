package utils

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// SearchQueryInfo represents the information needed for querying and filtering.
type SearchQueryInfo struct {
	APIQuery          string            // The query to send to the API
	ClientFilter      func(string) bool // The client-side filter function to apply
	NeedsClientFilter bool              // Whether client-side filtering is needed
}

// extractFirstAlphanumericWord extracts the first sequence of alphanumeric characters from a string
// For example: "foo-bar" -> "foo", "test123_xyz" -> "test123", "  hello world" -> "hello".
func extractFirstAlphanumericWord(s string) string {
	var result strings.Builder
	foundStart := false

	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			result.WriteRune(r)
			foundStart = true
		} else if foundStart {
			// We've reached the end of the first alphanumeric sequence
			break
		}
		// If we haven't found the start yet, keep looking
	}

	return result.String()
}

// ProcessNameSearchPattern processes a name pattern according to the specified rules:
// Pattern 1: "foo bar" -> API: name.raw:"foo bar" (exact match)
// Pattern 2: "foo bar*" -> API: name:*"foo" + client filter: contains "foo bar".
func ProcessNameSearchPattern(pattern string) SearchQueryInfo {
	if pattern == "" {
		return SearchQueryInfo{
			APIQuery:          "",
			ClientFilter:      func(string) bool { return true },
			NeedsClientFilter: false,
		}
	}

	if strings.HasSuffix(pattern, "*") {
		// Pattern 2: name = "foo bar*" -> API: name:*"foo", client: contains "foo bar"
		trimmedPattern := strings.TrimSuffix(pattern, "*")
		if trimmedPattern == "" {
			// Just "*" - no filtering
			return SearchQueryInfo{
				APIQuery:          "",
				ClientFilter:      func(string) bool { return true },
				NeedsClientFilter: false,
			}
		}

		// Extract first alphanumeric word (e.g., "foo-bar" -> "foo")
		firstWord := extractFirstAlphanumericWord(trimmedPattern)
		if firstWord == "" {
			return SearchQueryInfo{
				APIQuery:          "",
				ClientFilter:      func(string) bool { return true },
				NeedsClientFilter: false,
			}
		}

		return SearchQueryInfo{
			APIQuery: fmt.Sprintf("name:*'%s'", firstWord),
			ClientFilter: func(value string) bool {
				return strings.Contains(strings.ToLower(value), strings.ToLower(trimmedPattern))
			},
			NeedsClientFilter: true,
		}
	} else {
		// Pattern 1: name = "foo bar" -> API: name.raw:"foo bar", no client filtering
		return SearchQueryInfo{
			APIQuery:          fmt.Sprintf("name.raw:'%s'", pattern),
			ClientFilter:      func(string) bool { return true },
			NeedsClientFilter: false,
		}
	}
}

// ProcessDescriptionSearchPattern processes a description pattern according to the specified rules:
// Pattern 3: "foo bar" -> API: description:*"foo" + client filter: equals "foo bar"
// Pattern 4: "foo bar*" -> API: description:*"foo" + client filter: contains "foo bar".
func ProcessDescriptionSearchPattern(pattern string) SearchQueryInfo {
	if pattern == "" {
		return SearchQueryInfo{
			APIQuery:          "",
			ClientFilter:      func(string) bool { return true },
			NeedsClientFilter: false,
		}
	}

	if strings.HasSuffix(pattern, "*") {
		// Pattern 4: description = "foo bar*" -> API: description:*"foo", client: contains "foo bar"
		trimmedPattern := strings.TrimSuffix(pattern, "*")
		if trimmedPattern == "" {
			// Just "*" - no filtering
			return SearchQueryInfo{
				APIQuery:          "",
				ClientFilter:      func(string) bool { return true },
				NeedsClientFilter: false,
			}
		}

		// Extract first alphanumeric word (e.g., "foo-bar" -> "foo")
		firstWord := extractFirstAlphanumericWord(trimmedPattern)
		if firstWord == "" {
			return SearchQueryInfo{
				APIQuery:          "",
				ClientFilter:      func(string) bool { return true },
				NeedsClientFilter: false,
			}
		}

		return SearchQueryInfo{
			APIQuery: fmt.Sprintf("description:*'%s'", firstWord),
			ClientFilter: func(value string) bool {
				return strings.Contains(strings.ToLower(value), strings.ToLower(trimmedPattern))
			},
			NeedsClientFilter: true,
		}
	} else {
		// Pattern 3: description = "foo bar" -> API: description:*"foo", client: equals "foo bar"
		// Extract first alphanumeric word (e.g., "foo-bar" -> "foo")
		firstWord := extractFirstAlphanumericWord(pattern)
		if firstWord == "" {
			return SearchQueryInfo{
				APIQuery:          "",
				ClientFilter:      func(string) bool { return true },
				NeedsClientFilter: false,
			}
		}

		return SearchQueryInfo{
			APIQuery: fmt.Sprintf("description:*'%s'", firstWord),
			ClientFilter: func(value string) bool {
				return strings.EqualFold(value, pattern)
			},
			NeedsClientFilter: true,
		}
	}
}

// SetIDsToModify takes a set of IDs from plan and state and returns the IDs to add and remove to get from the state to the plan.
// idsToAdd is the slice of IDs that are in the plan but not in the state.
// idsToRemove is the slice of IDs that are in the state but not in the plan.
// useful for resources with HostGroups, RuleGroups, etc.
func SetIDsToModify(
	ctx context.Context,
	plan, state types.Set,
) (idsToAdd []string, idsToRemove []string, diags diag.Diagnostics) {
	if len(plan.Elements()) == 0 && len(state.Elements()) == 0 {
		return
	}

	var planIDs, stateIDs []types.String
	planMap := make(map[string]bool)
	stateMap := make(map[string]bool)

	if !plan.IsUnknown() && !plan.IsNull() {
		diags.Append(plan.ElementsAs(ctx, &planIDs, false)...)
		if diags.HasError() {
			return
		}
	}

	if !state.IsUnknown() && !state.IsNull() {
		diags.Append(state.ElementsAs(ctx, &stateIDs, false)...)
		if diags.HasError() {
			return
		}
	}

	for _, id := range planIDs {
		if !id.IsUnknown() && !id.IsNull() {
			planMap[id.ValueString()] = true
		}
	}

	for _, id := range stateIDs {
		if !id.IsUnknown() && !id.IsNull() {
			stateMap[id.ValueString()] = true
		}
	}

	for _, id := range planIDs {
		if !stateMap[id.ValueString()] {
			idsToAdd = append(idsToAdd, id.ValueString())
		}
	}

	for _, id := range stateIDs {
		if !planMap[id.ValueString()] {
			idsToRemove = append(idsToRemove, id.ValueString())
		}
	}

	return
}

// ListIDsToModify takes a list of unique IDs from plan and state and returns the IDs to add and remove to get from the state to the plan.
// idsToAdd is the slice of IDs that are in the plan but not in the state.
// idsToRemove is the slice of IDs that are in the state but not in the plan.
// useful for resources with HostGroups, RuleGroups, etc.
func ListIDsToModify(
	ctx context.Context,
	plan, state types.List,
) (idsToAdd []string, idsToRemove []string, diags diag.Diagnostics) {
	var planIDs, stateIDs []string
	planMap := make(map[string]bool)
	stateMap := make(map[string]bool)

	diags.Append(plan.ElementsAs(ctx, &planIDs, false)...)
	if diags.HasError() {
		return
	}
	diags.Append(state.ElementsAs(ctx, &stateIDs, false)...)
	if diags.HasError() {
		return
	}

	for _, id := range planIDs {
		planMap[id] = true
	}

	for _, id := range stateIDs {
		stateMap[id] = true
	}

	for _, id := range planIDs {
		if !stateMap[id] {
			idsToAdd = append(idsToAdd, id)
		}
	}

	for _, id := range stateIDs {
		if !planMap[id] {
			idsToRemove = append(idsToRemove, id)
		}
	}

	return
}

func GenerateUpdateTimestamp() basetypes.StringValue {
	return types.StringValue(time.Now().Format(time.RFC850))
}

// Addr returns the address of t.
func Addr[T any](t T) *T {
	return &t
}
