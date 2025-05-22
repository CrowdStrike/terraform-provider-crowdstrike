package utils

import (
	"context"
	"fmt"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// IsKnown returns true if an attribute value is known and not null.
func IsKnown(value attr.Value) bool {
	return !value.IsNull() && !value.IsUnknown()
}

// ListTypeAs converts a types.List into a known []T.
func ListTypeAs[T any](
	ctx context.Context,
	list types.List,
	diags *diag.Diagnostics,
) []T {
	if !IsKnown(list) {
		return nil
	}

	var elements []T

	diags.Append(list.ElementsAs(ctx, &elements, false)...)
	return elements
}

// MapTypeAs converts a types.Map into a known map[string]T.
func MapTypeAs[T any](
	ctx context.Context,
	mapIn types.Map,
	diags *diag.Diagnostics,
) map[string]T {
	if !IsKnown(mapIn) {
		return nil
	}
	var items map[string]T

	diags.Append(mapIn.ElementsAs(ctx, &items, false)...)
	return items
}

// ValidateEmptyIDs checks if a set contains empty IDs. Returns a attribute error at path.
func ValidateEmptyIDs(ctx context.Context, checkSet types.Set, attrPath string) diag.Diagnostics {
	var diags diag.Diagnostics

	if checkSet.IsNull() {
		return diags
	}

	if checkSet.IsUnknown() {
		return diags
	}

	ids := make([]types.String, 0, len(checkSet.Elements()))
	diags.Append(checkSet.ElementsAs(ctx, &ids, false)...)
	if diags.HasError() {
		return diags
	}

	for _, id := range ids {
		if !id.IsUnknown() && len(id.ValueString()) == 0 {
			diags.AddAttributeError(
				path.Root(attrPath),
				fmt.Sprintf("Error validating %s", attrPath),
				"List of IDs can not contain a empty \"\" value",
			)
		}
	}

	return diags
}

// ValidateEmptyIDsList checks if a list contains empty IDs. Returns a attribute error at path.
func ValidateEmptyIDsList(ctx context.Context, checkList types.Set, attrPath string) diag.Diagnostics {
	var diags diag.Diagnostics

	if checkList.IsNull() {
		return diags
	}

	if checkList.IsUnknown() {
		return diags
	}

	ids := make([]types.String, 0, len(checkList.Elements()))
	diags.Append(checkList.ElementsAs(ctx, &ids, false)...)
	if diags.HasError() {
		return diags
	}

	for _, id := range ids {
		if !id.IsUnknown() && len(id.ValueString()) == 0 {
			diags.AddAttributeError(
				path.Root(attrPath),
				fmt.Sprintf("Error validating %s", attrPath),
				"List of IDs can not contain a empty \"\" value",
			)
		}
	}

	return diags
}

// MarkdownDescription generates a markdown description that works for generating terraform docs.
func MarkdownDescription(section string, description string, apiScopes []scopes.Scope) string {
	return fmt.Sprintf("%s --- %s\n\n%s",
		section,
		description,
		scopes.GenerateScopeDescription(apiScopes),
	)
}

// MissingElements checks if any elements in slice `a` are missing from slice `b`.
// It returns a slice containing the missing elements.
func MissingElements(a, b []string) []string {
	missing := []string{}
	bMap := make(map[string]bool, len(b))

	for _, val := range b {
		bMap[val] = true
	}

	for _, val := range a {
		if !bMap[val] {
			missing = append(missing, val)
		}
	}

	return missing
}
