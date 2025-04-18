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

// MarkdownDescription generates a markdown description that works for generating terraform docs.
func MarkdownDescription(section string, description string, apiScopes []scopes.Scope) string {
	return fmt.Sprintf("%s --- %s\n\n%s",
		section,
		description,
		scopes.GenerateScopeDescription(apiScopes),
	)
}
