package utils

import (
	"context"
	"fmt"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
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

// SliceToListTypeString converts []string into types.List with an attr.Type of types.String.
// Empty []string will result in an empty types.List.
func SliceToListTypeString(
	ctx context.Context,
	elems []string,
	diags *diag.Diagnostics,
) types.List {
	elemsSlice := make([]types.String, 0, len(elems))
	for _, elem := range elems {
		elemsSlice = append(elemsSlice, types.StringValue(elem))
	}
	elemList, err := types.ListValueFrom(
		ctx,
		types.StringType,
		elemsSlice,
	)

	diags.Append(err...)

	return elemList
}

// SliceToListTypeObject converts []T into types.List with an attr.Type of types.Object{}.
func SliceToListTypeObject[T any](
	ctx context.Context,
	elems []T,
	attrs map[string]attr.Type,
	diags *diag.Diagnostics,
) types.List {

	elemsSlice := make([]T, 0, len(elems))
	elemsSlice = append(elemsSlice, elems...)
	elemList, err := types.ListValueFrom(
		ctx,
		types.ObjectType{AttrTypes: attrs},
		elemsSlice,
	)

	diags.Append(err...)
	return elemList
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
func ValidateEmptyIDsList(
	ctx context.Context,
	checkList types.Set,
	attrPath string,
) diag.Diagnostics {
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

// SetInt64FromAPIIfNotZero sets an Int64 value from API response, keeping null if current is null and API value is 0.
func SetInt64FromAPIIfNotZero(currentValue types.Int64, apiValue int64) types.Int64 {
	if currentValue.IsNull() && apiValue == 0 {
		return types.Int64Null()
	}
	return types.Int64Value(apiValue)
}

// SetStringFromAPIIfNotEmpty sets a String value from API response, keeping null if current is null and API value is "".
func SetStringFromAPIIfNotEmpty(currentValue types.String, apiValue string) types.String {
	if currentValue.IsNull() && apiValue == "" {
		return types.StringNull()
	}
	return types.StringValue(apiValue)
}

// OptionalString converts a string pointer to types.String, returning null if pointer is nil or empty.
func OptionalString(value *string) types.String {
	if value != nil && *value != "" {
		return types.StringPointerValue(value)
	}
	return types.StringNull()
}

// TerraformObjectConvertible is an interface for models that can be converted to Terraform objects.
type TerraformObjectConvertible interface {
	AttributeTypes() map[string]attr.Type
}

// ConvertModelToTerraformObject converts a model pointer to a Terraform object.
// If the model is nil, returns a null object with the provided attribute types.
func ConvertModelToTerraformObject[T TerraformObjectConvertible](
	ctx context.Context,
	model *T,
) (types.Object, diag.Diagnostics) {
	if model == nil {
		var zero T
		zeroObj := types.ObjectNull(zero.AttributeTypes())
		return zeroObj, nil
	}

	obj, diags := types.ObjectValueFrom(ctx, (*model).AttributeTypes(), *model)
	if diags.HasError() {
		return types.ObjectNull((*model).AttributeTypes()), diags
	}

	tflog.Debug(ctx, "Successfully converted model to Terraform object", map[string]interface{}{
		"object": obj.String(),
	})
	return obj, diags
}
