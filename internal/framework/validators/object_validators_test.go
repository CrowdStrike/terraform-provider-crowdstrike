package validators

import (
	"context"
	"math/big"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func TestAtLeastOneNonEmptyAttribute(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		objectValue basetypes.ObjectValue
		expectError bool
		validator   validator.Object
	}{
		"null object": {
			objectValue: types.ObjectNull(map[string]attr.Type{
				"ids":   types.SetType{ElemType: types.StringType},
				"names": types.SetType{ElemType: types.StringType},
			}),
			expectError: false,
			validator:   AtLeastOneNonEmptyAttribute("ids", "names"),
		},
		"all empty sets": {
			objectValue: types.ObjectValueMust(
				map[string]attr.Type{
					"ids":   types.SetType{ElemType: types.StringType},
					"names": types.SetType{ElemType: types.StringType},
				},
				map[string]attr.Value{
					"ids":   types.SetValueMust(types.StringType, []attr.Value{}),
					"names": types.SetValueMust(types.StringType, []attr.Value{}),
				},
			),
			expectError: true,
			validator:   AtLeastOneNonEmptyAttribute("ids", "names"),
		},
		"all null sets": {
			objectValue: types.ObjectValueMust(
				map[string]attr.Type{
					"ids":   types.SetType{ElemType: types.StringType},
					"names": types.SetType{ElemType: types.StringType},
				},
				map[string]attr.Value{
					"ids":   types.SetNull(types.StringType),
					"names": types.SetNull(types.StringType),
				},
			),
			expectError: true,
			validator:   AtLeastOneNonEmptyAttribute("ids", "names"),
		},
		"one non-empty set": {
			objectValue: types.ObjectValueMust(
				map[string]attr.Type{
					"ids":   types.SetType{ElemType: types.StringType},
					"names": types.SetType{ElemType: types.StringType},
				},
				map[string]attr.Value{
					"ids": types.SetValueMust(types.StringType, []attr.Value{
						types.StringValue("test-id"),
					}),
					"names": types.SetValueMust(types.StringType, []attr.Value{}),
				},
			),
			expectError: false,
			validator:   AtLeastOneNonEmptyAttribute("ids", "names"),
		},
		"multiple non-empty sets": {
			objectValue: types.ObjectValueMust(
				map[string]attr.Type{
					"ids":   types.SetType{ElemType: types.StringType},
					"names": types.SetType{ElemType: types.StringType},
				},
				map[string]attr.Value{
					"ids": types.SetValueMust(types.StringType, []attr.Value{
						types.StringValue("test-id"),
					}),
					"names": types.SetValueMust(types.StringType, []attr.Value{
						types.StringValue("test-name"),
					}),
				},
			),
			expectError: false,
			validator:   AtLeastOneNonEmptyAttribute("ids", "names"),
		},
		"mixed types - string and set": {
			objectValue: types.ObjectValueMust(
				map[string]attr.Type{
					"name": types.StringType,
					"ids":  types.SetType{ElemType: types.StringType},
				},
				map[string]attr.Value{
					"name": types.StringValue("test-name"),
					"ids":  types.SetValueMust(types.StringType, []attr.Value{}),
				},
			),
			expectError: false,
			validator:   AtLeastOneNonEmptyAttribute("name", "ids"),
		},
		"mixed types - empty string and empty set": {
			objectValue: types.ObjectValueMust(
				map[string]attr.Type{
					"name": types.StringType,
					"ids":  types.SetType{ElemType: types.StringType},
				},
				map[string]attr.Value{
					"name": types.StringValue(""),
					"ids":  types.SetValueMust(types.StringType, []attr.Value{}),
				},
			),
			expectError: true,
			validator:   AtLeastOneNonEmptyAttribute("name", "ids"),
		},
		"empty tuple": {
			objectValue: types.ObjectValueMust(
				map[string]attr.Type{
					"tuple": types.TupleType{ElemTypes: []attr.Type{}},
					"ids":   types.SetType{ElemType: types.StringType},
				},
				map[string]attr.Value{
					"tuple": types.TupleValueMust([]attr.Type{}, []attr.Value{}),
					"ids":   types.SetValueMust(types.StringType, []attr.Value{}),
				},
			),
			expectError: true,
			validator:   AtLeastOneNonEmptyAttribute("tuple", "ids"),
		},
		"non-empty tuple": {
			objectValue: types.ObjectValueMust(
				map[string]attr.Type{
					"tuple": types.TupleType{ElemTypes: []attr.Type{types.StringType, types.NumberType}},
					"ids":   types.SetType{ElemType: types.StringType},
				},
				map[string]attr.Value{
					"tuple": types.TupleValueMust([]attr.Type{types.StringType, types.NumberType}, []attr.Value{
						types.StringValue("test"),
						types.NumberValue(big.NewFloat(42)),
					}),
					"ids": types.SetValueMust(types.StringType, []attr.Value{}),
				},
			),
			expectError: false,
			validator:   AtLeastOneNonEmptyAttribute("tuple", "ids"),
		},
		"null tuple": {
			objectValue: types.ObjectValueMust(
				map[string]attr.Type{
					"tuple": types.TupleType{ElemTypes: []attr.Type{types.StringType, types.NumberType}},
					"ids":   types.SetType{ElemType: types.StringType},
				},
				map[string]attr.Value{
					"tuple": types.TupleNull([]attr.Type{types.StringType, types.NumberType}),
					"ids":   types.SetValueMust(types.StringType, []attr.Value{}),
				},
			),
			expectError: true,
			validator:   AtLeastOneNonEmptyAttribute("tuple", "ids"),
		},
		"dynamic value with non-empty string": {
			objectValue: types.ObjectValueMust(
				map[string]attr.Type{
					"dynamic": types.DynamicType,
					"ids":     types.SetType{ElemType: types.StringType},
				},
				map[string]attr.Value{
					"dynamic": types.DynamicValue(types.StringValue("test")),
					"ids":     types.SetValueMust(types.StringType, []attr.Value{}),
				},
			),
			expectError: false,
			validator:   AtLeastOneNonEmptyAttribute("dynamic", "ids"),
		},
		"dynamic value with empty string": {
			objectValue: types.ObjectValueMust(
				map[string]attr.Type{
					"dynamic": types.DynamicType,
					"ids":     types.SetType{ElemType: types.StringType},
				},
				map[string]attr.Value{
					"dynamic": types.DynamicValue(types.StringValue("")),
					"ids":     types.SetValueMust(types.StringType, []attr.Value{}),
				},
			),
			expectError: true,
			validator:   AtLeastOneNonEmptyAttribute("dynamic", "ids"),
		},
		"null dynamic value": {
			objectValue: types.ObjectValueMust(
				map[string]attr.Type{
					"dynamic": types.DynamicType,
					"ids":     types.SetType{ElemType: types.StringType},
				},
				map[string]attr.Value{
					"dynamic": types.DynamicNull(),
					"ids":     types.SetValueMust(types.StringType, []attr.Value{}),
				},
			),
			expectError: true,
			validator:   AtLeastOneNonEmptyAttribute("dynamic", "ids"),
		},
	}

	for name, testCase := range testCases {
		name, testCase := name, testCase

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			request := validator.ObjectRequest{
				Path:        path.Root("test"),
				ConfigValue: testCase.objectValue,
			}
			response := validator.ObjectResponse{}

			testCase.validator.ValidateObject(context.Background(), request, &response)

			if testCase.expectError && !response.Diagnostics.HasError() {
				t.Fatal("expected error, got none")
			}

			if !testCase.expectError && response.Diagnostics.HasError() {
				t.Fatalf("expected no error, got: %s", response.Diagnostics)
			}
		})
	}
}
