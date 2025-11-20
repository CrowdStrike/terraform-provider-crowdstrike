package validators

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

var imageObjectType = types.ObjectType{
	AttrTypes: map[string]attr.Type{
		"registry":     types.StringType,
		"repositories": types.ListType{ElemType: types.StringType},
	},
}

func makeImageObject(registry, repository string) types.Object {
	return types.ObjectValueMust(
		imageObjectType.AttrTypes,
		map[string]attr.Value{
			"registry":     types.StringValue(registry),
			"repositories": types.ListValueMust(types.StringType, []attr.Value{types.StringValue(repository)}),
		},
	)
}

func makeImageObjectWithUnknownRegistry(repository string) types.Object {
	return types.ObjectValueMust(
		imageObjectType.AttrTypes,
		map[string]attr.Value{
			"registry":     types.StringUnknown(),
			"repositories": types.ListValueMust(types.StringType, []attr.Value{types.StringValue(repository)}),
		},
	)
}

func makeImageObjectWithNullRegistry(repository string) types.Object {
	return types.ObjectValueMust(
		imageObjectType.AttrTypes,
		map[string]attr.Value{
			"registry":     types.StringNull(),
			"repositories": types.ListValueMust(types.StringType, []attr.Value{types.StringValue(repository)}),
		},
	)
}

func makeImageList(objects ...types.Object) types.List {
	values := make([]attr.Value, len(objects))
	for i, obj := range objects {
		values[i] = obj
	}
	return types.ListValueMust(imageObjectType, values)
}

func TestListObjectUniqueString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		val         types.List
		expectError bool
	}{
		{
			name:        "null",
			val:         types.ListNull(imageObjectType),
			expectError: false,
		},
		{
			name:        "unknown",
			val:         types.ListUnknown(imageObjectType),
			expectError: false,
		},
		{
			name: "valid - single item",
			val: makeImageList(
				makeImageObject("docker.io", "nginx"),
			),
			expectError: false,
		},
		{
			name: "valid - multiple unique items",
			val: makeImageList(
				makeImageObject("docker.io", "nginx"),
				makeImageObject("gcr.io", "alpine"),
				makeImageObject("ghcr.io", "myapp"),
			),
			expectError: false,
		},
		{
			name: "valid - unknown attribute value",
			val: makeImageList(
				makeImageObjectWithUnknownRegistry("nginx"),
				makeImageObject("gcr.io", "alpine"),
			),
			expectError: false,
		},
		{
			name: "valid - null attribute value",
			val: makeImageList(
				makeImageObjectWithNullRegistry("nginx"),
				makeImageObject("gcr.io", "alpine"),
			),
			expectError: false,
		},
		{
			name: "invalid - duplicate registry values",
			val: makeImageList(
				makeImageObject("docker.io", "nginx"),
				makeImageObject("docker.io", "alpine"),
			),
			expectError: true,
		},
		{
			name: "invalid - multiple duplicates",
			val: makeImageList(
				makeImageObject("docker.io", "nginx"),
				makeImageObject("docker.io", "alpine"),
				makeImageObject("gcr.io", "myapp"),
				makeImageObject("gcr.io", "yourapp"),
			),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			request := validator.ListRequest{
				Path:           path.Root("test"),
				PathExpression: path.MatchRoot("test"),
				ConfigValue:    tt.val,
			}
			response := validator.ListResponse{}

			ListObjectUniqueString("registry").ValidateList(context.Background(), request, &response)

			if tt.expectError {
				assert.True(t, response.Diagnostics.HasError(), "expected error but got none")
			} else {
				assert.False(t, response.Diagnostics.HasError(), "unexpected error: %s", response.Diagnostics)
			}
		})
	}
}
