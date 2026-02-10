package flex_test

import (
	"context"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

type testObject struct {
	Name  types.String `tfsdk:"name"`
	Value types.Int64  `tfsdk:"value"`
}

func TestExpandListAs_Strings(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	testCases := []struct {
		name     string
		input    types.List
		expected []string
		wantDiag bool
	}{
		{
			name:     "null list returns empty slice",
			input:    types.ListNull(types.StringType),
			expected: []string{},
			wantDiag: false,
		},
		{
			name:     "unknown list returns empty slice",
			input:    types.ListUnknown(types.StringType),
			expected: []string{},
			wantDiag: false,
		},
		{
			name: "empty list returns empty slice",
			input: types.ListValueMust(
				types.StringType,
				[]attr.Value{},
			),
			expected: []string{},
			wantDiag: false,
		},
		{
			name: "list with values returns slice",
			input: types.ListValueMust(
				types.StringType,
				[]attr.Value{
					types.StringValue("value1"),
					types.StringValue("value2"),
					types.StringValue("value3"),
				},
			),
			expected: []string{"value1", "value2", "value3"},
			wantDiag: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			diags := &diag.Diagnostics{}
			result := flex.ExpandListAs[string](ctx, tc.input, diags)

			assert.Equal(t, tc.expected, result)

			if tc.wantDiag {
				assert.True(t, diags.HasError(), "expected diagnostics but got none")
			} else {
				assert.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
			}
		})
	}
}

func TestExpandListAs_Int64(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	testCases := []struct {
		name     string
		input    types.List
		expected []int64
		wantDiag bool
	}{
		{
			name:     "null list returns empty slice",
			input:    types.ListNull(types.Int64Type),
			expected: []int64{},
			wantDiag: false,
		},
		{
			name: "list with values returns slice",
			input: types.ListValueMust(
				types.Int64Type,
				[]attr.Value{
					types.Int64Value(1),
					types.Int64Value(2),
					types.Int64Value(3),
				},
			),
			expected: []int64{1, 2, 3},
			wantDiag: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			diags := &diag.Diagnostics{}
			result := flex.ExpandListAs[int64](ctx, tc.input, diags)

			assert.Equal(t, tc.expected, result)

			if tc.wantDiag {
				assert.True(t, diags.HasError(), "expected diagnostics but got none")
			} else {
				assert.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
			}
		})
	}
}

func TestExpandListAs_Objects(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	objectType := types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"name":  types.StringType,
			"value": types.Int64Type,
		},
	}

	testCases := []struct {
		name     string
		input    types.List
		expected []testObject
		wantDiag bool
	}{
		{
			name:     "null list returns empty slice",
			input:    types.ListNull(objectType),
			expected: []testObject{},
			wantDiag: false,
		},
		{
			name: "list with values returns slice",
			input: types.ListValueMust(
				objectType,
				[]attr.Value{
					types.ObjectValueMust(
						objectType.AttrTypes,
						map[string]attr.Value{
							"name":  types.StringValue("first"),
							"value": types.Int64Value(100),
						},
					),
					types.ObjectValueMust(
						objectType.AttrTypes,
						map[string]attr.Value{
							"name":  types.StringValue("second"),
							"value": types.Int64Value(200),
						},
					),
				},
			),
			expected: []testObject{
				{
					Name:  types.StringValue("first"),
					Value: types.Int64Value(100),
				},
				{
					Name:  types.StringValue("second"),
					Value: types.Int64Value(200),
				},
			},
			wantDiag: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			diags := &diag.Diagnostics{}
			result := flex.ExpandListAs[testObject](ctx, tc.input, diags)

			assert.Equal(t, tc.expected, result)

			if tc.wantDiag {
				assert.True(t, diags.HasError(), "expected diagnostics but got none")
			} else {
				assert.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
			}
		})
	}
}

func TestFlattenStringValueList(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		values   []string
		expected types.List
	}{
		{
			name:     "nil slice returns null",
			values:   nil,
			expected: acctest.StringListOrNull(),
		},
		{
			name:     "empty slice returns null",
			values:   []string{},
			expected: acctest.StringListOrNull(),
		},
		{
			name:     "slice with valid values returns list",
			values:   []string{"value1", "value2", "value3"},
			expected: acctest.StringListOrNull("value1", "value2", "value3"),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			result, diags := flex.FlattenStringValueList(t.Context(), tc.values)

			assert.False(t, diags.HasError(), "unexpected diagnostics errors: %v", diags.Errors())
			assert.True(t, result.Equal(tc.expected), "expected %v, got %v", tc.expected, result)
		})
	}
}
