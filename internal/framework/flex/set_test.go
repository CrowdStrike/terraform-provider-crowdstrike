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

func TestExpandSetAs_Strings(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	testCases := []struct {
		name     string
		input    types.Set
		expected []string
		wantDiag bool
	}{
		{
			name:     "null set returns empty slice",
			input:    types.SetNull(types.StringType),
			expected: []string{},
			wantDiag: false,
		},
		{
			name:     "unknown set returns empty slice",
			input:    types.SetUnknown(types.StringType),
			expected: []string{},
			wantDiag: false,
		},
		{
			name: "empty set returns empty slice",
			input: types.SetValueMust(
				types.StringType,
				[]attr.Value{},
			),
			expected: []string{},
			wantDiag: false,
		},
		{
			name: "set with values returns slice",
			input: types.SetValueMust(
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
			result := flex.ExpandSetAs[string](ctx, tc.input, diags)

			assert.Equal(t, tc.expected, result)

			if tc.wantDiag {
				assert.True(t, diags.HasError(), "expected diagnostics but got none")
			} else {
				assert.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
			}
		})
	}
}

func TestExpandSetAs_Int64(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	testCases := []struct {
		name     string
		input    types.Set
		expected []int64
		wantDiag bool
	}{
		{
			name:     "null set returns empty slice",
			input:    types.SetNull(types.Int64Type),
			expected: []int64{},
			wantDiag: false,
		},
		{
			name: "set with values returns slice",
			input: types.SetValueMust(
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
			result := flex.ExpandSetAs[int64](ctx, tc.input, diags)

			assert.Equal(t, tc.expected, result)

			if tc.wantDiag {
				assert.True(t, diags.HasError(), "expected diagnostics but got none")
			} else {
				assert.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
			}
		})
	}
}

func TestExpandSetAs_Objects(t *testing.T) {
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
		input    types.Set
		expected []testObject
		wantDiag bool
	}{
		{
			name:     "null set returns empty slice",
			input:    types.SetNull(objectType),
			expected: []testObject{},
			wantDiag: false,
		},
		{
			name: "set with values returns slice",
			input: types.SetValueMust(
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
			result := flex.ExpandSetAs[testObject](ctx, tc.input, diags)

			assert.Equal(t, tc.expected, result)

			if tc.wantDiag {
				assert.True(t, diags.HasError(), "expected diagnostics but got none")
			} else {
				assert.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
			}
		})
	}
}

func TestMergeSet(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		a        types.Set
		b        types.Set
		expected []string
	}{
		{
			name:     "both null",
			a:        types.SetNull(types.StringType),
			b:        types.SetNull(types.StringType),
			expected: []string{},
		},
		{
			name:     "a null",
			a:        types.SetNull(types.StringType),
			b:        acctest.StringSetOrNull("group1", "group2"),
			expected: []string{"group1", "group2"},
		},
		{
			name:     "b null",
			a:        acctest.StringSetOrNull("group1", "group2"),
			b:        types.SetNull(types.StringType),
			expected: []string{"group1", "group2"},
		},
		{
			name:     "no overlap",
			a:        acctest.StringSetOrNull("group1", "group2"),
			b:        acctest.StringSetOrNull("group3", "group4"),
			expected: []string{"group1", "group2", "group3", "group4"},
		},
		{
			name:     "duplicates",
			a:        acctest.StringSetOrNull("group1", "group1", "group2"),
			b:        acctest.StringSetOrNull("group2", "group2", "group3"),
			expected: []string{"group1", "group2", "group3"},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var diags diag.Diagnostics
			result := flex.MergeStringSet(t.Context(), tc.a, tc.b, &diags)

			assert.False(t, diags.HasError(), "unexpected diagnostics errors: %v", diags.Errors())

			expected := acctest.StringSetOrNull(tc.expected...)
			assert.True(t, result.Equal(expected), "expected %v, got %v", expected, result)
		})
	}
}

func TestDiffSet(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		a        types.Set
		b        types.Set
		expected []string
	}{
		{
			name:     "a null",
			a:        types.SetNull(types.StringType),
			b:        acctest.StringSetOrNull("group1"),
			expected: nil,
		},
		{
			name:     "b null",
			a:        acctest.StringSetOrNull("group1", "group2"),
			b:        types.SetNull(types.StringType),
			expected: []string{"group1", "group2"},
		},
		{
			name:     "no changes",
			a:        acctest.StringSetOrNull("group1", "group2"),
			b:        acctest.StringSetOrNull("group1", "group2"),
			expected: nil,
		},
		{
			name:     "remove multiple",
			a:        acctest.StringSetOrNull("group1", "group2", "group3"),
			b:        acctest.StringSetOrNull("group1"),
			expected: []string{"group2", "group3"},
		},
		{
			name:     "b adds new",
			a:        acctest.StringSetOrNull("group1"),
			b:        acctest.StringSetOrNull("group1", "group2"),
			expected: nil,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var diags diag.Diagnostics
			result := flex.DiffStringSet(t.Context(), tc.a, tc.b, &diags)

			assert.False(t, diags.HasError(), "unexpected diagnostics errors: %v", diags.Errors())

			if tc.expected == nil {
				assert.Nil(t, result)
				return
			}

			resultSet := acctest.StringSetOrNull(convertToStrings(result)...)
			expectedSet := acctest.StringSetOrNull(tc.expected...)
			assert.True(t, resultSet.Equal(expectedSet), "expected %v, got %v", expectedSet, resultSet)
		})
	}
}

func convertToStrings(items []types.String) []string {
	result := make([]string, len(items))
	for i, item := range items {
		result[i] = item.ValueString()
	}
	return result
}

func TestFlattenStringValueSet(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		values   []string
		expected types.Set
	}{
		{
			name:     "nil slice returns null",
			values:   nil,
			expected: acctest.StringSetOrNull(),
		},
		{
			name:     "empty slice returns null",
			values:   []string{},
			expected: acctest.StringSetOrNull(),
		},
		{
			name:     "slice with valid values returns set",
			values:   []string{"group1", "group2", "group3"},
			expected: acctest.StringSetOrNull("group1", "group2", "group3"),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			result, diags := flex.FlattenStringValueSet(t.Context(), tc.values)

			assert.False(t, diags.HasError(), "unexpected diagnostics errors: %v", diags.Errors())
			assert.True(t, result.Equal(tc.expected), "expected %v, got %v", tc.expected, result)
		})
	}
}
