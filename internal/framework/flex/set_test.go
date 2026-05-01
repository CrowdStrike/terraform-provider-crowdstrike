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

func TestExpandSetWithConverter(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	doubleConverter := func(source types.Int64) (int64, diag.Diagnostics) {
		return source.ValueInt64() * 2, nil
	}

	positiveOnlyConverter := func(source types.Int64) (int64, diag.Diagnostics) {
		var diags diag.Diagnostics
		val := source.ValueInt64()
		if val < 0 {
			diags.AddError("Invalid Value", "negative values not allowed")
			return 0, diags
		}
		return val, diags
	}

	testCases := []struct {
		name      string
		input     types.Set
		converter func(types.Int64) (int64, diag.Diagnostics)
		expected  []int64
		wantDiag  bool
	}{
		{
			name:      "null set returns empty slice",
			input:     types.SetNull(types.Int64Type),
			converter: doubleConverter,
			expected:  []int64{},
			wantDiag:  false,
		},
		{
			name:      "unknown set returns empty slice",
			input:     types.SetUnknown(types.Int64Type),
			converter: doubleConverter,
			expected:  []int64{},
			wantDiag:  false,
		},
		{
			name: "empty set returns empty slice",
			input: types.SetValueMust(
				types.Int64Type,
				[]attr.Value{},
			),
			converter: doubleConverter,
			expected:  []int64{},
			wantDiag:  false,
		},
		{
			name: "converts values using converter function",
			input: types.SetValueMust(
				types.Int64Type,
				[]attr.Value{
					types.Int64Value(1),
					types.Int64Value(2),
					types.Int64Value(3),
				},
			),
			converter: doubleConverter,
			expected:  []int64{2, 4, 6},
			wantDiag:  false,
		},
		{
			name: "converter returns diagnostics on error",
			input: types.SetValueMust(
				types.Int64Type,
				[]attr.Value{
					types.Int64Value(1),
					types.Int64Value(-5),
					types.Int64Value(3),
				},
			),
			converter: positiveOnlyConverter,
			expected:  []int64{},
			wantDiag:  true,
		},
		{
			name: "converter with all valid values",
			input: types.SetValueMust(
				types.Int64Type,
				[]attr.Value{
					types.Int64Value(10),
					types.Int64Value(20),
				},
			),
			converter: positiveOnlyConverter,
			expected:  []int64{10, 20},
			wantDiag:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, diags := flex.ExpandSetWithConverter(ctx, tc.input, tc.converter)

			assert.Equal(t, tc.expected, result)

			if tc.wantDiag {
				assert.True(t, diags.HasError(), "expected diagnostics but got none")
			} else {
				assert.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
			}
		})
	}
}

func TestExpandSetWithConverter_Objects(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	objectType := types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"name":  types.StringType,
			"value": types.Int64Type,
		},
	}

	valueExtractor := func(source testObject) (int64, diag.Diagnostics) {
		return source.Value.ValueInt64(), nil
	}

	stringFormatter := func(source testObject) (string, diag.Diagnostics) {
		return source.Name.ValueString() + "=" + types.Int64Value(source.Value.ValueInt64()).String(), nil
	}

	t.Run("converts objects to primitives", func(t *testing.T) {
		input := types.SetValueMust(
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
		)

		result, diags := flex.ExpandSetWithConverter(ctx, input, valueExtractor)

		assert.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
		assert.Equal(t, []int64{100, 200}, result)
	})

	t.Run("converts objects to strings", func(t *testing.T) {
		input := types.SetValueMust(
			objectType,
			[]attr.Value{
				types.ObjectValueMust(
					objectType.AttrTypes,
					map[string]attr.Value{
						"name":  types.StringValue("alpha"),
						"value": types.Int64Value(1),
					},
				),
				types.ObjectValueMust(
					objectType.AttrTypes,
					map[string]attr.Value{
						"name":  types.StringValue("beta"),
						"value": types.Int64Value(2),
					},
				),
			},
		)

		result, diags := flex.ExpandSetWithConverter(ctx, input, stringFormatter)

		assert.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
		assert.Contains(t, result, "alpha=1")
		assert.Contains(t, result, "beta=2")
	})
}

func TestFlattenObjectValueSetFrom(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	objectType := types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"name":  types.StringType,
			"value": types.Int64Type,
		},
	}

	type sourceData struct {
		name  string
		value int64
	}

	toTestObjectConverter := func(source sourceData) (testObject, diag.Diagnostics) {
		return testObject{
			Name:  types.StringValue(source.name),
			Value: types.Int64Value(source.value),
		}, nil
	}

	validatingConverter := func(source sourceData) (testObject, diag.Diagnostics) {
		var diags diag.Diagnostics
		if source.name == "" {
			diags.AddError("Invalid Data", "name cannot be empty")
			return testObject{}, diags
		}
		return testObject{
			Name:  types.StringValue(source.name),
			Value: types.Int64Value(source.value),
		}, diags
	}

	testCases := []struct {
		name       string
		sources    []sourceData
		converter  func(sourceData) (testObject, diag.Diagnostics)
		expected   map[string]int64
		expectNull bool
		wantDiag   bool
	}{
		{
			name:       "nil slice returns null set",
			sources:    nil,
			converter:  toTestObjectConverter,
			expected:   nil,
			expectNull: true,
			wantDiag:   false,
		},
		{
			name:       "empty slice returns null set",
			sources:    []sourceData{},
			converter:  toTestObjectConverter,
			expected:   nil,
			expectNull: true,
			wantDiag:   false,
		},
		{
			name: "converts valid sources to set",
			sources: []sourceData{
				{name: "first", value: 100},
				{name: "second", value: 200},
			},
			converter: toTestObjectConverter,
			expected: map[string]int64{
				"first":  100,
				"second": 200,
			},
			expectNull: false,
			wantDiag:   false,
		},
		{
			name: "returns null set when converter returns diagnostics",
			sources: []sourceData{
				{name: "first", value: 100},
				{name: "", value: 200},
			},
			converter:  validatingConverter,
			expected:   nil,
			expectNull: true,
			wantDiag:   true,
		},
		{
			name: "single element converts successfully",
			sources: []sourceData{
				{name: "only", value: 42},
			},
			converter: toTestObjectConverter,
			expected: map[string]int64{
				"only": 42,
			},
			expectNull: false,
			wantDiag:   false,
		},
		{
			name: "multiple elements with different values",
			sources: []sourceData{
				{name: "alpha", value: 10},
				{name: "beta", value: 20},
				{name: "gamma", value: 30},
			},
			converter: toTestObjectConverter,
			expected: map[string]int64{
				"alpha": 10,
				"beta":  20,
				"gamma": 30,
			},
			expectNull: false,
			wantDiag:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, diags := flex.FlattenObjectValueSetFrom(ctx, objectType, tc.sources, tc.converter)

			if tc.wantDiag {
				assert.True(t, diags.HasError(), "expected diagnostics but got none")
			} else {
				assert.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
			}

			if tc.expectNull {
				assert.True(t, result.IsNull(), "expected null set but got %v", result)
			} else {
				assert.False(t, result.IsNull(), "expected non-null set but got null")
				assert.Equal(t, len(tc.sources), len(result.Elements()))

				if tc.expected != nil {
					var converted []testObject
					diags.Append(result.ElementsAs(ctx, &converted, false)...)
					assert.False(t, diags.HasError(), "failed to extract elements: %v", diags)
					assert.Len(t, converted, len(tc.expected))

					actualValues := make(map[string]int64)
					for _, obj := range converted {
						actualValues[obj.Name.ValueString()] = obj.Value.ValueInt64()
					}

					assert.Equal(t, tc.expected, actualValues)
				}
			}
		})
	}
}
