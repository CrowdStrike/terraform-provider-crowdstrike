package flex

import (
	"context"
	"testing"

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
			result := ExpandSetAs[string](ctx, tc.input, diags)

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
			result := ExpandSetAs[int64](ctx, tc.input, diags)

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
			result := ExpandSetAs[testObject](ctx, tc.input, diags)

			assert.Equal(t, tc.expected, result)

			if tc.wantDiag {
				assert.True(t, diags.HasError(), "expected diagnostics but got none")
			} else {
				assert.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
			}
		})
	}
}
