package utils

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

type testType struct {
	Name types.String `tfsdk:"name"`
}

func (t testType) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"name": types.StringType,
	}
}

func TestSliceToListTypeObject(t *testing.T) {
	tests := []struct {
		name       string
		elems      []testType
		wantLength int
		wantError  bool
	}{
		{
			name:       "empty_slice",
			elems:      []testType{},
			wantLength: 0,
			wantError:  false,
		},
		{
			name: "single_element",
			elems: []testType{
				{Name: types.StringValue("test1")},
			},
			wantLength: 1,
			wantError:  false,
		},
		{
			name: "multiple_elements",
			elems: []testType{
				{Name: types.StringValue("test1")},
				{Name: types.StringValue("test2")},
				{Name: types.StringValue("test3")},
			},
			wantLength: 3,
			wantError:  false,
		},
		{
			name:       "nil_slice",
			elems:      nil,
			wantLength: 0,
			wantError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			diags := diag.Diagnostics{}
			attrs := map[string]attr.Type{
				"name": types.StringType,
			}

			result := SliceToListTypeObject(ctx, tt.elems, attrs, &diags)

			if tt.wantError {
				assert.True(t, diags.HasError(), "expected error but got none")
			} else {
				assert.False(t, diags.HasError(), "unexpected error: %v", diags)
			}

			assert.Equal(t, tt.wantLength, len(result.Elements()), "unexpected list length")

			assert.True(t, !result.IsNull(), "expected .IsNull() to be false")

			if tt.wantLength > 0 {
				for i, elem := range result.Elements() {
					obj, ok := elem.(types.Object)
					assert.True(t, ok, "element %d is not types.Object", i)
					if !ok {
						continue
					}

					attrs := obj.Attributes()
					nameAttr, exists := attrs["name"]
					assert.True(t, exists, "element %d missing 'name' attribute", i)
					if !exists {
						continue
					}

					nameStr, ok := nameAttr.(types.String)
					assert.True(t, ok, "element %d 'name' is not types.String", i)
					if !ok {
						continue
					}

					assert.Equal(t, tt.elems[i].Name.ValueString(), nameStr.ValueString(),
						"element %d name mismatch", i)
				}
			}
		})
	}
}

func TestSliceToListTypeObject_WithPointers(t *testing.T) {
	tests := []struct {
		name       string
		elems      []*testType
		wantLength int
		wantError  bool
	}{
		{
			name:       "empty_slice_of_pointers",
			elems:      []*testType{},
			wantLength: 0,
			wantError:  false,
		},
		{
			name: "single_pointer_element",
			elems: []*testType{
				{Name: types.StringValue("test1")},
			},
			wantLength: 1,
			wantError:  false,
		},
		{
			name: "multiple_pointer_elements",
			elems: []*testType{
				{Name: types.StringValue("test1")},
				{Name: types.StringValue("test2")},
			},
			wantLength: 2,
			wantError:  false,
		},
		{
			name: "slice_with_nil_pointers",
			elems: []*testType{
				{Name: types.StringValue("test1")},
				nil,
				{Name: types.StringValue("test3")},
			},
			wantLength: 2,
			wantError:  false,
		},
		{
			name: "all_nil_pointers",
			elems: []*testType{
				nil,
				nil,
			},
			wantLength: 0,
			wantError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			diags := diag.Diagnostics{}
			attrs := map[string]attr.Type{
				"name": types.StringType,
			}

			result := SliceToListTypeObject(ctx, tt.elems, attrs, &diags)

			if tt.wantError {
				assert.True(t, diags.HasError(), "expected error but got none")
			} else {
				assert.False(t, diags.HasError(), "unexpected error: %v", diags)
			}

			assert.Equal(t, tt.wantLength, len(result.Elements()), "unexpected list length")

			assert.True(t, !result.IsNull(), "expected .IsNull() to be false")

			if tt.wantLength > 0 {
				resultIdx := 0
				for i, elem := range tt.elems {
					if elem == nil {
						continue
					}

					obj, ok := result.Elements()[resultIdx].(types.Object)
					assert.True(t, ok, "element %d is not types.Object", resultIdx)
					if !ok {
						resultIdx++
						continue
					}

					attrs := obj.Attributes()
					nameAttr, exists := attrs["name"]
					assert.True(t, exists, "element %d missing 'name' attribute", resultIdx)
					if !exists {
						resultIdx++
						continue
					}

					nameStr, ok := nameAttr.(types.String)
					assert.True(t, ok, "element %d 'name' is not types.String", resultIdx)
					if !ok {
						resultIdx++
						continue
					}

					assert.Equal(t, tt.elems[i].Name.ValueString(), nameStr.ValueString(),
						"element %d name mismatch", resultIdx)
					resultIdx++
				}
			}
		})
	}
}
