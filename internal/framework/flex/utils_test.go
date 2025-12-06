package flex_test

import (
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

func TestUnique(t *testing.T) {
	t.Parallel()

	t.Run("empty slice", func(t *testing.T) {
		t.Parallel()
		input := []string{}
		result := flex.Unique(input)
		assert.Empty(t, result)
	})

	t.Run("nil slice", func(t *testing.T) {
		t.Parallel()
		var input []string
		result := flex.Unique(input)
		assert.Empty(t, result)
	})

	t.Run("no duplicates", func(t *testing.T) {
		t.Parallel()
		input := []string{"a", "b", "c"}
		result := flex.Unique(input)
		assert.Equal(t, []string{"a", "b", "c"}, result)
	})

	t.Run("with duplicates", func(t *testing.T) {
		t.Parallel()
		input := []string{"a", "b", "a", "c", "b", "d"}
		result := flex.Unique(input)
		assert.Equal(t, []string{"a", "b", "c", "d"}, result)
	})

	t.Run("all duplicates", func(t *testing.T) {
		t.Parallel()
		input := []string{"a", "a", "a", "a"}
		result := flex.Unique(input)
		assert.Equal(t, []string{"a"}, result)
	})

	t.Run("preserves first occurrence order", func(t *testing.T) {
		t.Parallel()
		input := []string{"c", "a", "b", "a", "c"}
		result := flex.Unique(input)
		assert.Equal(t, []string{"c", "a", "b"}, result)
	})

	t.Run("single element", func(t *testing.T) {
		t.Parallel()
		input := []string{"only"}
		result := flex.Unique(input)
		assert.Equal(t, []string{"only"}, result)
	})

	t.Run("integers", func(t *testing.T) {
		t.Parallel()
		input := []int{1, 2, 3, 2, 4, 1, 5}
		result := flex.Unique(input)
		assert.Equal(t, []int{1, 2, 3, 4, 5}, result)
	})

	t.Run("types.String", func(t *testing.T) {
		t.Parallel()
		input := []types.String{
			types.StringValue("id1"),
			types.StringValue("id2"),
			types.StringValue("id1"),
			types.StringValue("id3"),
		}
		result := flex.Unique(input)
		assert.Len(t, result, 3)
		assert.Equal(t, "id1", result[0].ValueString())
		assert.Equal(t, "id2", result[1].ValueString())
		assert.Equal(t, "id3", result[2].ValueString())
	})

	t.Run("types.Bool", func(t *testing.T) {
		t.Parallel()
		input := []types.Bool{
			types.BoolValue(true),
			types.BoolValue(false),
			types.BoolValue(true),
			types.BoolValue(false),
		}
		result := flex.Unique(input)
		assert.Len(t, result, 2)
		assert.True(t, result[0].ValueBool())
		assert.False(t, result[1].ValueBool())
	})

	t.Run("types.Int64", func(t *testing.T) {
		t.Parallel()
		input := []types.Int64{
			types.Int64Value(1),
			types.Int64Value(2),
			types.Int64Value(1),
			types.Int64Value(3),
			types.Int64Value(2),
		}
		result := flex.Unique(input)
		assert.Len(t, result, 3)
		assert.Equal(t, int64(1), result[0].ValueInt64())
		assert.Equal(t, int64(2), result[1].ValueInt64())
		assert.Equal(t, int64(3), result[2].ValueInt64())
	})

	t.Run("types.Set with types.String elements", func(t *testing.T) {
		t.Parallel()

		input := acctest.StringSetOrNull("a", "b", "b", "c", "c")
		result := flex.Unique(input.Elements())
		assert.Len(t, result, 3)
		assert.Equal(t, result[0], types.StringValue("a"))
		assert.Equal(t, result[1], types.StringValue("b"))
		assert.Equal(t, result[2], types.StringValue("c"))
	})

	t.Run("types.List with types.String elements", func(t *testing.T) {
		t.Parallel()

		input := acctest.StringListOrNull("a", "b", "b", "c", "c")
		result := flex.Unique(input.Elements())
		assert.Len(t, result, 3)
		assert.Equal(t, result[0], types.StringValue("a"))
		assert.Equal(t, result[1], types.StringValue("b"))
		assert.Equal(t, result[2], types.StringValue("c"))
	})

	t.Run("empty strings", func(t *testing.T) {
		t.Parallel()
		input := []string{"a", "", "b", "", "c"}
		result := flex.Unique(input)
		assert.Equal(t, []string{"a", "", "b", "c"}, result)
	})

	t.Run("case sensitive", func(t *testing.T) {
		t.Parallel()
		input := []string{"A", "a", "B", "b"}
		result := flex.Unique(input)
		assert.Equal(t, []string{"A", "a", "B", "b"}, result)
	})
}
