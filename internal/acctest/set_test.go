package acctest_test

import (
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

func TestStringSetOrNull(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		values []string
		want   types.Set
	}{
		{
			name:   "empty slice returns null",
			values: []string{},
			want:   types.SetNull(types.StringType),
		},
		{
			name:   "nil slice returns null",
			values: nil,
			want:   types.SetNull(types.StringType),
		},
		{
			name:   "single value",
			values: []string{"test"},
			want: types.SetValueMust(types.StringType, []attr.Value{
				types.StringValue("test"),
			}),
		},
		{
			name:   "multiple values",
			values: []string{"value1", "value2", "value3"},
			want: types.SetValueMust(types.StringType, []attr.Value{
				types.StringValue("value1"),
				types.StringValue("value2"),
				types.StringValue("value3"),
			}),
		},
		{
			name:   "single empty string",
			values: []string{""},
			want: types.SetValueMust(types.StringType, []attr.Value{
				types.StringValue(""),
			}),
		},
		{
			name:   "values with whitespace",
			values: []string{"  test  ", "value with spaces"},
			want: types.SetValueMust(types.StringType, []attr.Value{
				types.StringValue("  test  "),
				types.StringValue("value with spaces"),
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := acctest.StringSetOrNull(tt.values...)
			assert.True(t, got.Equal(tt.want), "StringSetOrNull() = %v, want %v", got, tt.want)
		})
	}
}
