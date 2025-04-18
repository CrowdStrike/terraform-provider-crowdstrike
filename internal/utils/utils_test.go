package utils

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"golang.org/x/exp/slices"
)

func TestSetIDsToModify(t *testing.T) {
	tests := []struct {
		name           string
		plan           []string
		state          []string
		expectedAdd    []string
		expectedRemove []string
	}{
		{
			name:           "empty",
			plan:           []string{},
			state:          []string{},
			expectedAdd:    []string{},
			expectedRemove: []string{},
		},
		{
			name:           "add",
			plan:           []string{"a"},
			state:          []string{},
			expectedAdd:    []string{"a"},
			expectedRemove: []string{},
		},
		{
			name:           "remove",
			plan:           []string{},
			state:          []string{"a"},
			expectedAdd:    []string{},
			expectedRemove: []string{"a"},
		},
		{
			name:           "add and remove",
			plan:           []string{"a", "b"},
			state:          []string{"a", "c"},
			expectedAdd:    []string{"b"},
			expectedRemove: []string{"c"},
		},
		{
			name:           "no change",
			plan:           []string{"a"},
			state:          []string{"a"},
			expectedAdd:    []string{},
			expectedRemove: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan, _ := types.SetValueFrom(t.Context(), types.StringType, tt.plan)
			state, _ := types.SetValueFrom(t.Context(), types.StringType, tt.state)

			idsToAdd, idsToRemove, diags := SetIDsToModify(t.Context(), plan, state)

			if !slices.Equal(idsToAdd, tt.expectedAdd) {
				t.Errorf("idsToAdd = %v, want %v", idsToAdd, tt.expectedAdd)
			}
			if !slices.Equal(idsToRemove, tt.expectedRemove) {
				t.Errorf("idsToRemove = %v, want %v", idsToRemove, tt.expectedRemove)
			}
			if diags.HasError() {
				t.Errorf("diags = %v, want no error", diags)
			}
		})
	}
}
