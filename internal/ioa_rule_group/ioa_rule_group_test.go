package ioarulegroup

import (
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

func strPtr(s string) *string {
	return &s
}

func TestConvertIOARuleGroupsToIDs(t *testing.T) {
	tests := []struct {
		name     string
		groups   []*models.IoaRuleGroupsRuleGroupV1
		expected []types.String
	}{
		{
			name:     "empty slice",
			groups:   []*models.IoaRuleGroupsRuleGroupV1{},
			expected: []types.String{},
		},
		{
			name:     "nil slice",
			groups:   nil,
			expected: []types.String{},
		},
		{
			name: "nil entry",
			groups: []*models.IoaRuleGroupsRuleGroupV1{
				nil,
			},
			expected: []types.String{},
		},
		{
			name: "entry with nil ID",
			groups: []*models.IoaRuleGroupsRuleGroupV1{
				{ID: nil},
			},
			expected: []types.String{},
		},
		{
			name: "single valid entry",
			groups: []*models.IoaRuleGroupsRuleGroupV1{
				{ID: strPtr("id-1")},
			},
			expected: []types.String{types.StringValue("id-1")},
		},
		{
			name: "multiple valid entries",
			groups: []*models.IoaRuleGroupsRuleGroupV1{
				{ID: strPtr("id-1")},
				{ID: strPtr("id-2")},
				{ID: strPtr("id-3")},
			},
			expected: []types.String{
				types.StringValue("id-1"),
				types.StringValue("id-2"),
				types.StringValue("id-3"),
			},
		},
		{
			name: "mixed nil and valid entries",
			groups: []*models.IoaRuleGroupsRuleGroupV1{
				{ID: strPtr("id-1")},
				nil,
				{ID: nil},
				{ID: strPtr("id-2")},
			},
			expected: []types.String{
				types.StringValue("id-1"),
				types.StringValue("id-2"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertIOARuleGroupsToIDs(tt.groups)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertIOARuleGroupToSet(t *testing.T) {
	tests := []struct {
		name          string
		groups        []*models.IoaRuleGroupsRuleGroupV1
		expectedCount int
	}{
		{
			name:          "empty slice",
			groups:        []*models.IoaRuleGroupsRuleGroupV1{},
			expectedCount: 0,
		},
		{
			name: "valid entries",
			groups: []*models.IoaRuleGroupsRuleGroupV1{
				{ID: strPtr("id-1")},
				{ID: strPtr("id-2")},
			},
			expectedCount: 2,
		},
		{
			name: "skips nil entries",
			groups: []*models.IoaRuleGroupsRuleGroupV1{
				{ID: strPtr("id-1")},
				nil,
				{ID: strPtr("id-2")},
			},
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, diags := ConvertIOARuleGroupToSet(t.Context(), tt.groups)
			assert.False(t, diags.HasError())
			assert.Len(t, result.Elements(), tt.expectedCount)
		})
	}
}

func TestConvertIOARuleGroupToList(t *testing.T) {
	tests := []struct {
		name          string
		groups        []*models.IoaRuleGroupsRuleGroupV1
		expectedCount int
		expectedIDs   []string
	}{
		{
			name:          "empty slice",
			groups:        []*models.IoaRuleGroupsRuleGroupV1{},
			expectedCount: 0,
			expectedIDs:   []string{},
		},
		{
			name: "preserves order",
			groups: []*models.IoaRuleGroupsRuleGroupV1{
				{ID: strPtr("id-b")},
				{ID: strPtr("id-a")},
			},
			expectedCount: 2,
			expectedIDs:   []string{"id-b", "id-a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, diags := ConvertIOARuleGroupToList(t.Context(), tt.groups)
			assert.False(t, diags.HasError())
			assert.Len(t, result.Elements(), tt.expectedCount)

			if tt.expectedCount > 0 {
				var ids []string
				result.ElementsAs(t.Context(), &ids, false)
				assert.Equal(t, tt.expectedIDs, ids)
			}
		})
	}
}
