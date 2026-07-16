package hostgroups

import (
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

func TestConvertHostGroupsToIDs(t *testing.T) {
	tests := []struct {
		name     string
		groups   []*models.HostGroupsHostGroupV1
		expected []types.String
	}{
		{
			name:     "empty slice",
			groups:   []*models.HostGroupsHostGroupV1{},
			expected: []types.String{},
		},
		{
			name:     "nil slice",
			groups:   nil,
			expected: []types.String{},
		},
		{
			name: "nil entry",
			groups: []*models.HostGroupsHostGroupV1{
				nil,
			},
			expected: []types.String{},
		},
		{
			name: "entry with nil ID",
			groups: []*models.HostGroupsHostGroupV1{
				{ID: nil},
			},
			expected: []types.String{},
		},
		{
			name: "entry with empty ID (flight control placeholder)",
			groups: []*models.HostGroupsHostGroupV1{
				{ID: utils.Addr("")},
			},
			expected: []types.String{},
		},
		{
			name: "single valid entry",
			groups: []*models.HostGroupsHostGroupV1{
				{ID: utils.Addr("id-1")},
			},
			expected: []types.String{types.StringValue("id-1")},
		},
		{
			name: "multiple valid entries",
			groups: []*models.HostGroupsHostGroupV1{
				{ID: utils.Addr("id-1")},
				{ID: utils.Addr("id-2")},
				{ID: utils.Addr("id-3")},
			},
			expected: []types.String{
				types.StringValue("id-1"),
				types.StringValue("id-2"),
				types.StringValue("id-3"),
			},
		},
		{
			name: "mixed nil and valid entries",
			groups: []*models.HostGroupsHostGroupV1{
				{ID: utils.Addr("id-1")},
				nil,
				{ID: nil},
				{ID: utils.Addr("id-2")},
			},
			expected: []types.String{
				types.StringValue("id-1"),
				types.StringValue("id-2"),
			},
		},
		{
			name: "mixed empty-ID placeholders and valid entries",
			groups: []*models.HostGroupsHostGroupV1{
				{ID: utils.Addr("id-1")},
				{ID: utils.Addr("")},
				{ID: utils.Addr("id-2")},
				{ID: utils.Addr("")},
			},
			expected: []types.String{
				types.StringValue("id-1"),
				types.StringValue("id-2"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertHostGroupsToIDs(tt.groups)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertHostGroupsToSet(t *testing.T) {
	tests := []struct {
		name          string
		groups        []*models.HostGroupsHostGroupV1
		expectedCount int
	}{
		{
			name:          "empty slice",
			groups:        []*models.HostGroupsHostGroupV1{},
			expectedCount: 0,
		},
		{
			name: "valid entries",
			groups: []*models.HostGroupsHostGroupV1{
				{ID: utils.Addr("id-1")},
				{ID: utils.Addr("id-2")},
			},
			expectedCount: 2,
		},
		{
			name: "skips nil entries",
			groups: []*models.HostGroupsHostGroupV1{
				{ID: utils.Addr("id-1")},
				nil,
				{ID: utils.Addr("id-2")},
			},
			expectedCount: 2,
		},
		{
			name: "skips empty-ID placeholders",
			groups: []*models.HostGroupsHostGroupV1{
				{ID: utils.Addr("id-1")},
				{ID: utils.Addr("")},
				{ID: utils.Addr("id-2")},
			},
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, diags := ConvertHostGroupsToSet(t.Context(), tt.groups)
			assert.False(t, diags.HasError())
			assert.False(t, result.IsNull())
			assert.Len(t, result.Elements(), tt.expectedCount)
		})
	}
}

func TestConvertHostGroupsToList(t *testing.T) {
	tests := []struct {
		name          string
		groups        []*models.HostGroupsHostGroupV1
		expectedCount int
		expectedIDs   []string
	}{
		{
			name:          "empty slice",
			groups:        []*models.HostGroupsHostGroupV1{},
			expectedCount: 0,
			expectedIDs:   []string{},
		},
		{
			name: "preserves order",
			groups: []*models.HostGroupsHostGroupV1{
				{ID: utils.Addr("id-b")},
				{ID: utils.Addr("id-a")},
			},
			expectedCount: 2,
			expectedIDs:   []string{"id-b", "id-a"},
		},
		{
			name: "drops empty-ID placeholders and preserves order",
			groups: []*models.HostGroupsHostGroupV1{
				{ID: utils.Addr("id-b")},
				{ID: utils.Addr("")},
				{ID: utils.Addr("id-a")},
			},
			expectedCount: 2,
			expectedIDs:   []string{"id-b", "id-a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, diags := ConvertHostGroupsToList(t.Context(), tt.groups)
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
