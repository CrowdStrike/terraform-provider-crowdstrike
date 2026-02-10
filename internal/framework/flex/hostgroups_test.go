package flex_test

import (
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

func TestFlattenHostGroupsToSet(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		groups   []*models.HostGroupsHostGroupV1
		expected types.Set
	}{
		{
			name:     "nil groups returns null",
			groups:   nil,
			expected: acctest.StringSetOrNull(),
		},
		{
			name:     "empty groups returns null",
			groups:   []*models.HostGroupsHostGroupV1{},
			expected: acctest.StringSetOrNull(),
		},
		{
			name: "groups with nil IDs returns null",
			groups: []*models.HostGroupsHostGroupV1{
				{ID: nil},
				{ID: nil},
			},
			expected: acctest.StringSetOrNull(),
		},
		{
			name: "groups with valid IDs returns set",
			groups: []*models.HostGroupsHostGroupV1{
				{ID: utils.Addr("group1")},
				{ID: utils.Addr("group2")},
				{ID: utils.Addr("group3")},
			},
			expected: acctest.StringSetOrNull("group1", "group2", "group3"),
		},
		{
			name: "mixed nil and valid IDs returns set with valid IDs",
			groups: []*models.HostGroupsHostGroupV1{
				{ID: utils.Addr("group1")},
				{ID: nil},
				{ID: utils.Addr("group2")},
			},
			expected: acctest.StringSetOrNull("group1", "group2"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, diags := flex.FlattenHostGroupsToSet(t.Context(), tc.groups)

			assert.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
			assert.True(t, result.Equal(tc.expected), "expected %v, got %v", tc.expected, result)
		})
	}
}

func TestFlattenHostGroupsToList(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		groups   []*models.HostGroupsHostGroupV1
		expected types.List
	}{
		{
			name:     "nil groups returns null",
			groups:   nil,
			expected: acctest.StringListOrNull(),
		},
		{
			name:     "empty groups returns null",
			groups:   []*models.HostGroupsHostGroupV1{},
			expected: acctest.StringListOrNull(),
		},
		{
			name: "groups with nil IDs returns null",
			groups: []*models.HostGroupsHostGroupV1{
				{ID: nil},
				{ID: nil},
			},
			expected: acctest.StringListOrNull(),
		},
		{
			name: "groups with valid IDs returns list",
			groups: []*models.HostGroupsHostGroupV1{
				{ID: utils.Addr("group1")},
				{ID: utils.Addr("group2")},
				{ID: utils.Addr("group3")},
			},
			expected: acctest.StringListOrNull("group1", "group2", "group3"),
		},
		{
			name: "mixed nil and valid IDs returns list with valid IDs",
			groups: []*models.HostGroupsHostGroupV1{
				{ID: utils.Addr("group1")},
				{ID: nil},
				{ID: utils.Addr("group2")},
			},
			expected: acctest.StringListOrNull("group1", "group2"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, diags := flex.FlattenHostGroupsToList(t.Context(), tc.groups)

			assert.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
			assert.True(t, result.Equal(tc.expected), "expected %v, got %v", tc.expected, result)
		})
	}
}
