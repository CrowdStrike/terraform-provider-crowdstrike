package ioarulegroup

import (
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

func TestWrapRulesResolvesTypeByName(t *testing.T) {
	tests := []struct {
		name         string
		apiRules     []*models.APIRuleV1
		expectedType map[string]string
	}{
		{
			name: "canonical windows ids",
			apiRules: []*models.APIRuleV1{
				{
					InstanceID:   utils.Addr("rule-1"),
					Name:         utils.Addr("Proc"),
					Description:  utils.Addr("d"),
					RuletypeID:   utils.Addr("1"),
					RuletypeName: utils.Addr("Process Creation"),
				},
			},
			expectedType: map[string]string{"rule-1": "Process Creation"},
		},
		{
			name: "legacy mac-range id in windows group resolves by name",
			apiRules: []*models.APIRuleV1{
				{
					InstanceID:   utils.Addr("rule-1"),
					Name:         utils.Addr("Proc"),
					Description:  utils.Addr("d"),
					RuletypeID:   utils.Addr("5"),
					RuletypeName: utils.Addr("Process Creation"),
				},
			},
			expectedType: map[string]string{"rule-1": "Process Creation"},
		},
		{
			name: "id absent from current catalog resolves by name",
			apiRules: []*models.APIRuleV1{
				{
					InstanceID:   utils.Addr("rule-1"),
					Name:         utils.Addr("Net"),
					Description:  utils.Addr("d"),
					RuletypeID:   utils.Addr("3"),
					RuletypeName: utils.Addr("Network Connection"),
				},
			},
			expectedType: map[string]string{"rule-1": "Network Connection"},
		},
		{
			name: "missing ruletype name yields empty type",
			apiRules: []*models.APIRuleV1{
				{
					InstanceID:  utils.Addr("rule-1"),
					Name:        utils.Addr("Proc"),
					Description: utils.Addr("d"),
					RuletypeID:  utils.Addr("1"),
				},
			},
			expectedType: map[string]string{"rule-1": ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			list, diags := wrapRules(t.Context(), tt.apiRules, nil)
			assert.False(t, diags.HasError())

			rules := utils.ListTypeAs[ioaRuleModel](t.Context(), list, &diags)
			assert.False(t, diags.HasError())
			assert.Len(t, rules, len(tt.expectedType))

			for _, r := range rules {
				want, ok := tt.expectedType[r.InstanceID.ValueString()]
				assert.True(t, ok, "unexpected instance id %q", r.InstanceID.ValueString())
				assert.Equal(t, want, r.Type.ValueString())
			}
		})
	}
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
			name: "entry with empty ID (flight control placeholder)",
			groups: []*models.IoaRuleGroupsRuleGroupV1{
				{ID: utils.Addr("")},
			},
			expected: []types.String{},
		},
		{
			name: "single valid entry",
			groups: []*models.IoaRuleGroupsRuleGroupV1{
				{ID: utils.Addr("id-1")},
			},
			expected: []types.String{types.StringValue("id-1")},
		},
		{
			name: "multiple valid entries",
			groups: []*models.IoaRuleGroupsRuleGroupV1{
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
			groups: []*models.IoaRuleGroupsRuleGroupV1{
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
			groups: []*models.IoaRuleGroupsRuleGroupV1{
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
				{ID: utils.Addr("id-1")},
				{ID: utils.Addr("id-2")},
			},
			expectedCount: 2,
		},
		{
			name: "skips nil entries",
			groups: []*models.IoaRuleGroupsRuleGroupV1{
				{ID: utils.Addr("id-1")},
				nil,
				{ID: utils.Addr("id-2")},
			},
			expectedCount: 2,
		},
		{
			name: "skips empty-ID placeholders",
			groups: []*models.IoaRuleGroupsRuleGroupV1{
				{ID: utils.Addr("id-1")},
				{ID: utils.Addr("")},
				{ID: utils.Addr("id-2")},
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
				{ID: utils.Addr("id-b")},
				{ID: utils.Addr("id-a")},
			},
			expectedCount: 2,
			expectedIDs:   []string{"id-b", "id-a"},
		},
		{
			name: "drops empty-ID placeholders and preserves order",
			groups: []*models.IoaRuleGroupsRuleGroupV1{
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
