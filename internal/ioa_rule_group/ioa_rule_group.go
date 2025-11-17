package ioarulegroup

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// convertIOARuleGroupsToIDs converts []*models.IoaRuleGroupsRuleGroupV1 to a slice of types.String.
// The returned []types.String will never be null.
func convertIOARuleGroupsToIDs(ioaRuleGroups []*models.IoaRuleGroupsRuleGroupV1) []types.String {
	ioaIDs := make([]types.String, 0, len(ioaRuleGroups))
	for _, group := range ioaRuleGroups {
		if group != nil && group.ID != nil {
			ioaIDs = append(ioaIDs, types.StringPointerValue(group.ID))
		}
	}
	return ioaIDs
}

// ConvertIOARuleGroupToSet converts a []*models.IoaRuleGroupsRuleGroupV1 to a Terraform set of IOA rule group IDs.
// The returned types.SetValue will never be null.
func ConvertIOARuleGroupToSet(
	ctx context.Context,
	groups []*models.IoaRuleGroupsRuleGroupV1,
) (basetypes.SetValue, diag.Diagnostics) {
	return types.SetValueFrom(ctx, types.StringType, convertIOARuleGroupsToIDs(groups))
}

// ConvertIOARuleGroupToList converts a []*models.IoaRuleGroupsRuleGroupV1 to a Terraform list of IOA rule group IDs.
// The returned types.ListValue will never be null.
func ConvertIOARuleGroupToList(
	ctx context.Context,
	groups []*models.IoaRuleGroupsRuleGroupV1,
) (basetypes.ListValue, diag.Diagnostics) {
	return types.ListValueFrom(ctx, types.StringType, convertIOARuleGroupsToIDs(groups))
}
