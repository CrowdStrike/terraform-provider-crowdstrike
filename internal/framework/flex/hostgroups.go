package flex

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// FlattenHostGroupsToSet converts []*models.HostGroupsHostGroupV1 to a Terraform set of host group IDs.
// Returns null if there are no groups or all groups are nil/have nil IDs.
func FlattenHostGroupsToSet(
	ctx context.Context,
	groups []*models.HostGroupsHostGroupV1,
) (types.Set, diag.Diagnostics) {
	if len(groups) == 0 {
		return types.SetNull(types.StringType), nil
	}

	groupIDs := make([]string, 0, len(groups))
	for _, group := range groups {
		if group != nil && group.ID != nil {
			groupIDs = append(groupIDs, *group.ID)
		}
	}

	return FlattenStringValueSet(ctx, groupIDs)
}

// FlattenHostGroupsToList converts []*models.HostGroupsHostGroupV1 to a Terraform list of host group IDs.
// Returns null if there are no groups or all groups are nil/have nil IDs.
func FlattenHostGroupsToList(
	ctx context.Context,
	groups []*models.HostGroupsHostGroupV1,
) (types.List, diag.Diagnostics) {
	if len(groups) == 0 {
		return types.ListNull(types.StringType), nil
	}

	groupIDs := make([]string, 0, len(groups))
	for _, group := range groups {
		if group != nil && group.ID != nil {
			groupIDs = append(groupIDs, *group.ID)
		}
	}

	return FlattenStringValueList(ctx, groupIDs)
}
