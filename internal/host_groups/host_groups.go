package hostgroups

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// HostGroupAction action for host group action api.
type HostGroupAction int

const (
	RemoveHostGroup HostGroupAction = iota
	AddHostGroup
)

// String convert HostGroupAction to string value the api accepts.
func (h HostGroupAction) String() string {
	return [...]string{"remove-host-group", "add-host-group"}[h]
}

// convertHostGroupsToIDs converts []*models.HostGroupsHostGroupV1 to a slice of types.String.
// The returned []types.String will never be null.
func convertHostGroupsToIDs(groups []*models.HostGroupsHostGroupV1) []types.String {
	groupIDs := make([]types.String, 0, len(groups))
	for _, group := range groups {
		if group != nil && group.ID != nil {
			groupIDs = append(groupIDs, types.StringPointerValue(group.ID))
		}
	}
	return groupIDs
}

// ConvertHostGroupsToSet converts []*models.HostGroupsHostGroupV1 to a Terraform set of host group IDs.
// The returned types.SetValue will never be null.
func ConvertHostGroupsToSet(
	ctx context.Context,
	groups []*models.HostGroupsHostGroupV1,
) (basetypes.SetValue, diag.Diagnostics) {
	return types.SetValueFrom(ctx, types.StringType, convertHostGroupsToIDs(groups))
}

// ConvertHostGroupsToSet converts []*models.HostGroupsHostGroupV1 to a Terraform list of host group IDs.
// The returned types.ListValue will never be null.
func ConvertHostGroupsToList(
	ctx context.Context,
	groups []*models.HostGroupsHostGroupV1,
) (basetypes.ListValue, diag.Diagnostics) {
	return types.ListValueFrom(ctx, types.StringType, convertHostGroupsToIDs(groups))
}
