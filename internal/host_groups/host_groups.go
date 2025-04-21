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

// ConvertHostGroupsToSet converts a slice of models.HostGroupsHostGroupV1 to a terraform set.
func ConvertHostGroupsToSet(
	ctx context.Context,
	groups []*models.HostGroupsHostGroupV1,
) (basetypes.SetValue, diag.Diagnostics) {

	hostGroups := make([]types.String, 0, len(groups))
	for _, hostGroup := range groups {
		hostGroups = append(hostGroups, types.StringValue(*hostGroup.ID))
	}

	hostGroupIDs, diags := types.SetValueFrom(ctx, types.StringType, hostGroups)

	return hostGroupIDs, diags
}
