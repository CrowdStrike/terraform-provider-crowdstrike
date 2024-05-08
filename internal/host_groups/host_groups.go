package hostgroups

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
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

// GetHostGroupsToModify takes in a slice of planned host groups and a slice of current host groups, and returns
// the host groups to add and remove.
func GetHostGroupsToModify(
	ctx context.Context,
	plan, state types.Set,
) (hostGroupsToAdd []string, hostGroupsToRemove []string, diags diag.Diagnostics) {
	var planHostGroupIDs, stateHostGroupIds []string
	planMap := make(map[string]bool)
	stateMap := make(map[string]bool)

	diags.Append(plan.ElementsAs(ctx, &planHostGroupIDs, false)...)
	if diags.HasError() {
		return
	}
	diags.Append(state.ElementsAs(ctx, &stateHostGroupIds, false)...)
	if diags.HasError() {
		return
	}

	for _, id := range planHostGroupIDs {
		planMap[id] = true
	}

	for _, id := range stateHostGroupIds {
		stateMap[id] = true
	}

	for _, id := range planHostGroupIDs {
		if !stateMap[id] {
			hostGroupsToAdd = append(hostGroupsToAdd, id)
		}
	}

	for _, id := range stateHostGroupIds {
		if !planMap[id] {
			hostGroupsToRemove = append(hostGroupsToRemove, id)
		}
	}

	return
}
