package utils

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// idsToModify takes a set of IDs from plan and state and returns the IDs to add and remove to get from the state to the plan.
// idsToAdd is the slice of IDs that are in the plan but not in the state.
// idsToRemove is the slice of IDs that are in the state but not in the plan.
// useful for resources with HostGroups, RuleGroups, etc.
func IDsToModify(
	ctx context.Context,
	plan, state types.Set,
) (idsToAdd []string, idsToRemove []string, diags diag.Diagnostics) {
	var planIDs, stateIDs []string
	planMap := make(map[string]bool)
	stateMap := make(map[string]bool)

	diags.Append(plan.ElementsAs(ctx, &planIDs, false)...)
	if diags.HasError() {
		return
	}
	diags.Append(state.ElementsAs(ctx, &stateIDs, false)...)
	if diags.HasError() {
		return
	}

	for _, id := range planIDs {
		planMap[id] = true
	}

	for _, id := range stateIDs {
		stateMap[id] = true
	}

	for _, id := range planIDs {
		if !stateMap[id] {
			idsToAdd = append(idsToAdd, id)
		}
	}

	for _, id := range stateIDs {
		if !planMap[id] {
			idsToRemove = append(idsToRemove, id)
		}
	}

	return
}
