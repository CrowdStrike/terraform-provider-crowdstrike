package utils

import (
	"context"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// SetIDsToModify takes a set of IDs from plan and state and returns the IDs to add and remove to get from the state to the plan.
// idsToAdd is the slice of IDs that are in the plan but not in the state.
// idsToRemove is the slice of IDs that are in the state but not in the plan.
// useful for resources with HostGroups, RuleGroups, etc.
func SetIDsToModify(
	ctx context.Context,
	plan, state types.Set,
) (idsToAdd []string, idsToRemove []string, diags diag.Diagnostics) {
	if len(plan.Elements()) == 0 && len(state.Elements()) == 0 {
		return
	}

	var planIDs, stateIDs []types.String
	planMap := make(map[string]bool)
	stateMap := make(map[string]bool)

	if !plan.IsUnknown() && !plan.IsNull() {
		diags.Append(plan.ElementsAs(ctx, &planIDs, false)...)
		if diags.HasError() {
			return
		}
	}

	if !state.IsUnknown() && !state.IsNull() {
		diags.Append(state.ElementsAs(ctx, &stateIDs, false)...)
		if diags.HasError() {
			return
		}
	}

	for _, id := range planIDs {
		if !id.IsUnknown() && !id.IsNull() {
			planMap[id.ValueString()] = true
		}
	}

	for _, id := range stateIDs {
		if !id.IsUnknown() && !id.IsNull() {
			stateMap[id.ValueString()] = true
		}
	}

	for _, id := range planIDs {
		if !stateMap[id.ValueString()] {
			idsToAdd = append(idsToAdd, id.ValueString())
		}
	}

	for _, id := range stateIDs {
		if !planMap[id.ValueString()] {
			idsToRemove = append(idsToRemove, id.ValueString())
		}
	}

	return
}

// ListIDsToModify takes a list of unique IDs from plan and state and returns the IDs to add and remove to get from the state to the plan.
// idsToAdd is the slice of IDs that are in the plan but not in the state.
// idsToRemove is the slice of IDs that are in the state but not in the plan.
// useful for resources with HostGroups, RuleGroups, etc.
func ListIDsToModify(
	ctx context.Context,
	plan, state types.List,
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

func GenerateUpdateTimestamp() basetypes.StringValue {
	return types.StringValue(time.Now().Format(time.RFC850))
}

// Addr returns the address of t.
func Addr[T any](t T) *T {
	return &t
}
