package hostgroups

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/host_group"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
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
// Groups with a nil or empty ID are skipped; in Flight Control setups the API can return
// placeholder groups with an empty ID for host groups assigned in a child CID.
// The returned []types.String will never be null.
func convertHostGroupsToIDs(groups []*models.HostGroupsHostGroupV1) []types.String {
	groupIDs := make([]types.String, 0, len(groups))
	for _, group := range groups {
		if group != nil && group.ID != nil && *group.ID != "" {
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

// lookupHostGroup resolves a single host group by ID or by name. Exactly one of
// id or name must be non-empty; callers rely on schema validators to enforce that.
func lookupHostGroup(
	ctx context.Context,
	falconClient *client.CrowdStrikeAPISpecification,
	id string,
	name string,
) (*models.HostGroupsHostGroupV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	if id != "" {
		tflog.Debug(ctx, "[datasource] Looking up host group by ID", map[string]any{
			"id": id,
		})

		res, err := falconClient.HostGroup.GetHostGroups(
			&host_group.GetHostGroupsParams{
				Context: ctx,
				Ids:     []string{id},
			},
		)
		notFoundDetail := fmt.Sprintf("No host group found with ID %q.", id)
		if err != nil {
			diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, dataSourceApiScopes, tferrors.WithNotFoundDetail(notFoundDetail)))
			return nil, diags
		}

		if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 ||
			res.Payload.Resources[0] == nil {
			diags.Append(tferrors.NewNotFoundError(notFoundDetail))
			return nil, diags
		}

		return res.Payload.Resources[0], diags
	}

	tflog.Debug(ctx, "[datasource] Looking up host group by name", map[string]any{
		"name": name,
	})

	filter := fmt.Sprintf("name:'%s'", strings.ToLower(name))
	res, err := falconClient.HostGroup.QueryCombinedHostGroups(
		&host_group.QueryCombinedHostGroupsParams{
			Context: ctx,
			Filter:  &filter,
		},
	)
	notFoundDetail := fmt.Sprintf("No host group found with name %q.", name)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, dataSourceApiScopes, tferrors.WithNotFoundDetail(notFoundDetail)))
		return nil, diags
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
		diags.Append(tferrors.NewNotFoundError(notFoundDetail))
		return nil, diags
	}

	// The FQL name filter may return partial matches, so filter
	// client-side for an exact (case-insensitive) name match.
	var matched []*models.HostGroupsHostGroupV1
	for _, g := range res.Payload.Resources {
		if g != nil && g.Name != nil && strings.EqualFold(*g.Name, name) {
			matched = append(matched, g)
		}
	}

	if len(matched) == 0 {
		diags.Append(tferrors.NewNotFoundError(
			fmt.Sprintf("No host group found with exact name %q.", name),
		))
		return nil, diags
	}

	if len(matched) > 1 {
		diags.AddError(
			"Multiple host groups found",
			fmt.Sprintf("Found %d host groups with name %q. Host group names are expected to be unique.", len(matched), name),
		)
		return nil, diags
	}

	return matched[0], diags
}
