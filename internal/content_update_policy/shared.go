package contentupdatepolicy

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/content_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	hostgroups "github.com/crowdstrike/terraform-provider-crowdstrike/internal/host_groups"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Valid delay hours for GA ring.
var validDelayHours = []int64{0, 1, 2, 4, 8, 12, 24, 48, 72}

// delayHoursValidators returns common validators for delay hours attributes.
func delayHoursValidators() []validator.Int64 {
	return []validator.Int64{
		int64validator.OneOf(validDelayHours...),
	}
}

// getContentUpdatePolicy retrieves a content update policy by ID.
func getContentUpdatePolicy(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	policyID string,
) (*models.ContentUpdatePolicyV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	tflog.Debug(ctx, "Starting getContentUpdatePolicy", map[string]interface{}{
		"policyID": policyID,
	})

	res, err := client.ContentUpdatePolicies.GetContentUpdatePolicies(
		&content_update_policies.GetContentUpdatePoliciesParams{
			Context: ctx,
			Ids:     []string{policyID},
		},
	)
	if err != nil {
		if _, ok := err.(*content_update_policies.GetContentUpdatePoliciesNotFound); ok {
			tflog.Warn(ctx, "Content update policy not found", map[string]interface{}{
				"policyID": policyID,
			})
			diags.Append(
				tferrors.NewNotFoundError(
					fmt.Sprintf("No content update policy with id: %s found.", policyID),
				),
			)
			return nil, diags
		}
		tflog.Error(ctx, "API call failed in getContentUpdatePolicy", map[string]interface{}{
			"policyID": policyID,
			"error":    err.Error(),
		})
		diags.AddError(
			"Error reading content update policy",
			"Could not read content update policy: "+policyID+": "+err.Error(),
		)
		return nil, diags
	}

	tflog.Debug(ctx, "API call successful", map[string]interface{}{
		"policyID":        policyID,
		"resources_count": len(res.Payload.Resources),
	})

	if len(res.Payload.Resources) == 0 {
		tflog.Warn(ctx, "Content update policy not found", map[string]interface{}{
			"policyID": policyID,
		})
		diags.Append(
			tferrors.NewNotFoundError(
				fmt.Sprintf("No content update policy with id: %s found.", policyID),
			),
		)
		return nil, diags
	}

	policy := res.Payload.Resources[0]
	tflog.Debug(ctx, "Successfully retrieved content update policy", map[string]interface{}{
		"policyID":          policyID,
		"policy_name":       *policy.Name,
		"enabled":           *policy.Enabled,
		"host_groups_count": len(policy.Groups),
	})

	return policy, diags
}

// updatePolicyEnabledState enables or disables a content update policy.
func updatePolicyEnabledState(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	policyID string,
	enabled bool,
) error {
	actionName := "disable"
	if enabled {
		actionName = "enable"
	}

	tflog.Debug(ctx, "Starting updatePolicyEnabledState", map[string]interface{}{
		"policyID":   policyID,
		"enabled":    enabled,
		"actionName": actionName,
	})

	_, err := client.ContentUpdatePolicies.PerformContentUpdatePoliciesAction(
		&content_update_policies.PerformContentUpdatePoliciesActionParams{
			Context:    ctx,
			ActionName: actionName,
			Body: &models.MsaEntityActionRequestV2{
				Ids: []string{policyID},
			},
		},
	)

	if err != nil {
		tflog.Error(ctx, "Failed to update policy enabled state", map[string]interface{}{
			"policyID":   policyID,
			"enabled":    enabled,
			"actionName": actionName,
			"error":      err.Error(),
		})
	} else {
		tflog.Debug(ctx, "Successfully updated policy enabled state", map[string]interface{}{
			"policyID":   policyID,
			"enabled":    enabled,
			"actionName": actionName,
		})
	}

	return err
}

// updateHostGroups adds or removes host groups from a content update policy.
func updateHostGroups(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	action hostgroups.HostGroupAction,
	hostGroupIDs []string,
	policyID string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if len(hostGroupIDs) == 0 {
		return diags
	}

	var actionParams []*models.MsaspecActionParameter

	actionMsg := "adding"
	if action == hostgroups.RemoveHostGroup {
		actionMsg = "removing"
	}
	name := "group_id"

	for _, g := range hostGroupIDs {
		gCopy := g
		actionParam := &models.MsaspecActionParameter{
			Name:  &name,
			Value: &gCopy,
		}

		actionParams = append(actionParams, actionParam)
	}

	res, err := client.ContentUpdatePolicies.PerformContentUpdatePoliciesAction(
		&content_update_policies.PerformContentUpdatePoliciesActionParams{
			Context:    ctx,
			ActionName: action.String(),
			Body: &models.MsaEntityActionRequestV2{
				ActionParameters: actionParams,
				Ids:              []string{policyID},
			},
		},
	)
	if err != nil {
		diags.AddError("Error updating content update policy host groups", fmt.Sprintf(
			"Error %s host groups (%s) to content update policy (%s): %s",
			actionMsg,
			strings.Join(hostGroupIDs, ", "),
			policyID,
			err.Error(),
		))

		return diags
	}

	returnedHostGroups := make(map[string]bool)

	if res != nil && res.Payload != nil {
		for _, r := range res.Payload.Resources {
			groups := r.Groups

			for _, group := range groups {
				returnedHostGroups[*group.ID] = true
			}
		}
	}

	if action == hostgroups.RemoveHostGroup {
		for _, group := range hostGroupIDs {
			_, ok := returnedHostGroups[group]
			if ok {
				diags.AddError(
					"Error updating content update policy host groups",
					fmt.Sprintf(
						"Error %s host groups (%s) to content update policy (%s): %s",
						actionMsg,
						group,
						policyID,
						"Remove failed",
					),
				)
			}
		}
	}

	if action == hostgroups.AddHostGroup {
		for _, group := range hostGroupIDs {
			_, ok := returnedHostGroups[group]
			if !ok {
				diags.AddError(
					"Error updating content update policy host groups",
					fmt.Sprintf(
						"Error %s host groups (%s) to content update policy (%s): %s",
						actionMsg,
						group,
						policyID,
						"Adding failed, ensure the host group is valid.",
					),
				)
			}
		}
	}

	if res != nil && res.Payload != nil {
		for _, err := range res.Payload.Errors {
			diags.AddError(
				"Error updating content update policy host groups",
				fmt.Sprintf(
					"Error %s host groups (%s) to content update policy (%s): %s",
					actionMsg,
					err.ID,
					policyID,
					err.String(),
				),
			)
		}
	}

	return diags
}

// syncHostGroups will sync the host groups from the resource model to the api.
func syncHostGroups(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	planGroups, stateGroups types.Set,
	id string,
) diag.Diagnostics {
	var diags diag.Diagnostics
	groupsToAdd, groupsToRemove, diags := utils.SetIDsToModify(
		ctx,
		planGroups,
		stateGroups,
	)
	diags.Append(diags...)
	if diags.HasError() {
		return diags
	}

	diags.Append(updateHostGroups(ctx, client, hostgroups.AddHostGroup, groupsToAdd, id)...)
	diags.Append(updateHostGroups(ctx, client, hostgroups.RemoveHostGroup, groupsToRemove, id)...)

	return diags
}
