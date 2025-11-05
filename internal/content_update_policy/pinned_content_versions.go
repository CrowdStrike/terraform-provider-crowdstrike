package contentupdatepolicy

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/content_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// pinnedContentVersion holds both current and planned pinned_content_version values.
type pinnedContentVersion struct {
	state types.String
	plan  types.String
}

// categoryAssignments holds the state and planned values for pinned_content_version for all content categories.
type categoryAssignments struct {
	sensorOperations        pinnedContentVersion
	systemCritical          pinnedContentVersion
	vulnerabilityManagement pinnedContentVersion
	rapidResponse           pinnedContentVersion
}

// toMap returns a map of pinnedContentVersion where the key is the API category.
func (c categoryAssignments) toMap() map[string]pinnedContentVersion {
	return map[string]pinnedContentVersion{
		"sensor_operations": {
			c.sensorOperations.state,
			c.sensorOperations.plan,
		},
		"system_critical": {
			c.systemCritical.state,
			c.systemCritical.plan,
		},
		"vulnerability_management": {
			c.vulnerabilityManagement.state,
			c.vulnerabilityManagement.plan,
		},
		"rapid_response_al_bl_listing": {
			c.rapidResponse.state,
			c.rapidResponse.plan,
		},
	}
}

// removePinnedContentVersions checks state and plan values, and removes any pinned content versions
// that exist in state but not in plan.
func removePinnedContentVersions(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	policyID string,
	assignments categoryAssignments,
) diag.Diagnostics {
	var diags diag.Diagnostics

	tflog.Debug(ctx, "Starting removePinnedContentVersions", map[string]interface{}{
		"policyID": policyID,
	})

	var categoriesToRemove []*models.MsaspecActionParameter
	categories := assignments.toMap()

	for categoryName, category := range categories {
		isPinned := category.state.ValueString() != ""
		planPinned := category.plan.ValueString() != ""
		if isPinned && !planPinned {
			tflog.Debug(ctx, "Adding category to list of pending removals", map[string]interface{}{
				"policyID":     policyID,
				"categoryName": categoryName,
			})
			categoriesToRemove = append(categoriesToRemove, &models.MsaspecActionParameter{
				Name:  &categoryName,
				Value: &categoryName,
			})
		}
	}

	if len(categoriesToRemove) > 0 {
		tflog.Debug(ctx, "Removing pinned content versions", map[string]any{
			"policyID": policyID,
		})

		_, err := client.ContentUpdatePolicies.PerformContentUpdatePoliciesAction(
			&content_update_policies.PerformContentUpdatePoliciesActionParams{
				Context:    ctx,
				ActionName: "remove-pinned-content-version",
				Body: &models.MsaEntityActionRequestV2{
					ActionParameters: categoriesToRemove,
					Ids:              []string{policyID},
				},
			},
		)

		if err != nil {
			diags.AddError(
				"Failed to Remove Pinned Content Versions",
				fmt.Sprintf("Could not remove pinned content versions for policy %s: %s", policyID, err.Error()),
			)
			return diags
		}

		tflog.Debug(ctx, "Successfully removed pinned content versions", map[string]interface{}{
			"policyID":   policyID,
			"categories": categoriesToRemove,
		})
	}

	tflog.Debug(ctx, "Completed removePinnedContentVersions", map[string]interface{}{
		"policyID": policyID,
	})

	return diags
}

// setPinnedContentVersions checks state and plan values, and adds any pinned content versions
// that exist in plan but not in state (or are different).
func setPinnedContentVersions(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	policyID string,
	assignments categoryAssignments,
) diag.Diagnostics {
	var diags diag.Diagnostics

	tflog.Debug(ctx, "Starting setPinnedContentVersions", map[string]interface{}{
		"policyID": policyID,
	})

	var categoriesToSet []*models.MsaspecActionParameter
	categories := assignments.toMap()

	for categoryName, category := range categories {
		planPinned := category.plan.ValueString() != ""
		planVersion := category.plan.ValueString()
		stateVersion := category.state.ValueString()

		if planPinned && planVersion != stateVersion {
			tflog.Debug(ctx, "Adding category to list of pending additions", map[string]interface{}{
				"policyID":     policyID,
				"categoryName": categoryName,
				"version":      planVersion,
			})
			categoriesToSet = append(categoriesToSet, &models.MsaspecActionParameter{
				Name:  &categoryName,
				Value: &planVersion,
			})
		}
	}

	if len(categoriesToSet) > 0 {
		tflog.Debug(ctx, "Setting pinned content versions", map[string]any{
			"policyID": policyID,
		})

		_, err := client.ContentUpdatePolicies.PerformContentUpdatePoliciesAction(
			&content_update_policies.PerformContentUpdatePoliciesActionParams{
				Context:    ctx,
				ActionName: "set-pinned-content-version",
				Body: &models.MsaEntityActionRequestV2{
					ActionParameters: categoriesToSet,
					Ids:              []string{policyID},
				},
			},
		)

		if err != nil {
			diags.AddError(
				"Failed to Set Pinned Content Versions",
				fmt.Sprintf("Could not set pinned content versions for policy %s: %s", policyID, err.Error()),
			)
			return diags
		}

		tflog.Debug(ctx, "Successfully set pinned content versions", map[string]interface{}{
			"policyID":   policyID,
			"categories": categoriesToSet,
		})
	}

	tflog.Debug(ctx, "Completed setPinnedContentVersions", map[string]interface{}{
		"policyID": policyID,
	})

	return diags
}
