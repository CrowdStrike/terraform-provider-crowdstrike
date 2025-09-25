package contentupdatepolicy

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/content_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
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
		diags.AddError(
			"Content update policy not found",
			fmt.Sprintf("Content update policy with ID %s not found", policyID),
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

// setPinnedContentVersion sets a pinned content version for a specific category.
func setPinnedContentVersion(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	policyID, categoryName, version string,
) error {
	tflog.Debug(ctx, "Starting setPinnedContentVersion", map[string]interface{}{
		"policyID":     policyID,
		"categoryName": categoryName,
		"version":      version,
	})

	actionParams := []*models.MsaspecActionParameter{
		{
			Name:  &categoryName,
			Value: &version,
		},
	}

	tflog.Debug(ctx, "Constructed action parameters", map[string]interface{}{
		"policyID":     policyID,
		"categoryName": categoryName,
		"version":      version,
		"actionParams": len(actionParams),
	})

	_, err := client.ContentUpdatePolicies.PerformContentUpdatePoliciesAction(
		&content_update_policies.PerformContentUpdatePoliciesActionParams{
			Context:    ctx,
			ActionName: "set-pinned-content-version",
			Body: &models.MsaEntityActionRequestV2{
				ActionParameters: actionParams,
				Ids:              []string{policyID},
			},
		},
	)

	if err != nil {
		tflog.Error(ctx, "Failed to set pinned content version", map[string]interface{}{
			"policyID":     policyID,
			"categoryName": categoryName,
			"version":      version,
			"error":        err.Error(),
		})
	} else {
		tflog.Debug(ctx, "Successfully set pinned content version", map[string]interface{}{
			"policyID":     policyID,
			"categoryName": categoryName,
			"version":      version,
		})
	}

	return err
}

// removePinnedContentVersion removes a pinned content version for a specific category.
func removePinnedContentVersion(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	policyID, categoryName string,
) error {
	tflog.Debug(ctx, "Starting removePinnedContentVersion", map[string]interface{}{
		"policyID":     policyID,
		"categoryName": categoryName,
	})

	// For remove action, we only need the category name as the parameter value
	actionParams := []*models.MsaspecActionParameter{
		{
			Name:  &categoryName,
			Value: &categoryName,
		},
	}

	tflog.Debug(ctx, "Constructed action parameters for removal", map[string]interface{}{
		"policyID":     policyID,
		"categoryName": categoryName,
		"actionParams": len(actionParams),
	})

	_, err := client.ContentUpdatePolicies.PerformContentUpdatePoliciesAction(
		&content_update_policies.PerformContentUpdatePoliciesActionParams{
			Context:    ctx,
			ActionName: "remove-pinned-content-version",
			Body: &models.MsaEntityActionRequestV2{
				ActionParameters: actionParams,
				Ids:              []string{policyID},
			},
		},
	)

	if err != nil {
		tflog.Error(ctx, "Failed to remove pinned content version", map[string]interface{}{
			"policyID":     policyID,
			"categoryName": categoryName,
			"error":        err.Error(),
		})
	} else {
		tflog.Debug(ctx, "Successfully removed pinned content version", map[string]interface{}{
			"policyID":     policyID,
			"categoryName": categoryName,
		})
	}

	return err
}

// managePinnedContentVersions handles setting and removing pinned content versions for a policy.
func managePinnedContentVersions(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	policyID string,
	currentSensorOps, currentSystemCrit, currentVulnMgmt, currentRapidResp *ringAssignmentModel,
	plannedSensorOps, plannedSystemCrit, plannedVulnMgmt, plannedRapidResp ringAssignmentModel,
) error {
	tflog.Debug(ctx, "Starting managePinnedContentVersions", map[string]interface{}{
		"policyID":                policyID,
		"currentSensorOps_nil":    currentSensorOps == nil,
		"plannedSensorOps_valid":  !plannedSensorOps.RingAssignment.IsNull(),
		"plannedSystemCrit_valid": !plannedSystemCrit.RingAssignment.IsNull(),
		"plannedVulnMgmt_valid":   !plannedVulnMgmt.RingAssignment.IsNull(),
		"plannedRapidResp_valid":  !plannedRapidResp.RingAssignment.IsNull(),
	})

	categories := map[string]struct {
		current *ringAssignmentModel
		planned ringAssignmentModel
		apiName string
	}{
		"sensor_operations": {
			currentSensorOps,
			plannedSensorOps,
			"sensor_operations",
		},
		"system_critical": {
			currentSystemCrit,
			plannedSystemCrit,
			"system_critical",
		},
		"vulnerability_management": {
			currentVulnMgmt,
			plannedVulnMgmt,
			"vulnerability_management",
		},
		"rapid_response": {
			currentRapidResp,
			plannedRapidResp,
			"rapid_response_al_bl_listing",
		},
	}

	var processedCount int
	var skippedCount int
	var changedCount int

	for categoryName, category := range categories {
		if category.planned.RingAssignment.IsNull() {
			tflog.Debug(ctx, "Skipping category - planned settings is invalid", map[string]interface{}{
				"policyID":     policyID,
				"categoryName": categoryName,
			})
			skippedCount++
			continue
		}

		var currentVersion, plannedVersion string

		if category.current != nil && !category.current.PinnedContentVersion.IsNull() {
			currentVersion = category.current.PinnedContentVersion.ValueString()
		}

		if !category.planned.PinnedContentVersion.IsNull() {
			plannedVersion = category.planned.PinnedContentVersion.ValueString()
		}

		tflog.Debug(ctx, "Comparing pinned content versions", map[string]interface{}{
			"policyID":       policyID,
			"categoryName":   categoryName,
			"apiName":        category.apiName,
			"currentVersion": currentVersion,
			"plannedVersion": plannedVersion,
			"versionsEqual":  currentVersion == plannedVersion,
		})

		// If versions are different, update accordingly
		if currentVersion != plannedVersion {
			changedCount++
			if plannedVersion != "" {
				// Set new pinned version
				tflog.Debug(ctx, "Setting new pinned version", map[string]interface{}{
					"policyID":        policyID,
					"categoryName":    categoryName,
					"apiName":         category.apiName,
					"newVersion":      plannedVersion,
					"previousVersion": currentVersion,
				})
				if err := setPinnedContentVersion(ctx, client, policyID, category.apiName, plannedVersion); err != nil {
					tflog.Error(ctx, "Failed to set pinned content version", map[string]interface{}{
						"policyID":     policyID,
						"categoryName": categoryName,
						"apiName":      category.apiName,
						"version":      plannedVersion,
						"error":        err.Error(),
					})
					return fmt.Errorf(
						"failed to set pinned content version for %s: %w",
						category.apiName,
						err,
					)
				}
			} else if currentVersion != "" {
				// Remove pinned version
				tflog.Debug(ctx, "Removing pinned version", map[string]interface{}{
					"policyID":       policyID,
					"categoryName":   categoryName,
					"apiName":        category.apiName,
					"removedVersion": currentVersion,
				})
				if err := removePinnedContentVersion(ctx, client, policyID, category.apiName); err != nil {
					tflog.Error(ctx, "Failed to remove pinned content version", map[string]interface{}{
						"policyID":     policyID,
						"categoryName": categoryName,
						"apiName":      category.apiName,
						"error":        err.Error(),
					})
					return fmt.Errorf("failed to remove pinned content version for %s: %w", category.apiName, err)
				}
			}
		} else {
			tflog.Debug(ctx, "No change needed for pinned content version", map[string]interface{}{
				"policyID":     policyID,
				"categoryName": categoryName,
				"version":      currentVersion,
			})
		}
		processedCount++
	}

	tflog.Debug(ctx, "Completed managePinnedContentVersions", map[string]interface{}{
		"policyID":        policyID,
		"processedCount":  processedCount,
		"skippedCount":    skippedCount,
		"changedCount":    changedCount,
		"totalCategories": len(categories),
	})

	return nil
}
