package contentupdatepolicy

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// validateContentUpdatePolicyModifyPlan performs plan-time validation to ensure ring assignment
// and delay_hours changes don't conflict with pinned content versions across all categories.
func validateContentUpdatePolicyModifyPlan(
	ctx context.Context,
	currentSensorOps, currentSystemCrit, currentVulnMgmt, currentRapidResp ringAssignmentModel,
	plannedSensorOps, plannedSystemCrit, plannedVulnMgmt, plannedRapidResp ringAssignmentModel,
) diag.Diagnostics {
	var diags diag.Diagnostics

	tflog.Debug(ctx, "Starting validateContentUpdatePolicyModifyPlan", map[string]interface{}{
		"currentSensorOps_valid": !currentSensorOps.RingAssignment.IsNull(),
		"plannedSensorOps_valid": !plannedSensorOps.RingAssignment.IsNull(),
	})

	tflog.Debug(ctx, "Current settings state", map[string]interface{}{
		"sensorOperations_valid":        !currentSensorOps.RingAssignment.IsNull(),
		"systemCritical_valid":          !currentSystemCrit.RingAssignment.IsNull(),
		"vulnerabilityManagement_valid": !currentVulnMgmt.RingAssignment.IsNull(),
		"rapidResponse_valid":           !currentRapidResp.RingAssignment.IsNull(),
	})

	tflog.Debug(ctx, "Planned settings state", map[string]interface{}{
		"sensorOperations_valid":        !plannedSensorOps.RingAssignment.IsNull(),
		"systemCritical_valid":          !plannedSystemCrit.RingAssignment.IsNull(),
		"vulnerabilityManagement_valid": !plannedVulnMgmt.RingAssignment.IsNull(),
		"rapidResponse_valid":           !plannedRapidResp.RingAssignment.IsNull(),
	})

	diags.Append(validateRingAssignmentWithPinnedVersion(
		ctx,
		"sensor_operations",
		currentSensorOps,
		plannedSensorOps,
		path.Root("sensor_operations"),
	)...)

	diags.Append(validateRingAssignmentWithPinnedVersion(
		ctx,
		"system_critical",
		currentSystemCrit,
		plannedSystemCrit,
		path.Root("system_critical"),
	)...)

	diags.Append(validateRingAssignmentWithPinnedVersion(
		ctx,
		"vulnerability_management",
		currentVulnMgmt,
		plannedVulnMgmt,
		path.Root("vulnerability_management"),
	)...)

	diags.Append(validateRingAssignmentWithPinnedVersion(
		ctx,
		"rapid_response",
		currentRapidResp,
		plannedRapidResp,
		path.Root("rapid_response"),
	)...)

	tflog.Debug(ctx, "Completed validateContentUpdatePolicyModifyPlan", map[string]interface{}{
		"total_errors": len(diags.Errors()),
	})

	return diags
}

// Validate ring assignment and delay_hours changes against pinned content versions.
func validateRingAssignmentWithPinnedVersion(
	ctx context.Context,
	categoryName string,
	currentSettings ringAssignmentModel,
	plannedSettings ringAssignmentModel,
	attrPath path.Path,
) diag.Diagnostics {
	var diags diag.Diagnostics

	tflog.Debug(ctx, "Validating ring assignment with pinned version", map[string]interface{}{
		"category":              categoryName,
		"currentSettings_valid": !currentSettings.RingAssignment.IsNull(),
		"plannedSettings_valid": !plannedSettings.RingAssignment.IsNull(),
	})

	if currentSettings.RingAssignment.IsNull() || plannedSettings.RingAssignment.IsNull() {
		tflog.Debug(ctx, "Skipping validation - one or both settings are invalid", map[string]interface{}{
			"category": categoryName,
		})
		return diags
	}

	tflog.Debug(ctx, "Current and planned settings state", map[string]interface{}{
		"category":                               categoryName,
		"current_ring_assignment_null":           currentSettings.RingAssignment.IsNull(),
		"current_ring_assignment_unknown":        currentSettings.RingAssignment.IsUnknown(),
		"current_delay_hours_null":               currentSettings.DelayHours.IsNull(),
		"current_delay_hours_unknown":            currentSettings.DelayHours.IsUnknown(),
		"current_pinned_content_version_null":    currentSettings.PinnedContentVersion.IsNull(),
		"current_pinned_content_version_unknown": currentSettings.PinnedContentVersion.IsUnknown(),
		"planned_ring_assignment_null":           plannedSettings.RingAssignment.IsNull(),
		"planned_ring_assignment_unknown":        plannedSettings.RingAssignment.IsUnknown(),
		"planned_delay_hours_null":               plannedSettings.DelayHours.IsNull(),
		"planned_delay_hours_unknown":            plannedSettings.DelayHours.IsUnknown(),
		"planned_pinned_content_version_null":    plannedSettings.PinnedContentVersion.IsNull(),
		"planned_pinned_content_version_unknown": plannedSettings.PinnedContentVersion.IsUnknown(),
	})

	// Skip validation if pinned content version is unknown - we can't validate against an unknown value
	if plannedSettings.PinnedContentVersion.IsUnknown() {
		tflog.Debug(ctx, "Skipping validation - pinned content version is unknown", map[string]interface{}{
			"category": categoryName,
		})
		return diags
	}

	// Check if there's a pinned version that would conflict with changes
	hasPinnedVersion := !plannedSettings.PinnedContentVersion.IsNull() &&
		plannedSettings.PinnedContentVersion.ValueString() != ""

	tflog.Debug(ctx, "Pinned version check", map[string]interface{}{
		"category":           categoryName,
		"hasPinnedVersion":   hasPinnedVersion,
		"pinnedVersionValue": plannedSettings.PinnedContentVersion.ValueString(),
	})

	if !hasPinnedVersion {
		tflog.Debug(ctx, "No pinned version, no conflict possible", map[string]interface{}{
			"category": categoryName,
		})
		return diags // No pinned version, no conflict possible
	}

	// Check ring assignment changes
	if !plannedSettings.RingAssignment.IsUnknown() &&
		currentSettings.RingAssignment.ValueString() != plannedSettings.RingAssignment.ValueString() {
		tflog.Error(ctx, "Ring assignment change blocked by pinned version", map[string]interface{}{
			"category":               categoryName,
			"current_ring":           currentSettings.RingAssignment.ValueString(),
			"planned_ring":           plannedSettings.RingAssignment.ValueString(),
			"pinned_content_version": plannedSettings.PinnedContentVersion.ValueString(),
		})
		diags.AddAttributeError(
			attrPath,
			"Cannot change ring assignment with pinned content version",
			fmt.Sprintf(
				"Cannot change ring_assignment for %s from '%s' to '%s' while a pinned_content_version is set. "+
					"To change ring assignments, remove the pinned_content_version.",
				categoryName,
				currentSettings.RingAssignment.ValueString(),
				plannedSettings.RingAssignment.ValueString(),
			),
		)
	}

	// Check delay hours changes
	if !currentSettings.DelayHours.IsUnknown() && !plannedSettings.DelayHours.IsUnknown() {
		currentDelayHours := int64(0)
		plannedDelayHours := int64(0)

		if !currentSettings.DelayHours.IsNull() {
			currentDelayHours = currentSettings.DelayHours.ValueInt64()
		}
		if !plannedSettings.DelayHours.IsNull() {
			plannedDelayHours = plannedSettings.DelayHours.ValueInt64()
		}

		tflog.Debug(ctx, "Delay hours comparison", map[string]interface{}{
			"category":            categoryName,
			"current_delay_hours": currentDelayHours,
			"planned_delay_hours": plannedDelayHours,
		})

		if currentDelayHours != plannedDelayHours {
			tflog.Error(ctx, "Delay hours change blocked by pinned version", map[string]interface{}{
				"category":               categoryName,
				"current_delay_hours":    currentDelayHours,
				"planned_delay_hours":    plannedDelayHours,
				"pinned_content_version": plannedSettings.PinnedContentVersion.ValueString(),
			})
			diags.AddAttributeError(
				attrPath,
				"Cannot change delay hours with pinned content version",
				fmt.Sprintf(
					"Cannot change delay_hours for %s from %v to %v while a pinned_content_version is set. "+
						"To change delay hours, remove the pinned_content_version.",
					categoryName,
					currentSettings.DelayHours.String(),
					plannedSettings.DelayHours.String(),
				),
			)
		}
	}

	return diags
}
