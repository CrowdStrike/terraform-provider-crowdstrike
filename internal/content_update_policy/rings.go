package contentupdatepolicy

import (
	"context"
	"fmt"
	"strconv"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// ringAssignmentModel represents a content category ring assignment.
type ringAssignmentModel struct {
	RingAssignment       types.String `tfsdk:"ring_assignment"`
	DelayHours           types.Int64  `tfsdk:"delay_hours"`
	PinnedContentVersion types.String `tfsdk:"pinned_content_version"`
}

// AttributeTypes returns the attribute types for the ring assignment model.
func (r ringAssignmentModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"ring_assignment":        types.StringType,
		"delay_hours":            types.Int64Type,
		"pinned_content_version": types.StringType,
	}
}

// wrap transforms Go values to their terraform wrapped values.
func (r *ringAssignmentModel) wrap(
	setting *models.ContentUpdateRingAssignmentSettingsV1,
) {
	isFreshModel := r.DelayHours.IsNull() && r.RingAssignment.IsNull() && r.PinnedContentVersion.IsNull()
	r.RingAssignment = types.StringPointerValue(setting.RingAssignment)

	if *setting.RingAssignment == "ga" {
		delayHours := int64(0)
		if setting.DelayHours != nil {
			if delayStr := *setting.DelayHours; delayStr != "" {
				if delay, err := strconv.ParseInt(delayStr, 10, 64); err == nil {
					delayHours = delay
				}
			}
		}

		if isFreshModel {
			r.DelayHours = types.Int64Value(delayHours)
		} else {
			r.DelayHours = utils.SetInt64FromAPIIfNotZero(r.DelayHours, delayHours)
		}
	} else {
		r.DelayHours = types.Int64Null()
	}

	r.PinnedContentVersion = utils.OptionalString(setting.PinnedContentVersion)
}

// Valid ring assignments.
var validRingAssignments = []string{
	"ga",    // general availability
	"ea",    // early access
	"pause", // pause updates
}

// Valid ring assignments for system_critical (no pause allowed).
var validSystemCriticalRingAssignments = []string{
	"ga", // general availability
	"ea", // early access
}

// ringAssignmentValidators returns common validators for ring assignment attributes.
func ringAssignmentValidators() map[string][]validator.String {
	return map[string][]validator.String{
		"ring_assignment": {stringvalidator.OneOf(validRingAssignments...)},
		"system_critical": {stringvalidator.OneOf(validSystemCriticalRingAssignments...)},
	}
}

// buildRingAssignmentSettings converts content update policy settings to API model.
func buildRingAssignmentSettings(
	ctx context.Context,
	sensorOperations ringAssignmentModel,
	systemCritical ringAssignmentModel,
	vulnerabilityManagement ringAssignmentModel,
	rapidResponse ringAssignmentModel,
) []*models.ContentUpdateRingAssignmentSettingsReqV1 {
	tflog.Debug(ctx, "Starting buildRingAssignmentSettings", map[string]interface{}{
		"sensorOperations_valid":        !sensorOperations.RingAssignment.IsNull(),
		"systemCritical_valid":          !systemCritical.RingAssignment.IsNull(),
		"vulnerabilityManagement_valid": !vulnerabilityManagement.RingAssignment.IsNull(),
		"rapidResponse_valid":           !rapidResponse.RingAssignment.IsNull(),
	})

	ringAssignmentSettings := make([]*models.ContentUpdateRingAssignmentSettingsReqV1, 0, 4)

	if !sensorOperations.RingAssignment.IsNull() {
		delayHours := int64(0)
		if !sensorOperations.DelayHours.IsNull() {
			delayHours = sensorOperations.DelayHours.ValueInt64()
		}
		delayHoursStr := fmt.Sprintf("%d", delayHours)
		categoryID := "sensor_operations"
		setting := &models.ContentUpdateRingAssignmentSettingsReqV1{
			ID:             &categoryID,
			RingAssignment: sensorOperations.RingAssignment.ValueStringPointer(),
			DelayHours:     &delayHoursStr,
		}
		tflog.Debug(ctx, "Built sensor_operations ring assignment", map[string]interface{}{
			"categoryID":     categoryID,
			"ringAssignment": sensorOperations.RingAssignment.ValueString(),
			"delayHours":     delayHours,
		})
		ringAssignmentSettings = append(ringAssignmentSettings, setting)
	}

	if !systemCritical.RingAssignment.IsNull() {
		delayHours := int64(0)
		if !systemCritical.DelayHours.IsNull() {
			delayHours = systemCritical.DelayHours.ValueInt64()
		}
		delayHoursStr := fmt.Sprintf("%d", delayHours)
		categoryID := "system_critical"
		setting := &models.ContentUpdateRingAssignmentSettingsReqV1{
			ID:             &categoryID,
			RingAssignment: systemCritical.RingAssignment.ValueStringPointer(),
			DelayHours:     &delayHoursStr,
		}
		tflog.Debug(ctx, "Built system_critical ring assignment", map[string]interface{}{
			"categoryID":     categoryID,
			"ringAssignment": systemCritical.RingAssignment.ValueString(),
			"delayHours":     delayHours,
		})
		ringAssignmentSettings = append(ringAssignmentSettings, setting)
	}

	if !vulnerabilityManagement.RingAssignment.IsNull() {
		delayHours := int64(0)
		if !vulnerabilityManagement.DelayHours.IsNull() {
			delayHours = vulnerabilityManagement.DelayHours.ValueInt64()
		}
		delayHoursStr := fmt.Sprintf("%d", delayHours)
		categoryID := "vulnerability_management"
		setting := &models.ContentUpdateRingAssignmentSettingsReqV1{
			ID:             &categoryID,
			RingAssignment: vulnerabilityManagement.RingAssignment.ValueStringPointer(),
			DelayHours:     &delayHoursStr,
		}
		tflog.Debug(ctx, "Built vulnerability_management ring assignment", map[string]interface{}{
			"categoryID":     categoryID,
			"ringAssignment": vulnerabilityManagement.RingAssignment.ValueString(),
			"delayHours":     delayHours,
		})
		ringAssignmentSettings = append(ringAssignmentSettings, setting)
	}

	if !rapidResponse.RingAssignment.IsNull() {
		delayHours := int64(0)
		if !rapidResponse.DelayHours.IsNull() {
			delayHours = rapidResponse.DelayHours.ValueInt64()
		}
		delayHoursStr := fmt.Sprintf("%d", delayHours)
		categoryID := "rapid_response_al_bl_listing"
		setting := &models.ContentUpdateRingAssignmentSettingsReqV1{
			ID:             &categoryID,
			RingAssignment: rapidResponse.RingAssignment.ValueStringPointer(),
			DelayHours:     &delayHoursStr,
		}
		tflog.Debug(ctx, "Built rapid_response ring assignment", map[string]interface{}{
			"categoryID":     categoryID,
			"ringAssignment": rapidResponse.RingAssignment.ValueString(),
			"delayHours":     delayHours,
		})
		ringAssignmentSettings = append(ringAssignmentSettings, setting)
	}

	tflog.Debug(ctx, "Completed buildRingAssignmentSettings", map[string]interface{}{
		"total_settings": len(ringAssignmentSettings),
	})

	return ringAssignmentSettings
}
