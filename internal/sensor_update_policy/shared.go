package sensorupdatepolicy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	hostgroups "github.com/crowdstrike/terraform-provider-crowdstrike/internal/host_groups"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// int64ToDay maps numbers used by api to a string representation of the day.
var int64ToDay = map[int64]string{
	0: "sunday",
	1: "monday",
	2: "tuesday",
	3: "wednesday",
	4: "thursday",
	5: "friday",
	6: "saturday",
}

// dayToInt64 maps a string representation of the day to the numbers used by the api.
var dayToInt64 = map[string]int64{
	"sunday":    0,
	"monday":    1,
	"tuesday":   2,
	"wednesday": 3,
	"thursday":  4,
	"friday":    5,
	"saturday":  6,
}

// timezones a slice of supported timezones for sensor update policy.
var timezones = []string{
	"Etc/GMT-2",
	"Etc/UTC",
	"Etc/GMT+7",
	"Etc/GMT+12",
	"Atlantic/Cape_Verde",
	"America/Noronha",
	"America/Sao_Paulo",
	"America/St_Johns",
	"America/Santo_Domingo",
	"America/Caracas",
	"America/New_York",
	"America/Lima",
	"America/Havana",
	"America/Mexico_City",
	"America/Phoenix",
	"America/Los_Angeles",
	"America/Anchorage",
	"Pacific/Kiritimati",
	"Pacific/Marquesas",
	"Pacific/Honolulu",
	"Pacific/Tahiti",
	"Pacific/Niue",
	"Pacific/Pago_Pago",
	"Pacific/Gambier",
	"Pacific/Pitcairn",
	"Pacific/Chatham",
	"Pacific/Auckland",
	"Pacific/Guam",
	"Pacific/Fiji",
	"Pacific/Norfolk",
	"Pacific/Galapagos",
	"Asia/Sakhalin",
	"Asia/Chita",
	"Asia/Jayapura",
	"Asia/Seoul",
	"Asia/Tokyo",
	"Asia/Kuala_Lumpur",
	"Asia/Vladivostok",
	"Asia/Shanghai",
	"Asia/Hong_Kong",
	"Asia/Makassar",
	"Asia/Manila",
	"Asia/Bangkok",
	"Asia/Jakarta",
	"Asia/Rangoon",
	"Asia/Dhaka",
	"Asia/Kathmandu",
	"Asia/Kolkata",
	"Asia/Colombo",
	"Asia/Tashkent",
	"Asia/Karachi",
	"Asia/Kabul",
	"Asia/Dubai",
	"Asia/Tehran",
	"Asia/Jerusalem",
	"Australia/Sydney",
	"Australia/Adelaide",
	"Australia/Brisbane",
	"Australia/Darwin",
	"Australia/Eucla",
	"Australia/Perth",
	"Africa/Nairobi",
	"Africa/Khartoum",
	"Africa/Cairo",
	"Africa/Johannesburg",
	"Africa/Lagos",
	"Africa/Casablanca",
	"Europe/Istanbul",
	"Europe/Moscow",
	"Europe/Paris",
	"Europe/London",
	"Europe/Lisbon",
	"Antartica/Troll",
	"MET",
}

var linuxArm64Varient = "LinuxArm64"

// policySchedule the schedule for a sensor update policy.
type policySchedule struct {
	Enabled    types.Bool   `tfsdk:"enabled"`
	Timezone   types.String `tfsdk:"timezone"`
	TimeBlocks []timeBlock  `tfsdk:"time_blocks"`
}

func (p policySchedule) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"enabled":  types.BoolType,
		"timezone": types.StringType,
		"time_blocks": types.SetType{
			ElemType: types.ObjectType{AttrTypes: timeBlock{}.AttributeTypes()},
		},
	}
}

// timeBlock a time block for a sensor update policy schedule.
type timeBlock struct {
	Days      types.Set    `tfsdk:"days"`
	StartTime types.String `tfsdk:"start_time"`
	EndTime   types.String `tfsdk:"end_time"`
}

func (t timeBlock) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"days":       types.SetType{ElemType: types.StringType},
		"start_time": types.StringType,
		"end_time":   types.StringType,
	}
}

// validTime checks if the start and end time are atleast 1 hour apart.
func validTime(startTimeStr string, endTimeStr string) (bool, error) {
	startTime, err := time.Parse("15:04", startTimeStr)
	if err != nil {
		return false, err
	}
	endTime, err := time.Parse("15:04", endTimeStr)
	if err != nil {
		return false, err
	}

	duration := endTime.Sub(startTime)

	return duration >= time.Hour, nil
}

// createUpdateSchedules handles the logic to create a models.PolicySensorUpdateSchedule.
func createUpdateSchedules(
	ctx context.Context,
	timeBlocks []timeBlock,
) ([]*models.PolicySensorUpdateSchedule, diag.Diagnostics) {
	updateSchedules := []*models.PolicySensorUpdateSchedule{}
	diags := diag.Diagnostics{}

	for _, b := range timeBlocks {
		bCopy := b
		days := []string{}
		daysInt64 := []int64{}

		diags = bCopy.Days.ElementsAs(ctx, &days, false)

		if diags.HasError() {
			return updateSchedules, diags
		}

		for _, d := range days {
			dCopy := d
			daysInt64 = append(daysInt64, dayToInt64[strings.ToLower(dCopy)])
		}

		updateSchedules = append(updateSchedules, &models.PolicySensorUpdateSchedule{
			Start: bCopy.StartTime.ValueStringPointer(),
			End:   bCopy.EndTime.ValueStringPointer(),
			Days:  daysInt64,
		})
	}

	return updateSchedules, diags
}

// getSensorUpdatePolicy gets a sensor update policy based on ID.
func getSensorUpdatePolicy(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	policyID string,
) (*models.SensorUpdatePolicyV2, diag.Diagnostics) {
	var diags diag.Diagnostics

	res, err := client.SensorUpdatePolicies.GetSensorUpdatePoliciesV2(
		&sensor_update_policies.GetSensorUpdatePoliciesV2Params{
			Context: ctx,
			Ids:     []string{policyID},
		},
	)

	if _, ok := err.(*sensor_update_policies.GetSensorUpdatePoliciesV2NotFound); ok {
		diags.Append(
			newNotFoundError(fmt.Sprintf("No sensor update policy with id: %s found.", policyID)),
		)
		return nil, diags
	}

	if err != nil {
		diags.AddError(
			"Error reading CrowdStrike sensor update policy",
			fmt.Sprintf(
				"Could not read CrowdStrike sensor update policy (%s): %s",
				policyID,
				err.Error(),
			),
		)
		return nil, diags
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
		diags.AddError(
			"Error reading CrowdStrike sensor update policy",
			"API return successful status code, but no resources were returned.",
		)
		return nil, diags
	}

	policy := res.Payload.Resources[0]

	return policy, diags
}

// updateHostGroups will remove or add a slice of host groups
// to a sensor update policy.
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

	res, err := client.SensorUpdatePolicies.PerformSensorUpdatePoliciesAction(
		&sensor_update_policies.PerformSensorUpdatePoliciesActionParams{
			Context:    ctx,
			ActionName: action.String(),
			Body: &models.MsaEntityActionRequestV2{
				ActionParameters: actionParams,
				Ids:              []string{policyID},
			},
		},
	)

	if err != nil {
		diags.AddError("Error updating sensor update policy host groups", fmt.Sprintf(
			"Error %s host groups (%s) to sensor update policy (%s): %s",
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
					"Error updating sensor update policy host groups",
					fmt.Sprintf(
						"Error %s host groups (%s) to sensor update policy (%s): %s",
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
					"Error updating sensor update policy host groups",
					fmt.Sprintf(
						"Error %s host groups (%s) to sensor update policy (%s): %s",
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
				"Error updating sensor update policy host groups",
				fmt.Sprintf(
					"Error %s host groups (%s) to sensor update policy (%s): %s",
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
	policyID string,
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

	diags.Append(updateHostGroups(ctx, client, hostgroups.AddHostGroup, groupsToAdd, policyID)...)
	diags.Append(
		updateHostGroups(ctx, client, hostgroups.RemoveHostGroup, groupsToRemove, policyID)...)

	return diags
}
