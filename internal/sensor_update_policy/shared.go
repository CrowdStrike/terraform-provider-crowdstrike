package sensorupdatepolicy

import (
	"context"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/models"
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

// timeBlock a time block for a sensor update policy schedule.
type timeBlock struct {
	Days      types.Set    `tfsdk:"days"`
	StartTime types.String `tfsdk:"start_time"`
	EndTime   types.String `tfsdk:"end_time"`
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
