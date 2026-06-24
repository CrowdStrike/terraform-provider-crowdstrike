package itautomation

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	fwtypes "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func TestFlattenScheduleAllowsMissingStartTime(t *testing.T) {
	t.Parallel()

	frequency := frequencyDaily
	interval := int32(0)
	got, diags := flattenSchedule(context.Background(), &models.FalconforitapiSchedule{
		Frequency: &frequency,
		Interval:  &interval,
		Time:      "09:00",
		Timezone:  "+0000",
	})
	if diags.HasError() {
		t.Fatalf("flattenSchedule returned diagnostics: %v", diags)
	}

	var schedule scheduleModel
	diags = got.As(context.Background(), &schedule, basetypes.ObjectAsOptions{})
	if diags.HasError() {
		t.Fatalf("converting flattened schedule returned diagnostics: %v", diags)
	}
	if !schedule.StartTime.IsNull() {
		t.Fatalf("expected start_time to be null, got %q", schedule.StartTime.ValueString())
	}
}

func TestBuildScheduleFromPlanAllowsMissingStartTime(t *testing.T) {
	t.Parallel()

	schedule, diags := types.ObjectValueFrom(
		context.Background(),
		scheduledTaskScheduleAttrTypes(),
		scheduleModel{
			Frequency:  types.StringValue(frequencyDaily),
			StartTime:  fwtypes.NewRFC3339Null(),
			EndTime:    fwtypes.NewRFC3339Null(),
			DayOfWeek:  types.StringNull(),
			DayOfMonth: types.Int64Null(),
			Interval:   types.Int64Null(),
		},
	)
	if diags.HasError() {
		t.Fatalf("creating schedule object returned diagnostics: %v", diags)
	}

	got, diags := buildScheduleFromPlan(context.Background(), schedule)
	if diags.HasError() {
		t.Fatalf("buildScheduleFromPlan returned diagnostics: %v", diags)
	}
	if got != nil {
		t.Fatalf("expected no schedule request, got %#v", got)
	}
}

func TestUpdateScheduledTaskRequestOmitsNilSchedule(t *testing.T) {
	t.Parallel()

	got, err := json.Marshal(updateScheduledTaskRequest{})
	if err != nil {
		t.Fatalf("marshaling update request: %v", err)
	}
	if strings.Contains(string(got), `"schedule"`) {
		t.Fatalf("expected nil schedule to be omitted, got %s", got)
	}
}
