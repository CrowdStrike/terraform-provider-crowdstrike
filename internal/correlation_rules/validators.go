package correlationrules

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

const maxLookback = 168 * time.Hour

// lookbackValidator validates search.lookback bounds. The GoDurationType custom
// type already enforces the Go duration FORMAT (rejecting `1d`, garbage, etc.);
// this validator only checks the value is positive and within the 168h cap.
type lookbackValidator struct{}

func (v lookbackValidator) Description(_ context.Context) string {
	return "must be a positive Go duration no longer than `168h`"
}

func (v lookbackValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v lookbackValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	value := req.ConfigValue.ValueString()

	d, err := time.ParseDuration(value)
	if err != nil {
		// Format errors are surfaced by the GoDurationType custom type; skip.
		return
	}

	if d <= 0 {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid lookback",
			fmt.Sprintf("lookback must be a positive duration. Got: %q", value),
		)
		return
	}

	if d > maxLookback {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Lookback exceeds maximum",
			fmt.Sprintf("lookback must be at most `168h`. Got: %q", value),
		)
	}
}

// LookbackValidator validates a search lookback duration.
func LookbackValidator() validator.String {
	return lookbackValidator{}
}

const minScheduleInterval = 5 * time.Minute

// scheduleIntervalValidator validates schedule.interval bounds. The
// GoDurationType custom type enforces the Go duration FORMAT; this validator
// only checks the value is at least 5m (the API caps at 288 executions/day).
type scheduleIntervalValidator struct{}

func (v scheduleIntervalValidator) Description(_ context.Context) string {
	return "must be a Go duration of at least `5m`"
}

func (v scheduleIntervalValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v scheduleIntervalValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	value := req.ConfigValue.ValueString()

	d, err := time.ParseDuration(value)
	if err != nil {
		// Format errors are surfaced by the GoDurationType custom type; skip.
		return
	}

	if d < minScheduleInterval {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Schedule interval below minimum",
			fmt.Sprintf("schedule interval must be at least `5m` (API caps at 288 executions per day). Got: %q", value),
		)
	}
}

// ScheduleIntervalValidator validates a bare-duration schedule interval.
func ScheduleIntervalValidator() validator.String {
	return scheduleIntervalValidator{}
}

var cidNormalizedPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

// cidValidator validates a CrowdStrike CID: 32 lowercase hex characters,
// with no `-NN` checksum suffix. The API returns the canonical form, so we
// require it here to avoid state drift after apply.
type cidValidator struct{}

func (v cidValidator) Description(_ context.Context) string {
	return "must be a CrowdStrike CID in canonical form: 32 lowercase hex characters, with no `-NN` checksum suffix"
}

func (v cidValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v cidValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	value := req.ConfigValue.ValueString()
	if !cidNormalizedPattern.MatchString(value) {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid cid",
			fmt.Sprintf("cid must be 32 lowercase hex characters with no `-NN` checksum suffix. Got: %q", value),
		)
	}
}

// CIDValidator validates a CrowdStrike CID.
func CIDValidator() validator.String {
	return cidValidator{}
}
