package itautomation

import (
	"context"
	"fmt"
	"regexp"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

var durationCanonicalPattern = regexp.MustCompile(`^[1-9]\d*[smhd]$`)

type durationCanonicalValidator struct{}

func (v durationCanonicalValidator) Description(_ context.Context) string {
	return "value must be a duration like `1m`, `30m`, `1h`, or `2d` in canonical form (largest unit that divides evenly, minimum `1m`)"
}

func (v durationCanonicalValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v durationCanonicalValidator) ValidateString(
	ctx context.Context,
	req validator.StringRequest,
	resp *validator.StringResponse,
) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	value := req.ConfigValue.ValueString()

	if !durationCanonicalPattern.MatchString(value) {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid duration",
			fmt.Sprintf(
				"Expected a duration like `1m`, `30m`, `1h`, or `2d` (single positive integer plus one of `s`, `m`, `h`, `d`). Got: %q.",
				value,
			),
		)
		return
	}

	canonical, ok := canonicalizeDuration(value)
	if !ok {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid duration",
			fmt.Sprintf(
				"Duration %q is below the minimum of `1m`.",
				value,
			),
		)
		return
	}

	if canonical != value {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Duration not in canonical form",
			fmt.Sprintf(
				"Duration %q should be written as %q. The API normalizes to the largest unit that divides evenly (60s = 1m, 60m = 1h, 24h = 1d).",
				value,
				canonical,
			),
		)
		return
	}
}

// canonicalizeDuration walks a duration up its units, stopping at the largest
// unit that divides evenly. Returns the canonical form and false if the
// duration is below the minimum (1m).
func canonicalizeDuration(value string) (string, bool) {
	if len(value) < 2 {
		return "", false
	}

	unit := value[len(value)-1]
	numStr := value[:len(value)-1]
	n, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil || n <= 0 {
		return "", false
	}

	var seconds int64
	switch unit {
	case 's':
		seconds = n
	case 'm':
		seconds = n * 60
	case 'h':
		seconds = n * 3600
	case 'd':
		seconds = n * 86400
	default:
		return "", false
	}

	if seconds < 60 {
		return "", false
	}

	if seconds%86400 == 0 {
		return fmt.Sprintf("%dd", seconds/86400), true
	}
	if seconds%3600 == 0 {
		return fmt.Sprintf("%dh", seconds/3600), true
	}
	if seconds%60 == 0 {
		return fmt.Sprintf("%dm", seconds/60), true
	}
	return fmt.Sprintf("%ds", seconds), true
}

// DurationCanonicalValidator returns a validator that requires a duration
// string in canonical form (e.g. `30m`, `1h`, `2d`). It rejects decimals,
// multi-unit forms, leading zeros, and durations below `1m`.
func DurationCanonicalValidator() validator.String {
	return durationCanonicalValidator{}
}
