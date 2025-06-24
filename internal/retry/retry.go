package retry

import (
	"context"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// RetryUntilNoError repeatedly calls fn until it returns nil, the timeout is reached, or the context is cancelled.
// It waits interval between attempts, and logs each attempt and outcome.
func RetryUntilNoError(ctx context.Context, timeout, interval time.Duration, fn func() error) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for attempt := 1; ; attempt++ {
		err := fn()
		tflog.Debug(ctx, "Retry attempt", map[string]any{"attempt": attempt, "error": err})
		if err == nil {
			tflog.Debug(ctx, "Retry finished successfully", map[string]any{"attempt": attempt})
			return nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			tflog.Debug(ctx, "Retry timed out", map[string]any{"attempt": attempt, "last_error": lastErr})
			return lastErr
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			tflog.Debug(ctx, "Retry context cancelled during wait", map[string]any{"attempt": attempt})
			return ctx.Err()
		case <-timer.C:
		}
	}
}
