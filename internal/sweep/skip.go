package sweep

import (
	"strings"

	"github.com/go-openapi/runtime"
)

func SkipSweepError(err error) bool {
	if err == nil {
		return false
	}

	// Check for specific HTTP status codes that indicate transient issues
	if statusErr, ok := err.(runtime.ClientResponseStatus); ok {
		// Rate limiting
		if statusErr.IsCode(429) {
			return true
		}
		// Service unavailable
		if statusErr.IsCode(503) {
			return true
		}
		// Bad Gateway / Gateway Timeout
		if statusErr.IsCode(502) || statusErr.IsCode(504) {
			return true
		}
	}

	// Existing string-based checks for network/timeout errors
	skipMessages := []string{
		// Rate limiting
		"429", "rate limit", "too many requests",
		// Service availability
		"503", "502", "504", "service unavailable", "bad gateway", "gateway timeout",
		// Timeouts
		"timeout", "context deadline exceeded",
		// Network errors
		"no such host", "connection refused", "connection reset",
		"EOF", "i/o timeout", "broken pipe",
	}

	errStr := strings.ToLower(err.Error())
	for _, msg := range skipMessages {
		if strings.Contains(errStr, strings.ToLower(msg)) {
			return true
		}
	}

	return false
}
