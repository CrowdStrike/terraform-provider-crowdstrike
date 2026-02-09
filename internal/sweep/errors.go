package sweep

import (
	"strings"

	"github.com/go-openapi/runtime"
)

// IsNotFoundError checks if the error is a 404 Not Found response.
func IsNotFoundError(err error) bool {
	if err == nil {
		return false
	}

	// Type-safe check using runtime.ClientResponseStatus
	if statusErr, ok := err.(runtime.ClientResponseStatus); ok {
		return statusErr.IsCode(404)
	}

	// Fallback to string matching for backwards compatibility
	errStr := err.Error()
	return strings.Contains(errStr, "404") ||
		strings.Contains(strings.ToLower(errStr), "not found")
}

// IsForbiddenError checks if the error is a 403 Forbidden response.
func IsForbiddenError(err error) bool {
	if err == nil {
		return false
	}

	if statusErr, ok := err.(runtime.ClientResponseStatus); ok {
		return statusErr.IsCode(403)
	}

	errStr := err.Error()
	return strings.Contains(errStr, "403") ||
		strings.Contains(strings.ToLower(errStr), "forbidden") ||
		strings.Contains(strings.ToLower(errStr), "insufficient scope")
}

// IsConflictError checks if the error is a 409 Conflict response.
func IsConflictError(err error) bool {
	if err == nil {
		return false
	}

	if statusErr, ok := err.(runtime.ClientResponseStatus); ok {
		return statusErr.IsCode(409)
	}

	errStr := err.Error()
	return strings.Contains(errStr, "409") ||
		strings.Contains(strings.ToLower(errStr), "conflict")
}

// ShouldIgnoreError determines if a delete operation should ignore an error
// Returns true for errors that indicate the resource is already gone (404, 409)
// or that we don't have permission (403) - we can't fix permission issues in sweeper.
func ShouldIgnoreError(err error) bool {
	return IsNotFoundError(err) || IsForbiddenError(err)
}
