package tferrors

import "github.com/hashicorp/terraform-plugin-framework/diag"

// NotFoundErrorSummary is the standard summary message for resource not found errors.
// This constant should be used when checking diagnostic summaries to detect not found errors.
const NotFoundErrorSummary = "Resource Not Found"

// NewNotFoundError creates a new diagnostic error for when a resource is not found.
// This helper ensures consistent error reporting across resources and should be used
// whenever an API returns a 404 or indicates a resource doesn't exist.
//
// The detail parameter should contain specific information about what wasn't found,
// including resource IDs and any relevant API error messages.
func NewNotFoundError(detail string) diag.ErrorDiagnostic {
	return diag.NewErrorDiagnostic(NotFoundErrorSummary, detail)
}

// HasNotFoundError checks if a collection of diagnostics contains a not found error.
// This is useful in Read operations to determine if a resource should be removed from state.
//
// Returns true if any diagnostic has a summary matching NotFoundErrorSummary.
func HasNotFoundError(diags diag.Diagnostics) bool {
	if !diags.HasError() {
		return false
	}

	for _, d := range diags {
		if d.Summary() == NotFoundErrorSummary {
			return true
		}
	}
	return false
}
