package tferrors

import (
	"fmt"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// NotFoundErrorSummary is the standard summary message for resource not found errors.
// This constant should be used when checking diagnostic summaries to detect not found errors.
const NotFoundErrorSummary = "Resource Not Found"

// Operation represents a CRUD operation type for consistent error reporting.
type Operation string

// Operation constants define standard CRUD operations for consistent error reporting.
const (
	Create Operation = "create"
	Read   Operation = "read"
	Update Operation = "update"
	Delete Operation = "delete"
)

// NewNotFoundError creates a diagnostic error for when a resource is not found.
func NewNotFoundError(detail string) diag.ErrorDiagnostic {
	return diag.NewErrorDiagnostic(NotFoundErrorSummary, detail)
}

// HasNotFoundError checks if diagnostics contains a not found error.
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

// NewEmptyResponseError creates a diagnostic error for when an API returns no data.
func NewEmptyResponseError(operation Operation) diag.ErrorDiagnostic {
	return diag.NewErrorDiagnostic(
		fmt.Sprintf("Failed to %s", operation),
		"API call succeeded but returned no data. If the problem persists, please report this issue at: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues",
	)
}

// NewForbiddenError creates a diagnostic error for 403 Forbidden responses.
func NewForbiddenError(operation Operation, requiredScopes []scopes.Scope) diag.ErrorDiagnostic {
	return diag.NewErrorDiagnostic(
		fmt.Sprintf("Failed to %s: 403 Forbidden", operation),
		scopes.GenerateScopeDescription(requiredScopes),
	)
}

// NewOperationError creates a diagnostic error for general operation failures.
func NewOperationError(operation Operation, err error) diag.ErrorDiagnostic {
	return diag.NewErrorDiagnostic(
		fmt.Sprintf("Failed to %s", operation),
		err.Error(),
	)
}
