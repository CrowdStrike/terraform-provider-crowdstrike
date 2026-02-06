package tferrors

import (
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/go-openapi/runtime"
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

// NewConflictError creates a diagnostic error for 409 Conflict responses.
func NewConflictError(operation Operation, detail string) diag.ErrorDiagnostic {
	return diag.NewErrorDiagnostic(
		fmt.Sprintf("Failed to %s: 409 Conflict", operation),
		detail,
	)
}

// NewBadRequestError creates a diagnostic error for 400 Conflict responses.
func NewBadRequestError(operation Operation, detail string) diag.ErrorDiagnostic {
	return diag.NewErrorDiagnostic(
		fmt.Sprintf("Failed to %s: 400 Bad Request", operation),
		detail,
	)
}

// ErrorOption configures optional behavior for NewDiagnosticFromAPIError.
type ErrorOption func(*errorConfig)

// errorConfig holds optional configuration for error handling.
type errorConfig struct {
	forbiddenDetail   string
	notFoundDetail    string
	conflictDetail    string
	serverErrorDetail string
	badRequestDetail  string
	detail            string
}

// WithForbiddenDetail provides a custom detail message for 403 Forbidden errors.
// If not provided, defaults to the API scope requirements.
func WithForbiddenDetail(detail string) ErrorOption {
	return func(cfg *errorConfig) {
		cfg.forbiddenDetail = detail
	}
}

// WithNotFoundDetail provides a custom detail message for 404 Not Found errors.
func WithNotFoundDetail(detail string) ErrorOption {
	return func(cfg *errorConfig) {
		cfg.notFoundDetail = detail
	}
}

// WithConflictDetail provides a custom detail message for 409 Conflict errors.
func WithConflictDetail(detail string) ErrorOption {
	return func(cfg *errorConfig) {
		cfg.conflictDetail = detail
	}
}

// WithServerErrorDetail provides a custom detail message for 5xx server errors.
func WithServerErrorDetail(detail string) ErrorOption {
	return func(cfg *errorConfig) {
		cfg.serverErrorDetail = detail
	}
}

// WithBadRequestDetail provides a custom detail message for 400 Bad Request errors.
func WithBadRequestDetail(detail string) ErrorOption {
	return func(cfg *errorConfig) {
		cfg.badRequestDetail = detail
	}
}

// WithDetail provides a custom detail message for all other errors.
func WithDetail(detail string) ErrorOption {
	return func(cfg *errorConfig) {
		cfg.detail = detail
	}
}

// NewDiagnosticFromAPIError converts a gofalcon API error into a Terraform diagnostic.
func NewDiagnosticFromAPIError(operation Operation, err error, apiScopes []scopes.Scope, options ...ErrorOption) diag.Diagnostic {
	if err == nil {
		return nil
	}

	cfg := &errorConfig{}
	for _, opt := range options {
		opt(cfg)
	}

	if statusErr, ok := err.(runtime.ClientResponseStatus); ok {
		switch {
		case statusErr.IsCode(400):
			detail := cfg.badRequestDetail
			if detail == "" {
				detail = err.Error()
			}
			return NewBadRequestError(operation, detail)

		case statusErr.IsCode(403):
			detail := cfg.forbiddenDetail
			if detail == "" {
				detail = scopes.GenerateScopeDescription(apiScopes)
			}
			return diag.NewErrorDiagnostic(
				fmt.Sprintf("Failed to %s: 403 Forbidden", operation),
				detail,
			)

		case statusErr.IsCode(404):
			detail := cfg.notFoundDetail
			if detail == "" {
				detail = err.Error()
			}
			return NewNotFoundError(detail)

		case statusErr.IsCode(409):
			detail := cfg.conflictDetail
			if detail == "" {
				detail = err.Error()
			}
			return NewConflictError(operation, detail)

		case statusErr.IsServerError():
			detail := cfg.serverErrorDetail
			if detail == "" {
				detail = err.Error()
			}
			return diag.NewErrorDiagnostic(
				fmt.Sprintf("Failed to %s", operation),
				detail,
			)
		}
	}

	detail := cfg.detail
	if detail == "" {
		detail = err.Error()
	}
	return diag.NewErrorDiagnostic(
		fmt.Sprintf("Failed to %s", operation),
		detail,
	)
}

// NewDiagnosticFromPayloadErrors converts API payload errors to a Terraform diagnostic.
// This function checks for application-level errors within the API response payload
// using falcon.AssertNoError to convert MsaAPIError list to golang errors.
// Returns nil if there are no payload errors.
func NewDiagnosticFromPayloadErrors(operation Operation, payloadErrors []*models.MsaAPIError) diag.Diagnostic {
	// todo: in goFalcon implement a better error check that returns a better format
	if err := falcon.AssertNoError(payloadErrors); err != nil {
		return NewOperationError(operation, err)
	}
	return nil
}
