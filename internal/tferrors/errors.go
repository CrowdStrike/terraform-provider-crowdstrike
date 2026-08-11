package tferrors

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

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

// IsServerError reports whether a gofalcon error carries a 5xx status. Every
// generated response type implements runtime.ClientResponseStatus, so this is a
// type check rather than a match on the error text. errors.As is used rather than a
// direct type assertion so a wrapped error is still classified.
//
// Callers use this to tell a retryable server-side failure from a request the API
// rejected outright.
func IsServerError(err error) bool {
	var status runtime.ClientResponseStatus
	if errors.As(err, &status) {
		return status.IsServerError()
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

// NewTooManyRequestsError creates a diagnostic error for 429 Too Many Requests responses.
func NewTooManyRequestsError(operation Operation, detail string) diag.ErrorDiagnostic {
	return diag.NewErrorDiagnostic(
		fmt.Sprintf("Failed to %s: 429 Too Many Requests", operation),
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
	forbiddenDetail       string
	notFoundDetail        string
	conflictDetail        string
	serverErrorDetail     string
	badRequestDetail      string
	tooManyRequestsDetail string
	detail                string
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

// WithTooManyRequestsDetail provides a custom detail message for 429 Too Many Requests errors.
func WithTooManyRequestsDetail(detail string) ErrorOption {
	return func(cfg *errorConfig) {
		cfg.tooManyRequestsDetail = detail
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
				detail = extractAPIErrorDetail(err)
			}
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
				detail = extractAPIErrorDetail(err)
			}
			if detail == "" {
				detail = err.Error()
			}
			return NewNotFoundError(detail)

		case statusErr.IsCode(207):
			return handle207PayloadErrors(operation, err, cfg)

		case statusErr.IsCode(409):
			detail := cfg.conflictDetail
			if detail == "" {
				detail = extractAPIErrorDetail(err)
			}
			if detail == "" {
				detail = err.Error()
			}
			return NewConflictError(operation, detail)

		case statusErr.IsCode(429):
			detail := cfg.tooManyRequestsDetail
			if detail == "" {
				detail = err.Error()
			}
			return NewTooManyRequestsError(operation, detail)

		case statusErr.IsServerError():
			detail := cfg.serverErrorDetail
			if detail == "" {
				detail = extractAPIErrorDetail(err)
			}
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
		detail = extractAPIErrorDetail(err)
	}
	if detail == "" {
		detail = err.Error()
	}
	return diag.NewErrorDiagnostic(
		fmt.Sprintf("Failed to %s", operation),
		detail,
	)
}

// handle207PayloadErrors extracts and processes payload errors from 207 Multi-Status responses.
// Returns NotFoundError if any error has code 404, otherwise returns standard operation error.
func handle207PayloadErrors(operation Operation, err error, cfg *errorConfig) diag.Diagnostic {
	// Call GetPayload() method using reflection since return types vary by multi-status type
	errVal := reflect.ValueOf(err)
	getPayloadMethod := errVal.MethodByName("GetPayload")
	if !getPayloadMethod.IsValid() {
		return diag.NewErrorDiagnostic(
			fmt.Sprintf("Failed to %s", operation),
			err.Error(),
		)
	}

	// Call GetPayload()
	results := getPayloadMethod.Call(nil)
	if len(results) == 0 || results[0].IsNil() {
		return diag.NewErrorDiagnostic(
			fmt.Sprintf("Failed to %s", operation),
			err.Error(),
		)
	}

	payload := results[0].Interface()
	if payload == nil {
		return diag.NewErrorDiagnostic(
			fmt.Sprintf("Failed to %s", operation),
			err.Error(),
		)
	}

	payloadVal := reflect.ValueOf(payload)
	if payloadVal.Kind() == reflect.Ptr {
		payloadVal = payloadVal.Elem()
	}

	if payloadVal.Kind() != reflect.Struct {
		return diag.NewErrorDiagnostic(
			fmt.Sprintf("Failed to %s", operation),
			err.Error(),
		)
	}

	errorsField := payloadVal.FieldByName("Errors")
	if !errorsField.IsValid() || !errorsField.CanInterface() {
		return diag.NewErrorDiagnostic(
			fmt.Sprintf("Failed to %s", operation),
			err.Error(),
		)
	}

	// Type assert to []*models.MsaAPIError
	payloadErrors, ok := errorsField.Interface().([]*models.MsaAPIError)
	if !ok || len(payloadErrors) == 0 {
		return nil
	}

	// Check for 404 in payload errors
	for _, apiErr := range payloadErrors {
		if apiErr != nil && apiErr.Code != nil && *apiErr.Code == 404 {
			detail := cfg.notFoundDetail
			if detail == "" && apiErr.Message != nil {
				detail = *apiErr.Message
			}
			return NewNotFoundError(detail)
		}
	}

	// Other payload errors
	return NewDiagnosticFromPayloadErrors(operation, payloadErrors)
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

// extractAPIErrorDetail attempts to read error messages out of a failed gofalcon
// response. Two shapes are handled: a runtime.APIError, whose body must be parsed
// as JSON because the SDK has no typed response struct for the status code, and a
// generated typed response, whose payload carries the errors as a struct.
func extractAPIErrorDetail(err error) string {
	if detail := detailFromRuntimeAPIError(err); detail != "" {
		return detail
	}

	return detailFromTypedPayload(err)
}

// detailFromRuntimeAPIError reads error messages from the response body of a
// runtime.APIError. This handles cases where the gofalcon SDK does not have
// a typed response struct for a given status code (e.g., 400), causing the error
// to fall into the default case of ReadResponse with an unreadable body reference.
func detailFromRuntimeAPIError(err error) string {
	apiErr, ok := err.(*runtime.APIError)
	if !ok {
		return ""
	}

	resp, ok := apiErr.Response.(runtime.ClientResponse)
	if !ok || resp.Body() == nil {
		return ""
	}

	body, readErr := io.ReadAll(resp.Body())
	if readErr != nil || len(body) == 0 {
		return ""
	}

	var parsed struct {
		Errors []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}

	if json.Unmarshal(body, &parsed) != nil || len(parsed.Errors) == 0 {
		return ""
	}

	var messages []string
	for _, e := range parsed.Errors {
		if e.Message != "" {
			messages = append(messages, e.Message)
		}
	}

	return strings.Join(messages, "; ")
}

// errorsFieldName is the field every gofalcon response payload uses to carry
// application-level errors.
const errorsFieldName = "Errors"

// detailFromTypedPayload renders a generated gofalcon response payload, reached
// through the GetPayload method that go-swagger emits on every typed response.
//
// gofalcon's own rendering comes from the generated Error methods, which format the
// payload with %+v. That only produces readable output for payloads whose error
// type has a String method, which in practice is just models.MsaAPIError; every
// other error type (PolicymanagerError, FwmgrMsaspecError, GraphValidationError,
// and the rest) renders as a pointer address. This reproduces the MsaAPIError
// rendering for all of them so diagnostics read the same regardless of which error
// model an endpoint returns.
//
// Returns an empty string when the payload carries no errors, leaving the caller to
// fall back to err.Error().
func detailFromTypedPayload(err error) string {
	payload := typedResponsePayload(err)
	if !payload.IsValid() {
		return ""
	}

	payloadErrors := payload.FieldByName(errorsFieldName)
	if !payloadErrors.IsValid() || payloadErrors.Kind() != reflect.Slice || payloadErrors.Len() == 0 {
		return ""
	}

	return errorContextPrefix(err) + renderPayload(payload)
}

// renderPayload renders a response payload in the same shape fmt produces for a
// pointer to a struct, substituting a readable rendering for the errors slice.
// Every other field is delegated to fmt so that types gofalcon already renders
// well, such as models.MsaMetaInfo, keep their existing output.
func renderPayload(payload reflect.Value) string {
	var rendered strings.Builder
	rendered.WriteString("&{")

	payloadType := payload.Type()
	for i := 0; i < payload.NumField(); i++ {
		if i > 0 {
			rendered.WriteString(" ")
		}

		field := payloadType.Field(i)
		rendered.WriteString(field.Name)
		rendered.WriteString(":")

		if field.Name == errorsFieldName {
			rendered.WriteString(renderPayloadErrors(payload.Field(i)))
			continue
		}

		fmt.Fprintf(&rendered, "%+v", payload.Field(i).Interface())
	}

	rendered.WriteString("}")

	return rendered.String()
}

// renderPayloadErrors renders a slice of payload errors the way fmt renders a slice
// whose elements carry a String method: space separated inside square brackets.
func renderPayloadErrors(payloadErrors reflect.Value) string {
	var rendered strings.Builder
	rendered.WriteString("[")

	for i := 0; i < payloadErrors.Len(); i++ {
		if i > 0 {
			rendered.WriteString(" ")
		}

		rendered.WriteString(renderPayloadError(payloadErrors.Index(i)))
	}

	rendered.WriteString("]")

	return rendered.String()
}

// renderPayloadError renders a single payload error, matching the String method
// gofalcon hand-writes for models.MsaAPIError in falcon/models/helper_methods.go.
//
// That method skips fields the API omitted and puts a space after every field it
// writes except the last one declared on the struct, which leaves a trailing space
// whenever that last field is absent. Both quirks are reproduced here, because the
// point of this rendering is to be indistinguishable from gofalcon's own.
func renderPayloadError(payloadError reflect.Value) string {
	payloadError = derefToStruct(payloadError)
	if !payloadError.IsValid() {
		return "<nil>"
	}

	payloadErrorType := payloadError.Type()
	lastFieldSet := false

	var fields []string
	for i := 0; i < payloadError.NumField(); i++ {
		value, ok := setFieldValue(payloadError.Field(i))
		if !ok {
			continue
		}

		fields = append(fields, fmt.Sprintf("%s:%+v", payloadErrorType.Field(i).Name, value))
		lastFieldSet = i == payloadError.NumField()-1
	}

	rendered := strings.Join(fields, " ")
	if len(fields) > 0 && !lastFieldSet {
		rendered += " "
	}

	return "{" + rendered + "}"
}

// setFieldValue reports whether a payload error field was populated by the API and
// returns the value to render for it. Pointer fields count as populated when
// non-nil, and plain fields when non-zero, which mirrors how these models are
// declared: required fields are pointers and optional ones carry omitempty.
func setFieldValue(field reflect.Value) (any, bool) {
	if field.Kind() == reflect.Ptr {
		if field.IsNil() {
			return nil, false
		}

		return field.Elem().Interface(), true
	}

	if field.IsZero() {
		return nil, false
	}

	return field.Interface(), true
}

// payloadMarker is where a generated Error method stops describing the request and
// starts rendering the response payload.
const payloadMarker = "  &{"

// errorContextPrefix returns the request context that gofalcon's generated Error
// methods put in front of the payload, in the form "[METHOD /path][code] opName  ".
// That prefix is worth keeping so these diagnostics read the same as the ones from
// endpoints whose payload errors render on their own; only the payload rendering
// that follows it is unusable. Returns an empty string when the prefix cannot be
// located, leaving the caller with a bare message.
func errorContextPrefix(err error) string {
	context, _, found := strings.Cut(err.Error(), payloadMarker)
	if !found {
		return ""
	}

	return context + "  "
}

// typedResponsePayload calls the GetPayload method on a generated gofalcon
// response and returns the payload struct it yields. An invalid Value is returned
// when the error is not a typed response or carries no payload.
func typedResponsePayload(err error) reflect.Value {
	method := reflect.ValueOf(err).MethodByName("GetPayload")
	if !method.IsValid() {
		return reflect.Value{}
	}

	methodType := method.Type()
	if methodType.NumIn() != 0 || methodType.NumOut() != 1 {
		return reflect.Value{}
	}

	return derefToStruct(method.Call(nil)[0])
}

// derefToStruct follows pointers down to a struct value, returning an invalid
// Value when a nil pointer or a non-struct is encountered.
func derefToStruct(value reflect.Value) reflect.Value {
	for value.Kind() == reflect.Ptr || value.Kind() == reflect.Interface {
		if value.IsNil() {
			return reflect.Value{}
		}
		value = value.Elem()
	}

	if value.Kind() != reflect.Struct {
		return reflect.Value{}
	}

	return value
}
