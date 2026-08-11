package tferrors

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/d4c_registration"
	"github.com/crowdstrike/gofalcon/falcon/client/host_group"
	"github.com/crowdstrike/gofalcon/falcon/client/mssp"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/runtime"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/stretchr/testify/assert"
)

type mockClientResponse struct {
	code    int
	message string
	body    io.ReadCloser
}

func (m *mockClientResponse) Code() int                  { return m.code }
func (m *mockClientResponse) Message() string            { return m.message }
func (m *mockClientResponse) GetHeader(string) string    { return "" }
func (m *mockClientResponse) GetHeaders(string) []string { return nil }
func (m *mockClientResponse) Body() io.ReadCloser        { return m.body }

func TestNewDiagnosticFromAPIError(t *testing.T) {
	testScopes := []scopes.Scope{{Name: "test", Read: true}}

	tests := []struct {
		name      string
		err       error
		operation Operation
		options   []ErrorOption
		wantDiag  diag.Diagnostic
	}{
		{
			name:      "nil error",
			err:       nil,
			operation: Read,
			wantDiag:  nil,
		},
		{
			name:      "forbidden error",
			err:       host_group.NewGetHostGroupsForbidden(),
			operation: Read,
			wantDiag: diag.NewErrorDiagnostic(
				"Failed to read: 403 Forbidden",
				scopes.GenerateScopeDescription(testScopes),
			),
		},
		{
			name:      "not found error with custom detail",
			err:       host_group.NewGetHostGroupsNotFound(),
			operation: Read,
			options:   []ErrorOption{WithNotFoundDetail("Custom not found message")},
			wantDiag:  NewNotFoundError("Custom not found message"),
		},
		{
			name:      "not found error with default detail",
			err:       host_group.NewGetHostGroupsNotFound(),
			operation: Read,
			wantDiag:  NewNotFoundError(host_group.NewGetHostGroupsNotFound().Error()),
		},
		{
			name:      "bad request with custom detail",
			err:       cloud_policies.NewQueryRuleBadRequest(),
			operation: Create,
			options:   []ErrorOption{WithBadRequestDetail("Custom bad request message")},
			wantDiag:  NewBadRequestError(Create, "Custom bad request message"),
		},
		{
			name: "bad request from runtime.APIError extracts body errors",
			err: runtime.NewAPIError("create-rule", &mockClientResponse{
				code:    400,
				message: "400 Bad Request",
				body: io.NopCloser(strings.NewReader(`{
					"errors": [{"code": 400, "message": "item label not found or value invalid"}]
				}`)),
			}, 400),
			operation: Create,
			wantDiag:  NewBadRequestError(Create, "item label not found or value invalid"),
		},
		{
			name: "bad request from runtime.APIError with multiple errors",
			err: runtime.NewAPIError("create-rule", &mockClientResponse{
				code:    400,
				message: "400 Bad Request",
				body: io.NopCloser(strings.NewReader(`{
					"errors": [
						{"code": 400, "message": "first error"},
						{"code": 400, "message": "second error"}
					]
				}`)),
			}, 400),
			operation: Create,
			wantDiag:  NewBadRequestError(Create, "first error; second error"),
		},
		{
			name: "bad request from runtime.APIError with empty body falls back",
			err: runtime.NewAPIError("[POST /ioarules/entities/rules/v1] create-rule", &mockClientResponse{
				code:    400,
				message: "400 Bad Request",
				body:    io.NopCloser(strings.NewReader("")),
			}, 400),
			operation: Create,
			wantDiag:  NewBadRequestError(Create, "[POST /ioarules/entities/rules/v1] create-rule (status 400): {}"),
		},
		{
			name:      "conflict error",
			err:       d4c_registration.NewCreateDiscoverCloudAzureAccountConflict(),
			operation: Create,
			wantDiag:  NewConflictError(Create, d4c_registration.NewCreateDiscoverCloudAzureAccountConflict().Error()),
		},
		{
			name:      "conflict error with custom detail",
			err:       d4c_registration.NewCreateDiscoverCloudAzureAccountConflict(),
			operation: Create,
			options:   []ErrorOption{WithConflictDetail("Custom conflict message")},
			wantDiag:  NewConflictError(Create, "Custom conflict message"),
		},
		{
			name:      "too many requests error with custom detail",
			err:       host_group.NewGetHostGroupsTooManyRequests(),
			operation: Read,
			options:   []ErrorOption{WithTooManyRequestsDetail("Custom rate limit message")},
			wantDiag:  NewTooManyRequestsError(Read, "Custom rate limit message"),
		},
		{
			name:      "too many requests error with default detail",
			err:       host_group.NewGetHostGroupsTooManyRequests(),
			operation: Read,
			wantDiag:  NewTooManyRequestsError(Read, host_group.NewGetHostGroupsTooManyRequests().Error()),
		},
		{
			name:      "server error",
			err:       host_group.NewGetHostGroupsInternalServerError(),
			operation: Update,
			wantDiag: diag.NewErrorDiagnostic(
				"Failed to update",
				host_group.NewGetHostGroupsInternalServerError().Error(),
			),
		},
		{
			name:      "standard go error",
			err:       errors.New("standard go error"),
			operation: Read,
			wantDiag: diag.NewErrorDiagnostic(
				"Failed to read",
				"standard go error",
			),
		},
		{
			name:      "multiple options uses relevant one",
			err:       d4c_registration.NewCreateDiscoverCloudAzureAccountConflict(),
			operation: Create,
			options: []ErrorOption{
				WithNotFoundDetail("Not found detail"),
				WithConflictDetail("Conflict detail"),
				WithBadRequestDetail("Bad request detail"),
			},
			wantDiag: NewConflictError(Create, "Conflict detail"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDiag := NewDiagnosticFromAPIError(tt.operation, tt.err, testScopes, tt.options...)
			assert.Equal(t, tt.wantDiag, gotDiag)
		})
	}
}

func TestNewDiagnosticFromAPIError_207MultiStatus(t *testing.T) {
	testScopes := []scopes.Scope{{Name: "test", Read: true}}

	tests := []struct {
		name      string
		err       error
		operation Operation
		options   []ErrorOption
		wantDiag  diag.Diagnostic
	}{
		{
			name: "207 with 404 error in payload",
			err: &mssp.GetCIDGroupByIDV2MultiStatus{
				Payload: &models.DomainCIDGroupsResponseV1{
					Errors: []*models.MsaAPIError{
						{
							Code:    utils.Addr(int32(404)),
							Message: utils.Addr("No existing group with cid_group_id=123 found"),
						},
					},
				},
			},
			operation: Read,
			wantDiag:  NewNotFoundError("No existing group with cid_group_id=123 found"),
		},
		{
			name: "207 with 404 and custom detail",
			err: &mssp.GetCIDGroupByIDV2MultiStatus{
				Payload: &models.DomainCIDGroupsResponseV1{
					Errors: []*models.MsaAPIError{
						{
							Code:    utils.Addr(int32(404)),
							Message: utils.Addr("Resource not found"),
						},
					},
				},
			},
			operation: Read,
			options:   []ErrorOption{WithNotFoundDetail("Custom 404 message")},
			wantDiag:  NewNotFoundError("Custom 404 message"),
		},
		{
			name: "207 with non-404 error",
			err: &mssp.GetCIDGroupByIDV2MultiStatus{
				Payload: &models.DomainCIDGroupsResponseV1{
					Errors: []*models.MsaAPIError{
						{
							Code:    utils.Addr(int32(400)),
							Message: utils.Addr("Bad request"),
						},
					},
				},
			},
			operation: Create,
			wantDiag: NewOperationError(
				Create,
				errors.New("API Error : Bad request"),
			),
		},
		{
			name: "207 with multiple errors including 404",
			err: &mssp.GetCIDGroupByIDV2MultiStatus{
				Payload: &models.DomainCIDGroupsResponseV1{
					Errors: []*models.MsaAPIError{
						{
							Code:    utils.Addr(int32(400)),
							Message: utils.Addr("Bad request"),
						},
						{
							Code:    utils.Addr(int32(404)),
							Message: utils.Addr("Not found"),
						},
					},
				},
			},
			operation: Read,
			wantDiag:  NewNotFoundError("Not found"),
		},
		{
			name: "207 with empty errors",
			err: &mssp.GetCIDGroupByIDV2MultiStatus{
				Payload: &models.DomainCIDGroupsResponseV1{
					Errors: []*models.MsaAPIError{},
				},
			},
			operation: Read,
			wantDiag:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDiag := NewDiagnosticFromAPIError(tt.operation, tt.err, testScopes, tt.options...)
			assert.Equal(t, tt.wantDiag, gotDiag)
		})
	}
}

func TestNewDiagnosticFromPayloadErrors(t *testing.T) {
	tests := []struct {
		name          string
		operation     Operation
		payloadErrors []*models.MsaAPIError
		wantDiag      diag.Diagnostic
	}{
		{
			name:          "nil errors",
			operation:     Create,
			payloadErrors: nil,
			wantDiag:      nil,
		},
		{
			name:          "empty errors",
			operation:     Create,
			payloadErrors: []*models.MsaAPIError{},
			wantDiag:      nil,
		},
		{
			name:      "single error",
			operation: Create,
			payloadErrors: []*models.MsaAPIError{
				{
					Code:    utils.Addr(int32(400)),
					Message: utils.Addr("Invalid parameter"),
				},
			},
			wantDiag: NewOperationError(
				Create,
				errors.New("API Error : Invalid parameter"),
			),
		},
		{
			name:      "multiple errors",
			operation: Update,
			payloadErrors: []*models.MsaAPIError{
				{
					Code:    utils.Addr(int32(400)),
					Message: utils.Addr("First error"),
				},
				{
					Code:    utils.Addr(int32(400)),
					Message: utils.Addr("Second error"),
				},
			},
			wantDiag: NewOperationError(
				Update,
				errors.New("API Error : First errorAPI Error : Second error"),
			),
		},
		{
			name:      "read operation",
			operation: Read,
			payloadErrors: []*models.MsaAPIError{
				{
					Code:    utils.Addr(int32(404)),
					Message: utils.Addr("Resource not found"),
				},
			},
			wantDiag: NewOperationError(
				Read,
				errors.New("API Error : Resource not found"),
			),
		},
		{
			name:      "delete operation",
			operation: Delete,
			payloadErrors: []*models.MsaAPIError{
				{
					Code:    utils.Addr(int32(500)),
					Message: utils.Addr("Internal server error"),
				},
			},
			wantDiag: NewOperationError(
				Delete,
				errors.New("API Error : Internal server error"),
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDiag := NewDiagnosticFromPayloadErrors(tt.operation, tt.payloadErrors)
			assert.Equal(t, tt.wantDiag, gotDiag)
		})
	}
}

// requestContext mirrors the prefix gofalcon's generated Error methods put in front
// of the payload.
const requestContext = "[GET /some/endpoint/v1][400] someEndpointBadRequest"

// fakeTypedResponse stands in for a generated gofalcon error response. It reproduces
// the two things the rendering depends on: a GetPayload method, and an Error method
// that formats the payload with %+v the way go-swagger emits it.
type fakeTypedResponse struct {
	payload any
}

func (f *fakeTypedResponse) GetPayload() any { return f.payload }

func (f *fakeTypedResponse) Error() string {
	return fmt.Sprintf("%s  %+v", requestContext, f.payload)
}

// TestRenderPayloadError covers every payload error type gofalcon defines. The
// models disagree on almost everything: Code appears as *int32, int32, string and
// *string, Message as both *string and string, and the optional fields differ per
// service. All of them must render in the format gofalcon hand-writes for
// models.MsaAPIError, so a diagnostic never betrays which service failed.
//
// models.MsaAPIError cases assert against that String method directly rather than
// against a literal, so the day gofalcon changes it this fails instead of drifting.
func TestRenderPayloadError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		payloadError any
		expected     string
	}{
		{
			name:         "MsaAPIError",
			payloadError: &models.MsaAPIError{Code: utils.Addr(int32(400)), ID: "abc123", Message: utils.Addr("boom")},
			expected:     "{Code:400 ID:abc123 Message:boom}",
		},
		{
			name:         "MsaAPIError without an id",
			payloadError: &models.MsaAPIError{Code: utils.Addr(int32(400)), Message: utils.Addr("boom")},
			expected:     "{Code:400 Message:boom}",
		},
		{
			name:         "MsaAPIError with an absent trailing field keeps the trailing space",
			payloadError: &models.MsaAPIError{Code: utils.Addr(int32(500)), ID: "abc123"},
			expected:     "{Code:500 ID:abc123 }",
		},
		{
			name:         "MsaAPIError with an empty but present message",
			payloadError: &models.MsaAPIError{Code: utils.Addr(int32(500)), Message: utils.Addr("")},
			expected:     "{Code:500 Message:}",
		},
		{
			name:         "MsaAPIError with no fields set",
			payloadError: &models.MsaAPIError{},
			expected:     "{}",
		},
		{
			name:         "PolicymanagerError",
			payloadError: &models.PolicymanagerError{Code: utils.Addr(int32(400)), Field: "platform_name", ID: "abc123", Message: utils.Addr("boom")},
			expected:     "{Code:400 Field:platform_name ID:abc123 Message:boom}",
		},
		{
			name:         "PolicymanagerError without a field renders like MsaAPIError",
			payloadError: &models.PolicymanagerError{Code: utils.Addr(int32(400)), ID: "abc123", Message: utils.Addr("boom")},
			expected:     "{Code:400 ID:abc123 Message:boom}",
		},
		{
			name:         "FwmgrMsaspecError renders like MsaAPIError",
			payloadError: &models.FwmgrMsaspecError{Code: utils.Addr(int32(400)), ID: "abc123", Message: utils.Addr("boom")},
			expected:     "{Code:400 ID:abc123 Message:boom}",
		},
		{
			name:         "DomainReconAPIError",
			payloadError: &models.DomainReconAPIError{Code: utils.Addr(int32(400)), ID: "abc123", Message: utils.Addr("boom"), MessageKey: "recon_key"},
			expected:     "{Code:400 ID:abc123 Message:boom MessageKey:recon_key}",
		},
		{
			name:         "ReconmsaAPIError with an absent trailing field",
			payloadError: &models.ReconmsaAPIError{Code: utils.Addr(int32(400)), ID: "abc123", Message: utils.Addr("boom")},
			expected:     "{Code:400 ID:abc123 Message:boom }",
		},
		{
			name:         "MalqueryQueryError",
			payloadError: &models.MalqueryQueryError{Code: utils.Addr(int32(400)), ID: "abc123", Message: utils.Addr("boom"), Type: "query"},
			expected:     "{Code:400 ID:abc123 Message:boom Type:query}",
		},
		{
			name:         "DevicecontrolapiRespMSAErrorV1",
			payloadError: &models.DevicecontrolapiRespMSAErrorV1{Code: utils.Addr(int32(400)), Message: utils.Addr("boom"), ResourceID: "res-1", Type: "policy"},
			expected:     "{Code:400 Message:boom ResourceID:res-1 Type:policy}",
		},
		{
			name:         "AssetgroupmanagerV1Error with plain string fields",
			payloadError: &models.AssetgroupmanagerV1Error{Code: "invalid_request", ID: "abc123", Message: "boom"},
			expected:     "{Code:invalid_request ID:abc123 Message:boom}",
		},
		{
			name:         "ResponsesError",
			payloadError: &models.ResponsesError{Code: utils.Addr(int32(400)), Field: "name", ID: "abc123", Message: utils.Addr("boom")},
			expected:     "{Code:400 Field:name ID:abc123 Message:boom}",
		},
		{
			name:         "QuickscanproError with a string pointer code",
			payloadError: &models.QuickscanproError{Code: utils.Addr("invalid_request"), Message: utils.Addr("boom")},
			expected:     "{Code:invalid_request Message:boom}",
		},
		{
			name: "GraphValidationError with many optional fields",
			payloadError: &models.GraphValidationError{
				Code:         int32(42),
				Level:        "error",
				Message:      utils.Addr("boom"),
				NodeID:       "node-1",
				ParentNodeID: "node-0",
				Property:     "trigger.value",
				ResourceID:   "res-1",
			},
			expected: "{Code:42 Level:error Message:boom NodeID:node-1 ParentNodeID:node-0 Property:trigger.value ResourceID:res-1 }",
		},
		{
			name:         "FalconxMalqueryErrorV1 with plain scalar fields",
			payloadError: &models.FalconxMalqueryErrorV1{Code: int32(400), Message: "boom"},
			expected:     "{Code:400 Message:boom}",
		},
		{
			name:         "nil error",
			payloadError: (*models.PolicymanagerError)(nil),
			expected:     "<nil>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rendered := renderPayloadError(reflect.ValueOf(tt.payloadError))
			assert.Equal(t, tt.expected, rendered)

			if msaError, ok := tt.payloadError.(*models.MsaAPIError); ok {
				assert.Equal(t, msaError.String(), rendered,
					"must match the String method gofalcon hand-writes for MsaAPIError")
			}
		})
	}
}

// TestDetailFromTypedPayload renders the generated response models the provider
// actually receives, covering the payload fields surrounding the errors and the
// cases that must render nothing so the caller falls back to err.Error().
//
// Payloads carrying models.MsaAPIError are additionally required to be byte
// identical to err.Error(), because gofalcon already renders those readably and
// every existing resource in the provider surfaces that text today.
func TestDetailFromTypedPayload(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		// expected is the rendered payload, without the request context prefix. An
		// empty value means no detail is produced at all.
		expected string
		// matchesGofalcon marks payloads gofalcon renders readably on its own, whose
		// rendering must not change.
		matchesGofalcon bool
	}{
		{
			name: "PolicymanagerPoliciesResponse",
			err: &fakeTypedResponse{payload: &models.PolicymanagerPoliciesResponse{
				Errors: []*models.PolicymanagerError{
					{
						Code:    utils.Addr(int32(400)),
						Field:   "platform_name",
						Message: utils.Addr("platform_name parameter has to be either 'win', or 'mac', it is: nope"),
					},
				},
			}},
			expected: "&{Errors:[{Code:400 Field:platform_name Message:platform_name parameter has to be either 'win', or 'mac', it is: nope}] Meta:<nil> Resources:[]}",
		},
		{
			name: "PolicymanagerPoliciesResponse with meta",
			err: &fakeTypedResponse{payload: &models.PolicymanagerPoliciesResponse{
				Errors: []*models.PolicymanagerError{
					{Code: utils.Addr(int32(400)), Message: utils.Addr("boom")},
				},
				Meta: &models.MsaMetaInfo{TraceID: utils.Addr("trace-id")},
			}},
			expected: "&{Errors:[{Code:400 Message:boom}] Meta:PoweredBy: TraceID:trace-id} Resources:[]}",
		},
		{
			name: "ResponsesPolicySearchV1",
			err: &fakeTypedResponse{payload: &models.ResponsesPolicySearchV1{
				Errors: []*models.ResponsesError{
					{Code: utils.Addr(int32(400)), Field: "name", Message: utils.Addr("boom")},
				},
			}},
			expected: "&{Errors:[{Code:400 Field:name Message:boom}] Meta:<nil> Resources:[]}",
		},
		{
			name: "PreventionRespV1 matches gofalcon",
			err: &fakeTypedResponse{payload: &models.PreventionRespV1{
				Errors: []*models.MsaAPIError{
					{Code: utils.Addr(int32(400)), Message: utils.Addr("Invalid filter expression supplied")},
				},
				Meta: &models.MsaMetaInfo{
					QueryTime: utils.Addr(float64(0.0001)),
					TraceID:   utils.Addr("trace-id"),
				},
			}},
			expected:        "&{Errors:[{Code:400 Message:Invalid filter expression supplied}] Meta:PoweredBy: QueryTime:0.0001 TraceID:trace-id} Resources:[]}",
			matchesGofalcon: true,
		},
		{
			name: "DomainCIDGroupsResponseV1 with multiple errors matches gofalcon",
			err: &fakeTypedResponse{payload: &models.DomainCIDGroupsResponseV1{
				Errors: []*models.MsaAPIError{
					{Code: utils.Addr(int32(400)), Message: utils.Addr("first")},
					{Code: utils.Addr(int32(400)), Message: utils.Addr("second")},
				},
			}},
			expected:        "&{Errors:[{Code:400 Message:first} {Code:400 Message:second}] Meta:<nil> Resources:[]}",
			matchesGofalcon: true,
		},
		{
			name: "DomainCIDGroupsResponseV1 with a nil error element matches gofalcon",
			err: &fakeTypedResponse{payload: &models.DomainCIDGroupsResponseV1{
				Errors: []*models.MsaAPIError{nil},
			}},
			expected:        "&{Errors:[<nil>] Meta:<nil> Resources:[]}",
			matchesGofalcon: true,
		},
		{
			name: "not a typed response",
			err:  errors.New("plain error"),
		},
		{
			name: "nil payload",
			err:  &fakeTypedResponse{payload: (*models.PreventionRespV1)(nil)},
		},
		{
			name: "payload without an errors field",
			err:  &fakeTypedResponse{payload: &models.MsaMetaInfo{}},
		},
		{
			name: "empty errors slice",
			err:  &fakeTypedResponse{payload: &models.PreventionRespV1{Errors: []*models.MsaAPIError{}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			detail := detailFromTypedPayload(tt.err)

			if tt.expected == "" {
				assert.Empty(t, detail)
				return
			}

			assert.Equal(t, requestContext+"  "+tt.expected, detail)

			if tt.matchesGofalcon {
				assert.Equal(t, tt.err.Error(), detail,
					"rendering must match what gofalcon produces for MsaAPIError payloads")
			}
		})
	}
}
