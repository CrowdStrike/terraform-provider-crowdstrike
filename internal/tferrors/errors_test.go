package tferrors

import (
	"errors"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/d4c_registration"
	"github.com/crowdstrike/gofalcon/falcon/client/host_group"
	"github.com/crowdstrike/gofalcon/falcon/client/mssp"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/stretchr/testify/assert"
)

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
