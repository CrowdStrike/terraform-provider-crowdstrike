package tferrors

import (
	"errors"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/d4c_registration"
	"github.com/crowdstrike/gofalcon/falcon/client/host_group"
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
			name:      "conflict error with custom detail",
			err:       d4c_registration.NewCreateDiscoverCloudAzureAccountConflict(),
			operation: Create,
			options:   []ErrorOption{WithConflictDetail("Custom conflict message")},
			wantDiag:  NewConflictError(Create, "Custom conflict message"),
		},
		{
			name:      "conflict error with default detail",
			err:       d4c_registration.NewCreateDiscoverCloudAzureAccountConflict(),
			operation: Create,
			wantDiag:  NewConflictError(Create, d4c_registration.NewCreateDiscoverCloudAzureAccountConflict().Error()),
		},
		{
			name:      "bad request error with custom detail",
			err:       cloud_policies.NewCreateSuppressionRuleBadRequest(),
			operation: Create,
			options:   []ErrorOption{WithBadRequestDetail("Custom bad request message")},
			wantDiag:  NewBadRequestError(Create, "Custom bad request message"),
		},
		{
			name:      "bad request error with default detail",
			err:       cloud_policies.NewCreateSuppressionRuleBadRequest(),
			operation: Create,
			wantDiag:  NewBadRequestError(Create, cloud_policies.NewCreateSuppressionRuleBadRequest().Error()),
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
