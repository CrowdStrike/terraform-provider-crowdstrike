package tferrors

import (
	"errors"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/d4c_registration"
	"github.com/crowdstrike/gofalcon/falcon/client/host_group"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
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
