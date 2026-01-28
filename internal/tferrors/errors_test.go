package tferrors

import (
	"errors"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/d4c_registration"
	"github.com/crowdstrike/gofalcon/falcon/client/host_group"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/stretchr/testify/assert"
)

func TestHandleAPIError(t *testing.T) {
	testScopes := []scopes.Scope{{Name: "test", Read: true}}

	tests := []struct {
		name      string
		err       error
		operation Operation
		options   []ErrorOption
		wantDiags diag.Diagnostics
	}{
		{
			name:      "nil error",
			err:       nil,
			operation: Read,
			wantDiags: nil,
		},
		{
			name:      "forbidden error",
			err:       host_group.NewGetHostGroupsForbidden(),
			operation: Read,
			wantDiags: diag.Diagnostics{
				diag.NewErrorDiagnostic(
					"Failed to read: 403 Forbidden",
					scopes.GenerateScopeDescription(testScopes),
				),
			},
		},
		{
			name:      "not found error with custom detail",
			err:       host_group.NewGetHostGroupsNotFound(),
			operation: Read,
			options:   []ErrorOption{WithNotFoundDetail("Custom not found message")},
			wantDiags: diag.Diagnostics{
				NewNotFoundError("Custom not found message"),
			},
		},
		{
			name:      "not found error with default detail",
			err:       host_group.NewGetHostGroupsNotFound(),
			operation: Read,
			wantDiags: diag.Diagnostics{
				NewNotFoundError(host_group.NewGetHostGroupsNotFound().Error()),
			},
		},
		{
			name:      "conflict error with custom detail",
			err:       d4c_registration.NewCreateDiscoverCloudAzureAccountConflict(),
			operation: Create,
			options:   []ErrorOption{WithConflictDetail("Custom conflict message")},
			wantDiags: diag.Diagnostics{
				NewConflictError(Create, "Custom conflict message"),
			},
		},
		{
			name:      "conflict error with default detail",
			err:       d4c_registration.NewCreateDiscoverCloudAzureAccountConflict(),
			operation: Create,
			wantDiags: diag.Diagnostics{
				NewConflictError(Create, d4c_registration.NewCreateDiscoverCloudAzureAccountConflict().Error()),
			},
		},
		{
			name:      "server error",
			err:       host_group.NewGetHostGroupsInternalServerError(),
			operation: Update,
			wantDiags: diag.Diagnostics{
				diag.NewErrorDiagnostic(
					"Failed to update",
					host_group.NewGetHostGroupsInternalServerError().Error(),
				),
			},
		},
		{
			name:      "standard go error",
			err:       errors.New("standard go error"),
			operation: Read,
			wantDiags: diag.Diagnostics{
				diag.NewErrorDiagnostic(
					"Failed to read",
					"standard go error",
				),
			},
		},
		{
			name:      "multiple options uses relevant one",
			err:       d4c_registration.NewCreateDiscoverCloudAzureAccountConflict(),
			operation: Create,
			options: []ErrorOption{
				WithNotFoundDetail("Not found detail"),
				WithConflictDetail("Conflict detail"),
			},
			wantDiags: diag.Diagnostics{
				NewConflictError(Create, "Conflict detail"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDiags := HandleAPIError(tt.operation, tt.err, testScopes, tt.options...)
			assert.Equal(t, tt.wantDiags, gotDiags)
		})
	}
}
