package sensorupdatepolicy

import (
	"strings"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/hashicorp/terraform-plugin-framework/diag"
)

const notFoundErrorSummary = "Sensor Update Policy not found"

func newNotFoundError(detail string) diag.ErrorDiagnostic {
	return diag.NewErrorDiagnostic(notFoundErrorSummary, detail)
}

const invalidBuildPrefix = "invalid build"

func newAPIError(
	operation tferrors.Operation,
	err error,
	apiScopes []scopes.Scope,
) diag.Diagnostic {
	var opts []tferrors.ErrorOption
	if err != nil && strings.Contains(strings.ToLower(err.Error()), invalidBuildPrefix) {
		opts = append(opts, tferrors.WithBadRequestDetail("The build value may be incorrect or no longer supported by the CrowdStrike API. Use the crowdstrike_sensor_update_policy_builds data source to find valid build values for your platform."))
	}
	return tferrors.NewDiagnosticFromAPIError(operation, err, apiScopes, opts...)
}
