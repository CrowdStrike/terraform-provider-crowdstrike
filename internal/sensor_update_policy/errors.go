package sensorupdatepolicy

import "github.com/hashicorp/terraform-plugin-framework/diag"

const notFoundErrorSummary = "Sensor Update Policy not found"

func newNotFoundError(detail string) diag.ErrorDiagnostic {
	return diag.NewErrorDiagnostic(notFoundErrorSummary, detail)
}
