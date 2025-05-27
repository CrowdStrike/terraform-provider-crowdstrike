package fcs

import "github.com/hashicorp/terraform-plugin-framework/diag"

const notFoundErrorSummary = "Registration not found."

func newNotFoundError(detail string) diag.ErrorDiagnostic {
	return diag.NewErrorDiagnostic(notFoundErrorSummary, detail)
}
