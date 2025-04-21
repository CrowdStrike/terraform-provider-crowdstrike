package preventionpolicy

import "github.com/hashicorp/terraform-plugin-framework/diag"

const notFoundErrorSummary = "Prevention Policy not found"

func newNotFoundError(detail string) diag.ErrorDiagnostic {
	return diag.NewErrorDiagnostic(notFoundErrorSummary, detail)
}
