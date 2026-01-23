package tferrors

import (
	"github.com/hashicorp/terraform-plugin-framework/diag"
)

func NewResourceNotFoundWarningDiagnostic() diag.Diagnostic {
	return diag.NewWarningDiagnostic(
		"CrowdStrike resource not found during refresh",
		"Automatically removing from Terraform State instead of returning the error, which may trigger resource recreation. This usually indicates the remote resource was deleted outside of Terraform.",
	)
}
