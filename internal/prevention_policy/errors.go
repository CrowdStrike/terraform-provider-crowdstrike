package preventionpolicy

import (
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/hashicorp/terraform-plugin-framework/diag"
)

const notFoundErrorSummary = tferrors.NotFoundErrorSummary

func newNotFoundError(detail string) diag.ErrorDiagnostic {
	return tferrors.NewNotFoundError(detail)
}
