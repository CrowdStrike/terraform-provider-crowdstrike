package certificatebasedexclusion

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/certificate_based_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/hashicorp/terraform-plugin-framework/diag"
)

func getCertificateBasedExclusion(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	exclusionID string,
) (*models.APICertBasedExclusionV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := certificate_based_exclusions.NewCbExclusionsGetV1ParamsWithContext(ctx)
	params.SetIds([]string{exclusionID})

	res, err := client.CertificateBasedExclusions.CbExclusionsGetV1(params)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Read,
			err,
			certificateBasedExclusionRequiredScopes,
			tferrors.WithNotFoundDetail(fmt.Sprintf("Certificate based exclusion with ID %s was not found.", exclusionID)),
		))
		return nil, diags
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		diags.Append(tferrors.NewNotFoundError(
			fmt.Sprintf("Certificate based exclusion with ID %s was not found.", exclusionID),
		))
		return nil, diags
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diag != nil {
		diags.Append(diag)
		return nil, diags
	}

	return res.Payload.Resources[0], diags
}
