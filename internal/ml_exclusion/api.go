package mlexclusion

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ml_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/hashicorp/terraform-plugin-framework/diag"
)

func getMLExclusion(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	exclusionID string,
) (*models.ExclusionsExclusionV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := ml_exclusions.NewGetMLExclusionsV1ParamsWithContext(ctx)
	params.SetIds([]string{exclusionID})

	getResp, err := client.MlExclusions.GetMLExclusionsV1(params)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, mlExclusionRequiredScopes))
		return nil, diags
	}

	if getResp == nil || getResp.Payload == nil {
		diags.Append(
			tferrors.NewNotFoundError(
				fmt.Sprintf("ML exclusion with ID %s was not found.", exclusionID),
			),
		)
		return nil, diags
	}

	if payloadHasErrorCode(getResp.Payload.Errors, 404) {
		diags.Append(
			tferrors.NewNotFoundError(
				fmt.Sprintf("ML exclusion with ID %s was not found.", exclusionID),
			),
		)
		return nil, diags
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, getResp.Payload.Errors); diag != nil {
		diags.Append(diag)
		return nil, diags
	}

	if len(getResp.Payload.Resources) == 0 || getResp.Payload.Resources[0] == nil {
		diags.Append(
			tferrors.NewNotFoundError(
				fmt.Sprintf("ML exclusion with ID %s was not found.", exclusionID),
			),
		)
		return nil, diags
	}

	return getResp.Payload.Resources[0], diags
}

func payloadHasErrorCode(payloadErrors []*models.MsaAPIError, expectedCode int32) bool {
	for _, payloadError := range payloadErrors {
		if payloadError == nil || payloadError.Code == nil {
			continue
		}

		if *payloadError.Code == expectedCode {
			return true
		}
	}

	return false
}
