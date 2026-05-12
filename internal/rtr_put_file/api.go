package rtrputfile

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response_admin"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/hashicorp/terraform-plugin-framework/diag"
)

func getRTRPutFile(
	ctx context.Context,
	apiClient *client.CrowdStrikeAPISpecification,
	id string,
	apiScopes []scopes.Scope,
) (*models.EmpowerapiRemoteCommandPutFileV2, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := real_time_response_admin.NewRTRGetPutFilesV2ParamsWithContext(ctx).
		WithIds([]string{id})

	res, err := apiClient.RealTimeResponseAdmin.RTRGetPutFilesV2(params)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, apiScopes))
		return nil, diags
	}

	if res == nil || res.Payload == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return nil, diags
	}

	if diagErr := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diagErr != nil {
		diags.Append(diagErr)
		return nil, diags
	}

	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		diags.Append(tferrors.NewNotFoundError("RTR put file not found"))
		return nil, diags
	}

	return res.Payload.Resources[0], diags
}
