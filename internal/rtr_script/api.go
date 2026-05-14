package rtrscript

import (
	"context"
	"fmt"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response_admin"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/retry"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/hashicorp/terraform-plugin-framework/diag"
)

const contentNotRetrieved = "<COULD NOT RETRIEVE>"

func getRTRScript(
	ctx context.Context,
	apiClient *client.CrowdStrikeAPISpecification,
	id string,
	apiScopes []scopes.Scope,
) (*models.EmpowerapiRemoteCommandPutFileV2, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := real_time_response_admin.NewRTRGetScriptsV2ParamsWithContext(ctx)
	params.SetIds([]string{id})

	res, err := apiClient.RealTimeResponseAdmin.RTRGetScriptsV2(params)
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
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return nil, diags
	}

	return res.Payload.Resources[0], diags
}

func getRTRScriptWithContent(
	ctx context.Context,
	apiClient *client.CrowdStrikeAPISpecification,
	id string,
	apiScopes []scopes.Scope,
) (*models.EmpowerapiRemoteCommandPutFileV2, diag.Diagnostics) {
	var script *models.EmpowerapiRemoteCommandPutFileV2
	var readDiags diag.Diagnostics

	err := retry.RetryUntilNoError(ctx, 30*time.Second, 5*time.Second, func() error {
		script, readDiags = getRTRScript(ctx, apiClient, id, apiScopes)
		if readDiags.HasError() {
			return nil
		}
		if script.Content == contentNotRetrieved {
			return fmt.Errorf("content not yet available")
		}
		return nil
	})

	if err != nil && !readDiags.HasError() {
		readDiags.AddError(
			"Error reading RTR script...",
			"The API returned a placeholder for the script content. This is typically a temporary condition. Please try again.",
		)
	}

	return script, readDiags
}
