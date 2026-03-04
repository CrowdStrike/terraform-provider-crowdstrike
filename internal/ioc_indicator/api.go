package iocindicator

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ioc"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// getIOCIndicator retrieves a single IOC indicator by ID.
func getIOCIndicator(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	id string,
) (*models.APIIndicatorV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	tflog.Debug(ctx, "Calling CrowdStrike API to get IOC indicator", map[string]any{
		"indicator_id": id,
	})

	params := ioc.NewIndicatorGetV1Params().WithIds([]string{id})
	res, err := client.Ioc.IndicatorGetV1(params)

	if err != nil {
		if strings.Contains(err.Error(), "status 404") {
			diags.Append(
				tferrors.NewNotFoundError(
					fmt.Sprintf("IOC indicator with ID %s was not found.", id),
				),
			)
			return nil, diags
		}
		diags.Append(tferrors.NewOperationError(tferrors.Read, err))
		return nil, diags
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
		diags.Append(
			tferrors.NewNotFoundError(
				fmt.Sprintf("IOC indicator with ID %s was not found.", id),
			),
		)
		return nil, diags
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(
		tferrors.Read,
		res.Payload.Errors,
	); diag != nil {
		diags.Append(diag)
		return nil, diags
	}

	return res.Payload.Resources[0], diags
}
