package sensorvisibilityexclusion

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_visibility_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

func getSensorVisibilityExclusion(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	exclusionID string,
) (*models.SvExclusionsSVExclusionV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := sensor_visibility_exclusions.NewGetSensorVisibilityExclusionsV1ParamsWithContext(ctx)
	params.SetIds([]string{exclusionID})

	tflog.Debug(ctx, "Calling CrowdStrike API to get sensor visibility exclusion", map[string]any{
		"exclusion_id": exclusionID,
	})

	getResp, err := client.SensorVisibilityExclusions.GetSensorVisibilityExclusionsV1(params)
	if err != nil {
		if strings.Contains(err.Error(), "status 404") {
			diags.Append(
				tferrors.NewNotFoundError(
					fmt.Sprintf("Sensor visibility exclusion with ID %s was not found.", exclusionID),
				),
			)
			return nil, diags
		}
		diags.Append(tferrors.NewOperationError(tferrors.Read, err))
		return nil, diags
	}

	if getResp == nil || getResp.Payload == nil || len(getResp.Payload.Resources) == 0 {
		diags.Append(
			tferrors.NewNotFoundError(
				fmt.Sprintf("Sensor visibility exclusion with ID %s was not found.", exclusionID),
			),
		)
		return nil, diags
	}

	return getResp.Payload.Resources[0], diags
}
