package rtrputfile

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response_admin"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_rtr_put_file", sweepRtrPutFiles)
}

func sweepRtrPutFiles(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	// RTR put files list endpoint does not support FQL substring filters,
	// so we list all files and filter client-side.
	params := real_time_response_admin.NewRTRListPutFilesParamsWithContext(ctx)

	listResp, err := client.RealTimeResponseAdmin.RTRListPutFiles(params)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping RTR put file sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing RTR put files: %w", err)
	}
	if listResp == nil || listResp.Payload == nil || len(listResp.Payload.Resources) == 0 {
		return sweepables, nil
	}

	getParams := real_time_response_admin.NewRTRGetPutFilesV2ParamsWithContext(ctx).
		WithIds(listResp.Payload.Resources)

	getResp, err := client.RealTimeResponseAdmin.RTRGetPutFilesV2(getParams)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping RTR put file sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error getting RTR put files: %w", err)
	}
	if getResp == nil || getResp.Payload == nil {
		return sweepables, nil
	}

	for _, file := range getResp.Payload.Resources {
		if file == nil || file.ID == "" {
			continue
		}

		if !strings.Contains(file.Name, sweep.ResourcePrefix) {
			sweep.Trace("Skipping RTR put file %s (not a test resource)", file.Name)
			continue
		}

		sweepables = append(sweepables, sweep.NewSweepResource(
			file.ID,
			file.Name,
			deleteRtrPutFile,
		))
	}

	return sweepables, nil
}

func deleteRtrPutFile(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	id string,
) error {
	params := real_time_response_admin.NewRTRDeletePutFilesParamsWithContext(ctx).
		WithIds(id)

	_, err := client.RealTimeResponseAdmin.RTRDeletePutFiles(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for RTR put file %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}
