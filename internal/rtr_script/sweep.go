package rtrscript

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response_admin"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_rtr_script", sweepRTRScripts)
}

func sweepRTRScripts(
	ctx context.Context,
	apiClient *client.CrowdStrikeAPISpecification,
) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	listParams := real_time_response_admin.NewRTRListScriptsParamsWithContext(ctx)

	listResp, err := apiClient.RealTimeResponseAdmin.RTRListScripts(listParams)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping RTR script sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing RTR scripts: %w", err)
	}
	if listResp == nil || listResp.Payload == nil || len(listResp.Payload.Resources) == 0 {
		return sweepables, nil
	}

	getParams := real_time_response_admin.NewRTRGetScriptsV2ParamsWithContext(ctx)
	getParams.SetIds(listResp.Payload.Resources)

	getResp, err := apiClient.RealTimeResponseAdmin.RTRGetScriptsV2(getParams)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping RTR script sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error getting RTR scripts: %w", err)
	}
	if getResp == nil || getResp.Payload == nil {
		return sweepables, nil
	}

	for _, script := range getResp.Payload.Resources {
		if script == nil || script.ID == "" || script.Name == "" {
			continue
		}

		if !strings.HasPrefix(script.Name, sweep.ResourcePrefix) {
			sweep.Trace("Skipping RTR script %s (not a test resource)", script.Name)
			continue
		}

		sweepables = append(sweepables, sweep.NewSweepResource(
			script.ID,
			script.Name,
			deleteRTRScript,
		))
	}

	return sweepables, nil
}

func deleteRTRScript(
	ctx context.Context,
	apiClient *client.CrowdStrikeAPISpecification,
	id string,
) error {
	params := real_time_response_admin.NewRTRDeleteScriptsParamsWithContext(ctx)
	params.SetIds(id)

	_, err := apiClient.RealTimeResponseAdmin.RTRDeleteScripts(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for RTR script %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}
