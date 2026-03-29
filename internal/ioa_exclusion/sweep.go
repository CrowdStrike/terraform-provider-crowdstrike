package ioaexclusion

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ioa_exclusions"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_ioa_exclusion", sweepIOAExclusions)
}

func sweepIOAExclusions(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	params := ioa_exclusions.NewQueryIOAExclusionsV1ParamsWithContext(ctx)
	params.Filter = utils.Addr(fmt.Sprintf("name:~'%s'", sweep.ResourcePrefix))

	resp, err := client.IoaExclusions.QueryIOAExclusionsV1(params)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping IOA Exclusion sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing IOA exclusions: %w", err)
	}
	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		return sweepables, nil
	}
	if diagErr := diagnosticFromQueryPayload(tferrors.Delete, resp.Payload); diagErr != nil {
		return nil, fmt.Errorf("error listing IOA exclusions: %s", diagErr.Detail())
	}

	getParams := ioa_exclusions.NewGetIOAExclusionsV1ParamsWithContext(ctx)
	getParams.SetIds(resp.Payload.Resources)

	getResp, err := client.IoaExclusions.GetIOAExclusionsV1(getParams)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping IOA Exclusion sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error getting IOA exclusions: %w", err)
	}
	if getResp == nil || getResp.Payload == nil {
		return sweepables, nil
	}
	if diagErr := diagnosticFromIOAPayload(tferrors.Delete, getResp.Payload.Errors); diagErr != nil {
		return nil, fmt.Errorf("error getting IOA exclusions: %s", diagErr.Detail())
	}

	for _, exclusion := range getResp.Payload.Resources {
		if exclusion == nil || exclusion.ID == nil || exclusion.Name == nil {
			continue
		}

		if !strings.HasPrefix(*exclusion.Name, sweep.ResourcePrefix) {
			sweep.Trace("Skipping IOA Exclusion %s (not a test resource)", *exclusion.Name)
			continue
		}

		sweepables = append(sweepables, sweep.NewSweepResource(
			*exclusion.ID,
			*exclusion.Name,
			deleteIOAExclusion,
		))
	}

	return sweepables, nil
}

func deleteIOAExclusion(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	id string,
) error {
	params := ioa_exclusions.NewDeleteIOAExclusionsV1ParamsWithContext(ctx)
	params.SetIds([]string{id})

	resp, err := client.IoaExclusions.DeleteIOAExclusionsV1(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for IOA exclusion %s: %s", id, err)
			return nil
		}
		return err
	}

	if resp != nil {
		if diagErr := diagnosticFromQueryPayload(tferrors.Delete, resp.Payload); diagErr != nil && diagErr.Summary() != tferrors.NotFoundErrorSummary {
			return fmt.Errorf("%s", diagErr.Detail())
		}
	}

	return nil
}
