package selfserviceioaexclusion

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
	sweep.Register("crowdstrike_self_service_ioa_exclusion", sweepSelfServiceIOAExclusions)
}

func sweepSelfServiceIOAExclusions(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	params := ioa_exclusions.NewSsIoaExclusionsSearchV2ParamsWithContext(ctx)
	params.Filter = utils.Addr(fmt.Sprintf("name:~'%s'", sweep.ResourcePrefix))

	resp, err := client.IoaExclusions.SsIoaExclusionsSearchV2(params)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping Self Service IOA Exclusion sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing self-service IOA exclusions: %w", err)
	}
	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		return sweepables, nil
	}
	if diagErr := diagnosticFromSelfServiceIOAQueryPayload(tferrors.Delete, resp.Payload); diagErr != nil {
		return nil, fmt.Errorf("error listing self-service IOA exclusions: %s", diagErr.Detail())
	}

	getParams := ioa_exclusions.NewSsIoaExclusionsGetV2ParamsWithContext(ctx)
	getParams.SetIds(resp.Payload.Resources)

	getResp, err := client.IoaExclusions.SsIoaExclusionsGetV2(getParams)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping Self Service IOA Exclusion sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error getting self-service IOA exclusions: %w", err)
	}
	if getResp == nil || getResp.Payload == nil {
		return sweepables, nil
	}
	if diagErr := diagnosticFromSelfServiceIOAPayload(tferrors.Delete, getResp.Payload.Errors); diagErr != nil {
		return nil, fmt.Errorf("error getting self-service IOA exclusions: %s", diagErr.Detail())
	}

	for _, exclusion := range getResp.Payload.Resources {
		if exclusion == nil || exclusion.ID == nil {
			continue
		}

		if !strings.HasPrefix(exclusion.Name, sweep.ResourcePrefix) {
			sweep.Trace("Skipping Self Service IOA Exclusion %s (not a test resource)", exclusion.Name)
			continue
		}

		sweepables = append(sweepables, sweep.NewSweepResource(
			*exclusion.ID,
			exclusion.Name,
			deleteSelfServiceIOAExclusion,
		))
	}

	return sweepables, nil
}

func deleteSelfServiceIOAExclusion(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	id string,
) error {
	params := ioa_exclusions.NewSsIoaExclusionsDeleteV2ParamsWithContext(ctx)
	params.SetIds([]string{id})
	params.SetComment(utils.Addr("deleted by Terraform acceptance test sweeper"))

	resp, err := client.IoaExclusions.SsIoaExclusionsDeleteV2(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for self-service IOA exclusion %s: %s", id, err)
			return nil
		}
		return err
	}

	if resp != nil && resp.Payload != nil {
		if diagErr := diagnosticFromSelfServiceIOAPayload(tferrors.Delete, resp.Payload.Errors); diagErr != nil && diagErr.Summary() != tferrors.NotFoundErrorSummary {
			return fmt.Errorf("%s", diagErr.Detail())
		}
	}

	return nil
}
