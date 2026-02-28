package mlexclusion

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ml_exclusions"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_ml_exclusion", sweepMLExclusions)
}

func sweepMLExclusions(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	queryParams := ml_exclusions.NewQueryMLExclusionsV1Params()
	queryParams.WithContext(ctx)

	queryResp, err := client.MlExclusions.QueryMLExclusionsV1(queryParams)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping ML exclusion sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing ml exclusions: %w", err)
	}

	if queryResp == nil || queryResp.Payload == nil || queryResp.Payload.Resources == nil {
		return sweepables, nil
	}

	ids := queryResp.Payload.Resources
	if len(ids) == 0 {
		return sweepables, nil
	}

	getParams := ml_exclusions.NewGetMLExclusionsV1Params()
	getParams.WithContext(ctx)
	getParams.SetIds(ids)

	getResp, err := client.MlExclusions.GetMLExclusionsV1(getParams)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping ML exclusion sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error getting ml exclusions: %w", err)
	}

	if getResp == nil || getResp.Payload == nil || getResp.Payload.Resources == nil {
		return sweepables, nil
	}

	for _, exclusion := range getResp.Payload.Resources {
		if exclusion == nil || exclusion.Value == nil || exclusion.ID == nil {
			continue
		}

		name := *exclusion.Value
		if !strings.Contains(name, sweep.ResourcePrefix) {
			sweep.Trace("Skipping ML exclusion %s (not a test resource)", name)
			continue
		}

		sweepables = append(sweepables, sweep.NewSweepResource(
			*exclusion.ID,
			name,
			deleteMLExclusion,
		))
	}

	return sweepables, nil
}

func deleteMLExclusion(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	id string,
) error {
	params := ml_exclusions.NewDeleteMLExclusionsV1Params()
	params.WithContext(ctx)
	params.SetIds([]string{id})
	comment := "deleted by test sweeper"
	params.SetComment(&comment)

	_, err := client.MlExclusions.DeleteMLExclusionsV1(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for ml exclusion %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}
