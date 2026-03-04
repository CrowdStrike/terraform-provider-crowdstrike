package iocindicator

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ioc"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

// RegisterSweepers registers the sweepers for IOC indicator resources.
func RegisterSweepers() {
	sweep.Register("crowdstrike_ioc_indicator", sweepIOCIndicators)
}

func sweepIOCIndicators(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	params := ioc.NewIndicatorCombinedV1Params().WithDefaults()
	res, err := client.Ioc.IndicatorCombinedV1(params)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping IOC indicator sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing IOC indicators: %w", err)
	}

	if res.Payload == nil || res.Payload.Resources == nil {
		return sweepables, nil
	}

	for _, indicator := range res.Payload.Resources {
		if !strings.HasPrefix(indicator.Description, sweep.ResourcePrefix) {
			continue
		}

		sweepables = append(sweepables, sweep.NewSweepResource(
			indicator.ID,
			indicator.Value,
			deleteIOCIndicator,
		))
	}

	return sweepables, nil
}

// deleteIOCIndicator deletes an IOC indicator by ID.
func deleteIOCIndicator(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	id string,
) error {
	params := ioc.NewIndicatorDeleteV1Params().WithIds([]string{id})
	_, err := client.Ioc.IndicatorDeleteV1(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for IOC indicator %s: %s", id, err)
			return nil
		}
		return err
	}
	return nil
}
