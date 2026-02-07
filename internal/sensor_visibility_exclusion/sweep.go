package sensorvisibilityexclusion

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_visibility_exclusions"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_sensor_visibility_exclusion", sweepSensorVisibilityExclusions)
}

func sweepSensorVisibilityExclusions(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	params := sensor_visibility_exclusions.NewQuerySensorVisibilityExclusionsV1Params()
	params.WithContext(ctx)

	resp, err := client.SensorVisibilityExclusions.QuerySensorVisibilityExclusionsV1(params)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping Sensor Visibility Exclusion sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing sensor visibility exclusions: %w", err)
	}

	if resp.Payload == nil || resp.Payload.Resources == nil {
		return sweepables, nil
	}

	ids := resp.Payload.Resources

	if len(ids) == 0 {
		return sweepables, nil
	}

	getParams := sensor_visibility_exclusions.NewGetSensorVisibilityExclusionsV1Params()
	getParams.WithContext(ctx)
	getParams.Ids = ids

	getResp, err := client.SensorVisibilityExclusions.GetSensorVisibilityExclusionsV1(getParams)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping Sensor Visibility Exclusion sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error getting sensor visibility exclusions: %w", err)
	}

	if getResp.Payload == nil || getResp.Payload.Resources == nil {
		return sweepables, nil
	}

	for _, exclusion := range getResp.Payload.Resources {
		if exclusion.Value == nil {
			continue
		}
		name := *exclusion.Value

		if !strings.HasPrefix(name, sweep.ResourcePrefix) {
			sweep.Trace("Skipping Sensor Visibility Exclusion %s (not a test resource)", name)
			continue
		}

		if exclusion.ID == nil {
			continue
		}
		id := *exclusion.ID

		sweepables = append(sweepables, sweep.NewSweepResource(
			id,
			name,
			deleteSensorVisibilityExclusion,
		))
	}

	return sweepables, nil
}

func deleteSensorVisibilityExclusion(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	params := sensor_visibility_exclusions.NewDeleteSensorVisibilityExclusionsV1Params()
	params.WithContext(ctx)
	params.Ids = []string{id}

	_, err := client.SensorVisibilityExclusions.DeleteSensorVisibilityExclusionsV1(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for sensor visibility exclusion %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}
