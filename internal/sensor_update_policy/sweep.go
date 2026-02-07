package sensorupdatepolicy

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_sensor_update_policy", sweepSensorUpdatePolicies)
}

func sweepSensorUpdatePolicies(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	params := sensor_update_policies.NewQueryCombinedSensorUpdatePoliciesV2Params()
	params.WithContext(ctx)

	resp, err := client.SensorUpdatePolicies.QueryCombinedSensorUpdatePoliciesV2(params)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping Sensor Update Policy sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing sensor update policies: %w", err)
	}

	if resp.Payload == nil || resp.Payload.Resources == nil {
		return sweepables, nil
	}

	for _, policy := range resp.Payload.Resources {
		if policy.Name == nil {
			continue
		}
		name := *policy.Name

		if !strings.HasPrefix(name, sweep.ResourcePrefix) {
			sweep.Trace("Skipping Sensor Update Policy %s (not a test resource)", name)
			continue
		}

		if policy.ID == nil {
			continue
		}
		id := *policy.ID
		isEnabled := policy.Enabled != nil && *policy.Enabled

		sweepables = append(sweepables, sweep.NewSweepResource(
			id,
			name,
			makeSweepDeleteSensorUpdatePolicy(isEnabled),
		))
	}

	return sweepables, nil
}

func makeSweepDeleteSensorUpdatePolicy(isEnabled bool) func(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	return func(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
		if isEnabled {
			if err := sweepDisableSensorUpdatePolicy(ctx, client, id); err != nil {
				return err
			}
		}
		return sweepDeleteSensorUpdatePolicy(ctx, client, id)
	}
}

func sweepDisableSensorUpdatePolicy(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	params := sensor_update_policies.NewPerformSensorUpdatePoliciesActionParams()
	params.WithContext(ctx)
	params.ActionName = "disable"
	params.Body = &models.MsaEntityActionRequestV2{
		Ids: []string{id},
	}

	_, err := client.SensorUpdatePolicies.PerformSensorUpdatePoliciesAction(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for sensor update policy %s: %s", id, err)
			return nil
		}
		return err
	}

	sweep.Info("Successfully disabled sensor update policy: %s", id)
	return nil
}

func sweepDeleteSensorUpdatePolicy(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	params := sensor_update_policies.NewDeleteSensorUpdatePoliciesParams()
	params.WithContext(ctx)
	params.Ids = []string{id}

	_, err := client.SensorUpdatePolicies.DeleteSensorUpdatePolicies(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for sensor update policy %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}
