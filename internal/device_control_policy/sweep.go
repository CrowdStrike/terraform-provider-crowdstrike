package devicecontrolpolicy

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/device_control_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_device_control_policy", sweepDeviceControlPolicy)
}

func sweepDeviceControlPolicy(ctx context.Context, c *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	filter := fmt.Sprintf("name:~'%s'", sweep.ResourcePrefix)
	res, err := c.DeviceControlPolicies.QueryCombinedDeviceControlPolicies(
		&device_control_policies.QueryCombinedDeviceControlPoliciesParams{
			Context: ctx,
			Filter:  &filter,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query device control policies: %w", err)
	}

	if res == nil || res.Payload == nil {
		return sweepables, nil
	}

	for _, policy := range res.Payload.Resources {
		if policy == nil || policy.ID == nil || policy.Name == nil {
			continue
		}
		sweepables = append(sweepables, sweep.NewSweepResource(
			*policy.ID,
			*policy.Name,
			deleteDeviceControlPolicy,
		))
	}

	return sweepables, nil
}

func deleteDeviceControlPolicy(ctx context.Context, c *client.CrowdStrikeAPISpecification, id string) error {
	// Disable before deleting
	_, _ = c.DeviceControlPolicies.PerformDeviceControlPoliciesAction(
		&device_control_policies.PerformDeviceControlPoliciesActionParams{
			Context:    ctx,
			ActionName: "disable",
			Body: &models.MsaEntityActionRequestV2{
				Ids: []string{id},
			},
		},
	)

	_, err := c.DeviceControlPolicies.DeleteDeviceControlPolicies(
		&device_control_policies.DeleteDeviceControlPoliciesParams{
			Context: ctx,
			Ids:     []string{id},
		},
	)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			return nil
		}
		return err
	}

	return nil
}
