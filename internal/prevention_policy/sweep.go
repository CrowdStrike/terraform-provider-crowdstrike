package preventionpolicy

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/prevention_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_prevention_policy", sweepPreventionPolicies)
}

func sweepPreventionPolicies(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	params := prevention_policies.NewQueryCombinedPreventionPoliciesParams()
	params.WithContext(ctx)

	resp, err := client.PreventionPolicies.QueryCombinedPreventionPolicies(params)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping Prevention Policy sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing prevention policies: %w", err)
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
			sweep.Trace("Skipping Prevention Policy %s (not a test resource)", name)
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
			makeSweepDeletePreventionPolicy(isEnabled),
		))
	}

	return sweepables, nil
}

func makeSweepDeletePreventionPolicy(isEnabled bool) func(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	return func(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
		if isEnabled {
			if err := sweepDisablePreventionPolicy(ctx, client, id); err != nil {
				return err
			}
		}
		return sweepDeletePreventionPolicy(ctx, client, id)
	}
}

func sweepDisablePreventionPolicy(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	params := prevention_policies.NewPerformPreventionPoliciesActionParams()
	params.WithContext(ctx)
	params.ActionName = "disable"
	params.Body = &models.MsaEntityActionRequestV2{
		Ids: []string{id},
	}

	_, err := client.PreventionPolicies.PerformPreventionPoliciesAction(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for prevention policy %s: %s", id, err)
			return nil
		}
		return err
	}

	sweep.Info("Successfully disabled prevention policy: %s", id)
	return nil
}

func sweepDeletePreventionPolicy(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	params := prevention_policies.NewDeletePreventionPoliciesParams()
	params.WithContext(ctx)
	params.Ids = []string{id}

	_, err := client.PreventionPolicies.DeletePreventionPolicies(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for prevention policy %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}
