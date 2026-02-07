package contentupdatepolicy

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/response_policies"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_content_update_policy", sweepContentUpdatePolicies)
}

func sweepContentUpdatePolicies(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	params := response_policies.NewQueryCombinedRTResponsePoliciesParams()
	params.WithContext(ctx)

	resp, err := client.ResponsePolicies.QueryCombinedRTResponsePolicies(params)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping Content Update Policy sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing content update policies: %w", err)
	}

	if resp == nil || resp.Payload == nil || resp.Payload.Resources == nil {
		return sweepables, nil
	}

	for _, policy := range resp.Payload.Resources {
		if policy.Name == nil {
			continue
		}
		name := *policy.Name

		if !strings.HasPrefix(name, sweep.ResourcePrefix) {
			sweep.Trace("Skipping Content Update Policy %s (not a test resource)", name)
			continue
		}

		if policy.ID == nil {
			continue
		}
		id := *policy.ID

		sweepables = append(sweepables, sweep.NewSweepResource(
			id,
			name,
			deleteContentUpdatePolicy,
		))
	}

	return sweepables, nil
}

func deleteContentUpdatePolicy(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	params := response_policies.NewDeleteRTResponsePoliciesParams()
	params.WithContext(ctx)
	params.Ids = []string{id}

	_, err := client.ResponsePolicies.DeleteRTResponsePolicies(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for content update policy %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}
