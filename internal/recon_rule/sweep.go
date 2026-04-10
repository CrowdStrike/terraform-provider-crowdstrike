package reconrule

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/recon"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_recon_rule", sweepReconRules)
}

func sweepReconRules(ctx context.Context, apiClient *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	queryParams := recon.NewQueryRulesV1ParamsWithContext(ctx)

	resp, err := apiClient.Recon.QueryRulesV1(queryParams)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing recon rules: %w", err)
	}

	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		return sweepables, nil
	}

	getParams := recon.NewGetRulesV1ParamsWithContext(ctx)
	getParams.SetIds(resp.Payload.Resources)

	getResp, err := apiClient.Recon.GetRulesV1(getParams)
	if err != nil {
		if sweep.SkipSweepError(err) {
			sweep.Warn("Skipping sweep: %s", err)
			return nil, nil
		}
		return nil, fmt.Errorf("error getting recon rules: %w", err)
	}

	if getResp == nil || getResp.Payload == nil || len(getResp.Payload.Resources) == 0 {
		return sweepables, nil
	}

	for _, rule := range getResp.Payload.Resources {
		if rule.Name == nil || rule.ID == nil {
			continue
		}

		if !strings.HasPrefix(*rule.Name, sweep.ResourcePrefix) {
			sweep.Trace("Skipping %s (not a test resource)", *rule.Name)
			continue
		}

		sweepables = append(sweepables, sweep.NewSweepResource(
			*rule.ID,
			*rule.Name,
			deleteReconRule,
		))
	}

	return sweepables, nil
}

func deleteReconRule(ctx context.Context, apiClient *client.CrowdStrikeAPISpecification, id string) error {
	params := recon.NewDeleteRulesV1ParamsWithContext(ctx)
	params.SetIds([]string{id})

	_, err := apiClient.Recon.DeleteRulesV1(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for recon rule %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}
