package correlationrules

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/correlation_rules"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_correlation_rule", sweepCorrelationRules)
}

func sweepCorrelationRules(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	var offset int64
	limit := int64(100)
	for {
		params := correlation_rules.NewCombinedRulesGetV1Params()
		params.WithContext(ctx)
		params.Offset = &offset
		params.Limit = &limit

		resp, err := client.CorrelationRules.CombinedRulesGetV1(params)
		if sweep.SkipSweepError(err) {
			sweep.Warn("Skipping Correlation Rule sweep: %s", err)
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("error listing correlation rules: %w", err)
		}

		if resp.Payload == nil || len(resp.Payload.Resources) == 0 {
			break
		}

		for _, rule := range resp.Payload.Resources {
			if rule.Name == nil {
				continue
			}
			name := *rule.Name

			if !strings.HasPrefix(name, sweep.ResourcePrefix) {
				sweep.Trace("Skipping Correlation Rule %s (not a test resource)", name)
				continue
			}

			id := rule.RuleID
			if id == "" && rule.ID != nil {
				id = *rule.ID
			}
			if id == "" {
				continue
			}

			sweepables = append(sweepables, sweep.NewSweepResource(
				id,
				name,
				deleteCorrelationRule,
			))
		}

		if int64(len(resp.Payload.Resources)) < limit {
			break
		}
		offset += limit
	}

	return sweepables, nil
}

func deleteCorrelationRule(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	params := correlation_rules.NewEntitiesRulesDeleteV1Params()
	params.WithContext(ctx)
	params.Ids = []string{id}

	_, err := client.CorrelationRules.EntitiesRulesDeleteV1(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for correlation rule %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}
