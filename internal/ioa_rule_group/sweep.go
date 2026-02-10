package ioarulegroup

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/custom_ioa"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_ioa_rule_group", sweepIOARuleGroups)
}

func sweepIOARuleGroups(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	params := custom_ioa.NewQueryRuleGroupsMixin0Params()
	params.WithContext(ctx)

	resp, err := client.CustomIoa.QueryRuleGroupsMixin0(params)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping IOA Rule Group sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing IOA rule groups: %w", err)
	}

	if resp.Payload == nil || resp.Payload.Resources == nil {
		return sweepables, nil
	}

	ids := resp.Payload.Resources

	if len(ids) == 0 {
		return sweepables, nil
	}

	getParams := custom_ioa.NewGetRuleGroupsMixin0Params()
	getParams.WithContext(ctx)
	getParams.Ids = ids

	getResp, err := client.CustomIoa.GetRuleGroupsMixin0(getParams)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping IOA Rule Group sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error getting IOA rule groups: %w", err)
	}

	if getResp.Payload == nil || getResp.Payload.Resources == nil {
		return sweepables, nil
	}

	for _, ruleGroup := range getResp.Payload.Resources {
		if ruleGroup.Name == nil {
			continue
		}
		name := *ruleGroup.Name

		if !strings.HasPrefix(name, sweep.ResourcePrefix) {
			sweep.Trace("Skipping IOA Rule Group %s (not a test resource)", name)
			continue
		}

		if ruleGroup.ID == nil {
			continue
		}
		id := *ruleGroup.ID

		sweepables = append(sweepables, sweep.NewSweepResource(
			id,
			name,
			deleteIOARuleGroup,
		))
	}

	return sweepables, nil
}

func deleteIOARuleGroup(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	params := custom_ioa.NewDeleteRuleGroupsMixin0Params()
	params.WithContext(ctx)
	params.Ids = []string{id}

	_, err := client.CustomIoa.DeleteRuleGroupsMixin0(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for IOA rule group %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}
