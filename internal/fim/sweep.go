package fim

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/filevantage"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_filevantage_rule_group", sweepFilevantageRuleGroups)
	sweep.Register("crowdstrike_filevantage_policy", sweepFilevantagePolicies)
}

func sweepFilevantageRuleGroups(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable
	var allIDs []string

	ruleGroupTypes := []string{"WindowsFiles", "WindowsRegistry", "LinuxFiles", "MacFiles"}

	for _, rgType := range ruleGroupTypes {
		params := filevantage.NewQueryRuleGroupsParams()
		params.WithContext(ctx)
		params.Type = rgType

		resp, err := client.Filevantage.QueryRuleGroups(params)
		if sweep.SkipSweepError(err) {
			sweep.Warn("Skipping FileVantage Rule Group sweep for type %s: %s", rgType, err)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("error listing filevantage rule groups for type %s: %w", rgType, err)
		}

		if resp.Payload == nil || resp.Payload.Resources == nil {
			continue
		}

		allIDs = append(allIDs, resp.Payload.Resources...)
	}

	if len(allIDs) == 0 {
		return sweepables, nil
	}

	getParams := filevantage.NewGetRuleGroupsParams()
	getParams.WithContext(ctx)
	getParams.Ids = allIDs

	getResp, err := client.Filevantage.GetRuleGroups(getParams)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping FileVantage Rule Group sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error getting filevantage rule groups: %w", err)
	}

	if getResp.Payload == nil || getResp.Payload.Resources == nil {
		return sweepables, nil
	}

	for _, ruleGroup := range getResp.Payload.Resources {
		name := ruleGroup.Name

		if name == "" {
			continue
		}

		if !strings.HasPrefix(name, sweep.ResourcePrefix) {
			sweep.Trace("Skipping FileVantage Rule Group %s (not a test resource)", name)
			continue
		}

		if ruleGroup.ID == nil {
			continue
		}
		id := *ruleGroup.ID

		sweepables = append(sweepables, sweep.NewSweepResource(
			id,
			name,
			deleteFilevantageRuleGroup,
		))
	}

	return sweepables, nil
}

func deleteFilevantageRuleGroup(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	params := filevantage.NewDeleteRuleGroupsParams()
	params.WithContext(ctx)
	params.Ids = []string{id}

	_, err := client.Filevantage.DeleteRuleGroups(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for FileVantage rule group %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}

func sweepFilevantagePolicies(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable
	var allIDs []string

	policyTypes := []string{"Windows", "Linux", "Mac"}

	for _, policyType := range policyTypes {
		params := filevantage.NewQueryPoliciesParams()
		params.WithContext(ctx)
		params.Type = policyType
		params.Limit = utils.Addr(int64(500))

		resp, err := client.Filevantage.QueryPolicies(params)
		if sweep.SkipSweepError(err) {
			sweep.Warn("Skipping FileVantage Policy sweep for type %s: %s", policyType, err)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("error listing filevantage policies for type %s: %w", policyType, err)
		}

		if resp.Payload == nil || resp.Payload.Resources == nil {
			continue
		}

		allIDs = append(allIDs, resp.Payload.Resources...)
	}

	if len(allIDs) == 0 {
		return sweepables, nil
	}

	getParams := filevantage.NewGetPoliciesParams()
	getParams.WithContext(ctx)
	getParams.Ids = allIDs

	getResp, err := client.Filevantage.GetPolicies(getParams)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping FileVantage Policy sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error getting filevantage policies: %w", err)
	}

	if getResp.Payload == nil || getResp.Payload.Resources == nil {
		return sweepables, nil
	}

	for _, policy := range getResp.Payload.Resources {
		name := policy.Name

		if name == "" {
			continue
		}

		if !strings.HasPrefix(name, sweep.ResourcePrefix) {
			sweep.Trace("Skipping FileVantage Policy %s (not a test resource)", name)
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
			makeSweepDeleteFilevantagePolicy(isEnabled, name),
		))
	}

	return sweepables, nil
}

func makeSweepDeleteFilevantagePolicy(isEnabled bool, name string) func(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	return func(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
		if isEnabled {
			if err := sweepDisableFilevantagePolicy(ctx, client, id, name); err != nil {
				return err
			}
		}
		return sweepDeleteFilevantagePolicy(ctx, client, id)
	}
}

func sweepDisableFilevantagePolicy(ctx context.Context, client *client.CrowdStrikeAPISpecification, id, name string) error {
	params := filevantage.NewUpdatePoliciesParams()
	params.WithContext(ctx)
	params.Body = &models.PoliciesUpdateRequest{
		ID:      &id,
		Name:    name,
		Enabled: false,
	}

	_, err := client.Filevantage.UpdatePolicies(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for FileVantage policy %s: %s", id, err)
			return nil
		}
		return err
	}

	sweep.Info("Successfully disabled filevantage policy: %s", id)
	return nil
}

func sweepDeleteFilevantagePolicy(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	params := filevantage.NewDeletePoliciesParams()
	params.WithContext(ctx)
	params.Ids = []string{id}

	_, err := client.Filevantage.DeletePolicies(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for FileVantage policy %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}
