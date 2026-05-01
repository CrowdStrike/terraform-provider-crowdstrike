package firewall

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/firewall_management"
	"github.com/crowdstrike/gofalcon/falcon/client/firewall_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
	"github.com/go-openapi/swag"
)

// RegisterSweepers registers all firewall resource sweepers.
func RegisterSweepers() {
	// Register policy sweeper first (depends on rule groups)
	sweep.Register("crowdstrike_firewall_policy", sweepFirewallPolicies,
		"crowdstrike_firewall_rule_group")

	// Register rule group sweeper
	sweep.Register("crowdstrike_firewall_rule_group", sweepFirewallRuleGroups)
}

func sweepFirewallRuleGroups(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	params := firewall_management.NewQueryRuleGroupsParams().WithContext(ctx)
	resp, err := client.FirewallManagement.QueryRuleGroups(params)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping Firewall Rule Group sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing firewall rule groups: %w", err)
	}

	if resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		return sweepables, nil
	}

	getParams := firewall_management.NewGetRuleGroupsParams().
		WithContext(ctx).
		WithIds(resp.Payload.Resources)

	getResp, err := client.FirewallManagement.GetRuleGroups(getParams)
	if err != nil {
		return nil, fmt.Errorf("error getting firewall rule groups: %w", err)
	}

	if getResp.Payload == nil {
		return sweepables, nil
	}

	for _, rg := range getResp.Payload.Resources {
		if rg.Name == nil {
			continue
		}
		name := *rg.Name

		if !strings.HasPrefix(name, sweep.ResourcePrefix) {
			sweep.Trace("Skipping Firewall Rule Group %s (not a test resource)", name)
			continue
		}

		if rg.ID == nil {
			continue
		}
		id := *rg.ID

		sweepables = append(sweepables, sweep.NewSweepResource(
			id,
			name,
			deleteFirewallRuleGroup,
		))
	}

	return sweepables, nil
}

func deleteFirewallRuleGroup(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	// First, get the rule group to check if it needs to be disabled
	getParams := firewall_management.NewGetRuleGroupsParams().
		WithContext(ctx).
		WithIds([]string{id})

	getResp, err := client.FirewallManagement.GetRuleGroups(getParams)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for firewall rule group %s: %s", id, err)
			return nil
		}
		return err
	}

	// Disable before deleting if enabled
	if getResp.Payload != nil && len(getResp.Payload.Resources) > 0 {
		rg := getResp.Payload.Resources[0]
		if rg.Enabled != nil && *rg.Enabled {
			disableReq := &models.FwmgrAPIRuleGroupModifyRequestV1{
				ID:       swag.String(id),
				Tracking: rg.Tracking,
				DiffType: swag.String("application/json-patch+json"),
				DiffOperations: []*models.FwmgrAPIJSONDiff{
					{
						Op:    swag.String("replace"),
						Path:  swag.String("/enabled"),
						Value: false,
					},
				},
				RuleIds:      rg.RuleIds,
				RuleVersions: make([]int64, len(rg.RuleIds)),
			}

			disableParams := firewall_management.NewUpdateRuleGroupParams().
				WithContext(ctx).
				WithBody(disableReq)

			_, err := client.FirewallManagement.UpdateRuleGroup(disableParams)
			if err != nil {
				sweep.Debug("Error disabling firewall rule group %s: %s", id, err)
			}
		}
	}

	params := firewall_management.NewDeleteRuleGroupsParams().
		WithContext(ctx).
		WithIds([]string{id})

	_, err = client.FirewallManagement.DeleteRuleGroups(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for firewall rule group %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}

func sweepFirewallPolicies(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	params := firewall_policies.NewQueryCombinedFirewallPoliciesParams().WithContext(ctx)
	resp, err := client.FirewallPolicies.QueryCombinedFirewallPolicies(params)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping Firewall Policy sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing firewall policies: %w", err)
	}

	if resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		return sweepables, nil
	}

	for _, policy := range resp.Payload.Resources {
		if policy.Name == nil {
			continue
		}
		name := *policy.Name

		if !strings.HasPrefix(name, sweep.ResourcePrefix) {
			sweep.Trace("Skipping Firewall Policy %s (not a test resource)", name)
			continue
		}

		if policy.ID == nil {
			continue
		}
		id := *policy.ID

		sweepables = append(sweepables, sweep.NewSweepResource(
			id,
			name,
			deleteFirewallPolicy,
		))
	}

	return sweepables, nil
}

func deleteFirewallPolicy(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	// Disable before deleting
	disableParams := firewall_policies.NewPerformFirewallPoliciesActionParams().
		WithContext(ctx).
		WithActionName("disable").
		WithBody(&models.MsaEntityActionRequestV2{
			Ids: []string{id},
		})

	_, err := client.FirewallPolicies.PerformFirewallPoliciesAction(disableParams)
	if err != nil {
		sweep.Debug("Error disabling firewall policy %s: %s", id, err)
	}

	params := firewall_policies.NewDeleteFirewallPoliciesParams().
		WithContext(ctx).
		WithIds([]string{id})

	_, err = client.FirewallPolicies.DeleteFirewallPolicies(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for firewall policy %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}
