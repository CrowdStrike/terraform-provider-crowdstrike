package networkcontainment

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/containment_allowlist_rules"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_network_containment_allowlist_rule", sweepNetworkContainmentAllowlistRules)
}

// sweepNetworkContainmentAllowlistRules returns a single sweepable that deletes
// every test rule in order. The orchestrator runs sweepables concurrently, but
// the API refuses to delete the last ip_dns rule while an fqdn rule remains, so
// ip_dns rules must be deleted last.
func sweepNetworkContainmentAllowlistRules(
	ctx context.Context,
	apiClient *client.CrowdStrikeAPISpecification,
) ([]sweep.Sweepable, error) {
	rules, err := listAllowlistRules(ctx, apiClient)
	if err != nil {
		return nil, err
	}

	var ids, dnsIDs []string
	for _, rule := range rules {
		if rule.Label == nil || !strings.HasPrefix(*rule.Label, sweep.ResourcePrefix) {
			continue
		}
		if rule.Type != nil && *rule.Type == ruleTypeIPDNS {
			dnsIDs = append(dnsIDs, rule.ID)
			continue
		}
		ids = append(ids, rule.ID)
	}
	ids = append(ids, dnsIDs...)

	if len(ids) == 0 {
		return nil, nil
	}

	return []sweep.Sweepable{
		sweep.NewSweepResource(
			strings.Join(ids, ", "),
			"network containment allowlist rules",
			func(ctx context.Context, apiClient *client.CrowdStrikeAPISpecification, _ string) error {
				for _, id := range ids {
					if err := deleteNetworkContainmentAllowlistRule(ctx, apiClient, id); err != nil {
						return err
					}
				}
				return nil
			},
		),
	}, nil
}

// deleteNetworkContainmentAllowlistRule deletes a single rule. Deletes are not
// batched because a batch is all-or-nothing: one missing ID makes the API
// delete none of them.
func deleteNetworkContainmentAllowlistRule(
	ctx context.Context,
	apiClient *client.CrowdStrikeAPISpecification,
	id string,
) error {
	params := containment_allowlist_rules.NewDeleteContainmentAllowlistRulesParamsWithContext(ctx).
		WithIds([]string{id})

	if _, err := apiClient.ContainmentAllowlistRules.DeleteContainmentAllowlistRules(params); err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for network containment allowlist rule %s: %s", id, err)
			return nil
		}
		return fmt.Errorf("deleting network containment allowlist rule %s: %w", id, err)
	}

	return nil
}
