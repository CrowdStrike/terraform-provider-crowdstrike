package hostgroups

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/host_group"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_host_group", sweepHostGroups)
}

func sweepHostGroups(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	params := host_group.NewQueryCombinedHostGroupsParams()
	params.WithContext(ctx)

	resp, err := client.HostGroup.QueryCombinedHostGroups(params)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping Host Group sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing host groups: %w", err)
	}

	if resp.Payload == nil || resp.Payload.Resources == nil {
		return sweepables, nil
	}

	for _, hg := range resp.Payload.Resources {
		if hg.Name == nil {
			continue
		}
		name := *hg.Name

		if !strings.HasPrefix(name, sweep.ResourcePrefix) {
			sweep.Trace("Skipping Host Group %s (not a test resource)", name)
			continue
		}

		if hg.ID == nil {
			continue
		}
		id := *hg.ID

		sweepables = append(sweepables, sweep.NewSweepResource(
			id,
			name,
			deleteHostGroup,
		))
	}

	return sweepables, nil
}

func deleteHostGroup(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	params := host_group.NewDeleteHostGroupsParams()
	params.WithContext(ctx)
	params.Ids = []string{id}

	_, err := client.HostGroup.DeleteHostGroups(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for host group %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}
