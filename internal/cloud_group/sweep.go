package cloudgroup

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_cloud_group", sweepCloudGroups)
}

func sweepCloudGroups(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	params := cloud_security.NewListCloudGroupsExternalParams()
	params.WithContext(ctx)

	resp, err := client.CloudSecurity.ListCloudGroupsExternal(params)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping Cloud Group sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing cloud groups: %w", err)
	}

	if resp == nil || resp.Payload == nil || resp.Payload.Resources == nil {
		return sweepables, nil
	}

	for _, group := range resp.Payload.Resources {
		if group.Name == "" || group.ID == "" {
			continue
		}

		name := group.Name
		id := group.ID

		if !strings.HasPrefix(name, sweep.ResourcePrefix) {
			sweep.Trace("Skipping Cloud Group %s (not a test resource)", name)
			continue
		}

		sweepables = append(sweepables, sweep.NewSweepResource(
			id,
			name,
			deleteCloudGroup,
		))
	}

	return sweepables, nil
}

func deleteCloudGroup(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	params := cloud_security.NewDeleteCloudGroupsExternalParams()
	params.WithContext(ctx)
	params.Ids = []string{id}

	_, err := client.CloudSecurity.DeleteCloudGroupsExternal(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for cloud group %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}
