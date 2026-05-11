package falconcontainerimage

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/falcon_container_image"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_falcon_container_image", sweepFalconContainerImageRegistries)
}

func sweepFalconContainerImageRegistries(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	// The list API returns IDs only; fetch full records to filter by name prefix.
	listParams := falcon_container_image.NewReadRegistryEntitiesParams().
		WithContext(ctx)

	listResp, err := client.FalconContainerImage.ReadRegistryEntities(listParams)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping Falcon Container Image registry sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing falcon container image registries: %w", err)
	}

	if listResp.Payload == nil || len(listResp.Payload.Resources) == 0 {
		return sweepables, nil
	}

	ids := listResp.Payload.Resources
	if len(ids) == 0 {
		return sweepables, nil
	}

	// ReadRegistryEntitiesByUUID accepts a single ID; iterate over all IDs.
	for _, id := range ids {
		getParams := falcon_container_image.NewReadRegistryEntitiesByUUIDParams().
			WithContext(ctx).
			WithIds(id)

		getResp, err := client.FalconContainerImage.ReadRegistryEntitiesByUUID(getParams)
		if sweep.SkipSweepError(err) {
			sweep.Warn("Skipping Falcon Container Image registry %s: %s", id, err)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("error reading falcon container image registry %s: %w", id, err)
		}

		if getResp.Payload == nil || len(getResp.Payload.Resources) == 0 || getResp.Payload.Resources[0] == nil {
			continue
		}

		registry := getResp.Payload.Resources[0]

		// Use url_uniqueness_alias as the name to check — it is always populated by the API
		// and reflects the user_defined_alias when set, otherwise a system-generated value.
		if registry.URLUniquenessAlias == nil {
			continue
		}
		name := *registry.URLUniquenessAlias

		if !strings.HasPrefix(name, sweep.ResourcePrefix) {
			sweep.Trace("Skipping Falcon Container Image registry %s (not a test resource)", id)
			continue
		}

		sweepables = append(sweepables, sweep.NewSweepResource(
			id,
			name,
			deleteFalconContainerImageRegistry,
		))
	}

	return sweepables, nil
}

func deleteFalconContainerImageRegistry(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	params := falcon_container_image.NewDeleteRegistryEntitiesParams().
		WithContext(ctx).
		WithIds(id)

	_, err := client.FalconContainerImage.DeleteRegistryEntities(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for falcon container image registry %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}
