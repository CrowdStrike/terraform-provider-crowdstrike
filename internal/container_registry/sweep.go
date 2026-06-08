package containerregistry

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	fci "github.com/crowdstrike/gofalcon/falcon/client/falcon_container_image"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_container_registry", sweepContainerRegistry)
}

func sweepContainerRegistry(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	res, err := client.FalconContainerImage.ReadRegistryEntities(
		fci.NewReadRegistryEntitiesParams().WithContext(ctx),
	)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping Container Registry sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing registry entities: %w", err)
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
		return sweepables, nil
	}

	for _, id := range res.Payload.Resources {
		if id == "" {
			continue
		}

		entRes, err := client.FalconContainerImage.ReadRegistryEntitiesByUUID(
			fci.NewReadRegistryEntitiesByUUIDParams().WithContext(ctx).WithIds(id),
		)
		if sweep.SkipSweepError(err) {
			continue
		}
		if err != nil || entRes == nil || entRes.Payload == nil || len(entRes.Payload.Resources) == 0 || entRes.Payload.Resources[0] == nil {
			continue
		}

		reg := entRes.Payload.Resources[0]
		if reg.UserDefinedAlias == nil {
			continue
		}

		alias := *reg.UserDefinedAlias
		if !strings.HasPrefix(alias, sweep.ResourcePrefix) {
			sweep.Trace("Skipping registry entity %s (not a test resource)", id)
			continue
		}

		sweepables = append(sweepables, sweep.NewSweepResource(id, alias, deleteRegistryEntity))
	}

	return sweepables, nil
}

func deleteRegistryEntity(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	_, err := client.FalconContainerImage.DeleteRegistryEntities(
		fci.NewDeleteRegistryEntitiesParams().WithContext(ctx).WithIds(id),
	)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for registry entity %s: %s", id, err)
			return nil
		}
		return err
	}
	return nil
}
