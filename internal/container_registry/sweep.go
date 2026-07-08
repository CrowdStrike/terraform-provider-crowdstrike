package containerregistry

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	fci "github.com/crowdstrike/gofalcon/falcon/client/falcon_container_image"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
	goopenapiruntime "github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// readEntitiesBatchSize bounds the number of registry entity UUIDs we ask for
// in a single ReadRegistryEntitiesByUUID call to avoid overrunning any
// server-side limit on the ids[] query parameter.
const readEntitiesBatchSize = 100

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

	ids := make([]string, 0, len(res.Payload.Resources))
	for _, id := range res.Payload.Resources {
		if id != "" {
			ids = append(ids, id)
		}
	}

	for start := 0; start < len(ids); start += readEntitiesBatchSize {
		end := min(start+readEntitiesBatchSize, len(ids))
		batch := ids[start:end]

		entRes, err := readRegistryEntitiesBatch(ctx, client, batch)
		if err != nil {
			// Surface per-batch failures instead of silently swallowing them
			// with sweep.SkipSweepError + continue. We still keep going so a
			// single transient batch error doesn't block sweeping the rest.
			sweep.Warn("error reading registry entity batch (%d ids): %s", len(batch), err)
			continue
		}
		if entRes == nil || entRes.Payload == nil {
			continue
		}

		for _, reg := range entRes.Payload.Resources {
			if reg == nil || reg.ID == nil || reg.UserDefinedAlias == nil {
				continue
			}

			alias := *reg.UserDefinedAlias
			if !strings.HasPrefix(alias, sweep.ResourcePrefix) {
				sweep.Trace("Skipping registry entity %s (not a test resource)", *reg.ID)
				continue
			}

			sweepables = append(sweepables, sweep.NewSweepResource(*reg.ID, alias, deleteRegistryEntity))
		}
	}

	return sweepables, nil
}

// readRegistryEntitiesBatch issues a single ReadRegistryEntitiesByUUID request
// for the supplied IDs. The generated client only natively supports a single
// "ids" query value, so we override the operation params with a writer that
// emits ?ids=...&ids=... for every UUID in the batch.
func readRegistryEntitiesBatch(
	ctx context.Context,
	c *client.CrowdStrikeAPISpecification,
	ids []string,
) (*fci.ReadRegistryEntitiesByUUIDOK, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	params := fci.NewReadRegistryEntitiesByUUIDParams().WithContext(ctx)

	multiIDsOpt := func(op *goopenapiruntime.ClientOperation) {
		op.Params = goopenapiruntime.ClientRequestWriterFunc(
			func(r goopenapiruntime.ClientRequest, _ strfmt.Registry) error {
				return r.SetQueryParam("ids", ids...)
			},
		)
	}

	return c.FalconContainerImage.ReadRegistryEntitiesByUUID(params, multiIDsOpt)
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
