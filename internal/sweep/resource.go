package sweep

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
)

type sweepResource struct {
	id         string
	name       string
	deleteFunc func(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error
}

func NewSweepResource(id, name string, deleteFunc func(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error) Sweepable {
	return &sweepResource{
		id:         id,
		name:       name,
		deleteFunc: deleteFunc,
	}
}

func (sr *sweepResource) Delete(ctx context.Context) error {
	Info("Deleting resource: %s (ID: %s)", sr.name, sr.id)

	client, err := SharedClient(ctx)
	if err != nil {
		return fmt.Errorf("getting client: %w", err)
	}

	if err := sr.deleteFunc(ctx, client, sr.id); err != nil {
		return fmt.Errorf("deleting %s (%s): %w", sr.name, sr.id, err)
	}

	Info("Successfully deleted resource: %s (ID: %s)", sr.name, sr.id)
	return nil
}
