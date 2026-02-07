package sweep

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/hashicorp/go-multierror"
)

type Sweepable interface {
	Delete(ctx context.Context) error
}

type SweeperFunc func(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]Sweepable, error)

// ResourcePrefix is the standard prefix for all test resources.
const ResourcePrefix = "tf-acc-test-"

var (
	clientOnce   sync.Once
	clientCached *client.CrowdStrikeAPISpecification
	clientErr    error
)

func SharedClient(ctx context.Context) (*client.CrowdStrikeAPISpecification, error) {
	clientOnce.Do(func() {
		Info("Initializing sweeper client")

		clientId := os.Getenv("FALCON_CLIENT_ID")
		clientSecret := os.Getenv("FALCON_CLIENT_SECRET")
		cloud := os.Getenv("FALCON_CLOUD")

		if clientId == "" {
			clientErr = fmt.Errorf("FALCON_CLIENT_ID environment variable is required")
			return
		}

		if clientSecret == "" {
			clientErr = fmt.Errorf("FALCON_CLIENT_SECRET environment variable is required")
			return
		}

		apiConfig := falcon.ApiConfig{
			ClientId:     clientId,
			ClientSecret: clientSecret,
			Cloud:        falcon.Cloud(cloud),
			Context:      ctx,
		}

		clientCached, clientErr = falcon.NewClient(&apiConfig)
		if clientErr != nil {
			Error("Failed to initialize sweeper client: %s", clientErr.Error())
			return
		}

		Info("Sweeper client initialized successfully")
	})
	return clientCached, clientErr
}

func SweepOrchestrator(ctx context.Context, sweepables []Sweepable) error {
	if len(sweepables) == 0 {
		Info("No resources to sweep")
		return nil
	}

	Info("Starting resource sweep (count: %d)", len(sweepables))

	var g multierror.Group

	for _, sweepable := range sweepables {
		sweepable := sweepable
		g.Go(func() error {
			return sweepable.Delete(ctx)
		})
	}

	err := g.Wait().ErrorOrNil()
	if err != nil {
		Error("Sweep completed with errors: %s", err.Error())
	} else {
		Info("Sweep completed successfully")
	}

	return err
}
