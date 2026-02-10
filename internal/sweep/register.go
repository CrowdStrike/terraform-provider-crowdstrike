package sweep

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func Register(name string, f SweeperFunc, dependencies ...string) {
	resource.AddTestSweepers(name, &resource.Sweeper{
		Name: name,
		F: func(region string) error {
			ctx := context.Background()

			client, err := SharedClient(ctx)
			if err != nil {
				return fmt.Errorf("getting client: %w", err)
			}

			Info("Listing %s resources", name)
			sweepables, err := f(ctx, client)

			if SkipSweepError(err) {
				Warn("Skipping %s sweeper: %s", name, err.Error())
				return nil
			}
			if err != nil {
				return fmt.Errorf("listing %q: %w", name, err)
			}

			err = SweepOrchestrator(ctx, sweepables)
			if err != nil {
				return fmt.Errorf("sweeping %q: %w", name, err)
			}

			return nil
		},
		Dependencies: dependencies,
	})
}
