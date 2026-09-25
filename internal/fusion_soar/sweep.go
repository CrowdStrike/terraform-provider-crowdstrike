package fusionsoar

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_fusion_soar_workflow", sweepFusionWorkflows)
}

func sweepFusionWorkflows(ctx context.Context, apiClient *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	res, err := queryDefinitions(ctx, apiClient, fmt.Sprintf("name:~'%s'", sweep.ResourcePrefix))
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping Fusion workflow sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing Fusion workflows: %w", err)
	}

	for _, workflow := range res.Resources {
		if workflow.ID == "" {
			continue
		}

		// The FQL ~ operator is a case-insensitive substring match.
		if !strings.HasPrefix(workflow.Name, sweep.ResourcePrefix) {
			continue
		}

		sweepables = append(sweepables, sweep.NewSweepResource(workflow.ID, workflow.Name, deleteFusionWorkflow))
	}

	return sweepables, nil
}

func deleteFusionWorkflow(ctx context.Context, apiClient *client.CrowdStrikeAPISpecification, id string) error {
	_, err := deleteWorkflow(ctx, apiClient, id)
	if sweep.ShouldIgnoreError(err) {
		sweep.Debug("Ignoring error for Fusion workflow %s: %s", id, err)
		return nil
	}
	return err
}
