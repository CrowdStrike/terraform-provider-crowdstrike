package cloudgoogleregistration

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_cloud_gcp_account", sweepCloudGCPAccounts)
}

func sweepCloudGCPAccounts(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	sweep.Info("GCP Cloud Account sweep not yet implemented - no list API available")
	return nil, nil
}
