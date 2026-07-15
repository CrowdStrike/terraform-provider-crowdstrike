package ngsiem

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ngsiem"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_ngsiem_data_connector_config", sweepConnectorConfigs)
	sweep.Register("crowdstrike_ngsiem_data_connection", sweepDataConnections)
}

func sweepConnectorConfigs(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	// Config list/delete are keyed by connector id, which is tenant/catalog
	// specific; skip the sweep when it is not configured.
	connectorID := os.Getenv("TF_ACC_NGSIEM_CONNECTOR_ID")
	if connectorID == "" {
		sweep.Warn("Skipping NG-SIEM connector config sweep: TF_ACC_NGSIEM_CONNECTOR_ID is not set")
		return nil, nil
	}

	params := ngsiem.NewExternalListConnectorConfigsParams().
		WithContext(ctx).
		WithIds(connectorID)

	resp, err := client.Ngsiem.ExternalListConnectorConfigs(params)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping NG-SIEM connector config sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing ngsiem connector configs: %w", err)
	}

	if resp == nil || resp.Payload == nil {
		return sweepables, nil
	}

	for _, c := range resp.Payload.Resources {
		if c == nil || c.ID == nil || c.Name == nil {
			continue
		}
		if !strings.HasPrefix(*c.Name, sweep.ResourcePrefix) {
			continue
		}
		sweepables = append(sweepables, sweep.NewSweepResource(
			*c.ID,
			*c.Name,
			deleteConnectorConfig(connectorID),
		))
	}

	return sweepables, nil
}

func deleteConnectorConfig(connectorID string) func(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	return func(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
		params := ngsiem.NewExternalDeleteConnectorConfigsParams().
			WithContext(ctx).
			WithConnectorID(connectorID).
			WithIds([]string{id})

		_, err := client.Ngsiem.ExternalDeleteConnectorConfigs(params)
		if err != nil {
			if sweep.ShouldIgnoreError(err) {
				sweep.Debug("Ignoring error for ngsiem connector config %s: %s", id, err)
				return nil
			}
			return err
		}

		return nil
	}
}

func sweepDataConnections(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	params := ngsiem.NewExternalListDataConnectionsParams().
		WithContext(ctx)

	resp, err := client.Ngsiem.ExternalListDataConnections(params)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping NG-SIEM data connection sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing ngsiem data connections: %w", err)
	}

	if resp == nil || resp.Payload == nil {
		return sweepables, nil
	}

	for _, c := range resp.Payload.Resources {
		if c == nil || c.ID == nil || c.Name == nil {
			continue
		}
		if !strings.HasPrefix(*c.Name, sweep.ResourcePrefix) {
			continue
		}
		sweepables = append(sweepables, sweep.NewSweepResource(
			*c.ID,
			*c.Name,
			deleteDataConnection,
		))
	}

	return sweepables, nil
}

func deleteDataConnection(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	params := ngsiem.NewExternalDeleteDataConnectionParams().
		WithContext(ctx).
		WithIds(id)

	_, err := client.Ngsiem.ExternalDeleteDataConnection(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for ngsiem data connection %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}
