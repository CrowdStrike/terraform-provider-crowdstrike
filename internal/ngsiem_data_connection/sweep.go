package ngsiemdataconnection

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ngsiem"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
)

const connectionPageSize = int64(100)

// maxConnectionOffset bounds pagination so an endpoint that never returns a short page can't loop forever.
const maxConnectionOffset = 100_000

func RegisterSweepers() {
	sweep.Register("crowdstrike_ngsiem_data_connection", sweepNgsiemDataConnections)
}

// pageDataConnections pages by actual length until an empty page marks the end. Unlike pageConnectors
// it doesn't dedup overlapping pages: a duplicate delete just 404s and is ignored, so it's harmless here.
func pageDataConnections(fetch func(offset int64) ([]*models.DataconnectionmanagementDataConnection, error)) ([]*models.DataconnectionmanagementDataConnection, error) {
	var out []*models.DataconnectionmanagementDataConnection
	for offset := int64(0); offset <= maxConnectionOffset; {
		page, err := fetch(offset)
		if err != nil {
			return nil, err
		}
		if len(page) == 0 {
			break
		}
		out = append(out, page...)
		offset += int64(len(page))
	}
	return out, nil
}

// sweepNgsiemDataConnections deletes leaked test connections. The FQL `~` is a contains match, so a
// client-side HasPrefix guard prevents deleting a real connection whose name merely contains the prefix.
func sweepNgsiemDataConnections(ctx context.Context, c *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	skipped := false
	conns, err := pageDataConnections(func(offset int64) ([]*models.DataconnectionmanagementDataConnection, error) {
		params := ngsiem.NewExternalListDataConnectionsParams()
		params.WithContext(ctx)
		limit, off := connectionPageSize, offset
		params.Limit, params.Offset = &limit, &off
		params.Filter = utils.Addr(fmt.Sprintf("name:~'%s'", sweep.ResourcePrefix))

		resp, lerr := c.Ngsiem.ExternalListDataConnections(params)
		if sweep.SkipSweepError(lerr) {
			sweep.Warn("Skipping NG-SIEM data connection sweep: %s", lerr)
			skipped = true
			return nil, nil // stop paging; handled after the loop
		}
		if lerr != nil {
			return nil, fmt.Errorf("error listing data connections: %w", lerr)
		}
		if resp == nil || resp.Payload == nil {
			return nil, nil
		}
		return resp.Payload.Resources, nil
	})
	if skipped {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var sweepables []sweep.Sweepable
	for _, conn := range conns {
		if conn == nil || conn.ID == nil || conn.Name == nil {
			continue
		}
		name := *conn.Name
		if !isSweepableTestConnection(name) {
			sweep.Trace("Skipping NG-SIEM data connection %s (not a test resource)", name)
			continue
		}
		sweepables = append(sweepables, sweep.NewSweepResource(*conn.ID, name, deleteNgsiemDataConnection))
	}

	return sweepables, nil
}

// isSweepableTestConnection reports whether a connection name belongs to this provider's acceptance
// tests. The list filter uses FQL `~` (a CONTAINS match), so this prefix check is what actually keeps a
// real connection whose name merely contains the prefix from being deleted.
func isSweepableTestConnection(name string) bool {
	return strings.HasPrefix(name, sweep.ResourcePrefix)
}

func deleteNgsiemDataConnection(ctx context.Context, c *client.CrowdStrikeAPISpecification, id string) error {
	params := ngsiem.NewExternalDeleteDataConnectionParams()
	params.WithContext(ctx)
	params.Ids = id

	if _, err := c.Ngsiem.ExternalDeleteDataConnection(params); err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for data connection %s: %s", id, err)
			return nil
		}
		return err
	}
	return nil
}
