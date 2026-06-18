package ngsiemdataconnection

import (
	"context"
	"fmt"

	apiclient "github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ngsiem"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
)

const (
	// The endpoint treats page size as a hint, returning variable-size, sometimes overlapping pages,
	// so pageConnectors advances by actual length and dedups.
	connectorPageSize = int64(100)
	// maxConnectorOffset bounds pagination so an endpoint that never returns a short page can't loop
	// forever. The real catalog is ~150; 100k is unreachable.
	maxConnectorOffset = 100_000
)

type connector struct {
	ID, Name, Type, Description, VendorName, VendorProductName string
	Parsers                                                    []string
}

func listConnectors(ctx context.Context, client *apiclient.CrowdStrikeAPISpecification) ([]connector, error) {
	return pageConnectors(func(offset int64) ([]connector, error) {
		params := ngsiem.NewExternalListDataConnectorsParams()
		params.Context = ctx
		limit, off := connectorPageSize, offset
		params.Limit, params.Offset = &limit, &off
		resp, err := client.Ngsiem.ExternalListDataConnectors(params)
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Payload == nil {
			return nil, nil
		}
		// A 200 can still carry application-level errors (e.g. a partial-scope token); surface them
		// rather than returning an empty catalog.
		if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, resp.Payload.Errors); diag != nil {
			return nil, fmt.Errorf("%s: %s", diag.Summary(), diag.Detail())
		}
		out := make([]connector, 0, len(resp.Payload.Resources))
		for _, c := range resp.Payload.Resources {
			out = append(out, toConnector(c))
		}
		return out, nil
	})
}

// pageConnectors pages by actual length until an empty page marks the end. Terminating on "added
// nothing new" instead would stop early on a wholly-duplicate middle page and drop higher-offset
// connectors. A seen-set dedups overlapping pages.
func pageConnectors(fetch func(offset int64) ([]connector, error)) ([]connector, error) {
	var out []connector
	seen := make(map[string]struct{})
	for offset := int64(0); offset <= maxConnectorOffset; {
		page, err := fetch(offset)
		if err != nil {
			return nil, err
		}
		if len(page) == 0 {
			break
		}
		for _, c := range page {
			if c.ID == "" {
				continue // no ID: can't be addressed or deduped
			}
			if _, dup := seen[c.ID]; dup {
				continue
			}
			seen[c.ID] = struct{}{}
			out = append(out, c)
		}
		offset += int64(len(page))
	}
	return out, nil
}

func toConnector(r *models.DataconnectionmanagementDataConnector) connector {
	if r == nil {
		return connector{}
	}
	return connector{
		ID:                deref(r.ID),
		Name:              deref(r.Name),
		Type:              deref(r.Type),
		Description:       r.Description,
		VendorName:        deref(r.VendorName),
		VendorProductName: deref(r.VendorProductName),
		Parsers:           r.Parsers,
	}
}

func findConnectorByName(connectors []connector, name string) (connector, error) {
	for _, c := range connectors {
		if c.Name == name {
			if c.ID == "" {
				return connector{}, fmt.Errorf("NG-SIEM data connector %q was found but has no usable ID", name)
			}
			return c, nil
		}
	}
	return connector{}, fmt.Errorf("no NG-SIEM data connector found with name %q", name)
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
