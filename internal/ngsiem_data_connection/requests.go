package ngsiemdataconnection

import (
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// gofalcon's generated request models tag enable_*_enrichment, description, and log_sources with
// `,omitempty`, so they can't express an explicit `false`, a cleared description, or omit-vs-send on
// update. We send our own structs via the op.Params hook: bodyOverrideParams runs the generated writer
// first (for the timeout and the `ids` query param), then replaces just the body.
type bodyOverrideParams struct {
	inner runtime.ClientRequestWriter
	body  any
}

func (p bodyOverrideParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {
	if p.inner != nil {
		if err := p.inner.WriteToRequest(r, reg); err != nil {
			return err
		}
	}
	return r.SetBodyParam(p.body)
}

// createDataConnectionBody drops `,omitempty` on the enrichment bools so an explicit false is sent;
// an omitted key would otherwise get the API's own default, which the read API never exposes for drift.
type createDataConnectionBody struct {
	ConnectorID          string   `json:"connector_id"`
	Name                 string   `json:"name"`
	Parser               string   `json:"parser"`
	Description          string   `json:"description,omitempty"`
	EnableHostEnrichment bool     `json:"enable_host_enrichment"`
	EnableUserEnrichment bool     `json:"enable_user_enrichment"`
	LogSources           []string `json:"log_sources"`
}

// updateDataConnectionBody omits unset write-only fields so the merge-update server keeps their current
// value rather than clobbering one set out of band; an explicit enrichment true OR false is non-nil and
// sent. description is the exception — sent unconditionally so removal clears it in place (its validator
// blocks an explicit "", so removal is the only way to clear).
type updateDataConnectionBody struct {
	Name                 string   `json:"name"`
	Parser               string   `json:"parser"`
	Description          string   `json:"description"`
	EnableHostEnrichment *bool    `json:"enable_host_enrichment,omitempty"`
	EnableUserEnrichment *bool    `json:"enable_user_enrichment,omitempty"`
	LogSources           []string `json:"log_sources,omitempty"`
}
