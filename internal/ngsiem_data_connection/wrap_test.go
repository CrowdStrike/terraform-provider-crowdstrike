package ngsiemdataconnection

import (
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// wrap refreshes only the read-API fields (name, status, ingest_url) and must guard a blank read so it
// can't null the Required name or a previously captured ingest_url. The API never returns these blank in
// practice, so the guards are unobservable via acctest and are pinned here.
func TestWrap(t *testing.T) {
	t.Run("populated read refreshes name, status, and ingest_url", func(t *testing.T) {
		m := ngsiemDataConnectionResourceModel{}
		m.wrap(models.DataconnectionmanagementDataConnection{
			Name:      utils.Addr("conn-name"),
			Status:    utils.Addr("Active"),
			IngestURL: "https://example/services/collector",
		})
		if got := m.Name.ValueString(); got != "conn-name" {
			t.Errorf("name = %q, want conn-name", got)
		}
		if got := m.Status.ValueString(); got != "Active" {
			t.Errorf("status = %q, want Active", got)
		}
		if got := m.IngestURL.ValueString(); got != "https://example/services/collector" {
			t.Errorf("ingest_url = %q, want the read value", got)
		}
	})

	t.Run("blank or nil read name does not clobber the existing Required name", func(t *testing.T) {
		for _, name := range []*string{nil, utils.Addr("")} {
			m := ngsiemDataConnectionResourceModel{Name: types.StringValue("keep-me")}
			m.wrap(models.DataconnectionmanagementDataConnection{Name: name})
			if got := m.Name.ValueString(); got != "keep-me" {
				t.Errorf("name = %q, want keep-me preserved for read name %v", got, name)
			}
		}
	})

	t.Run("blank read ingest_url preserves the captured URL", func(t *testing.T) {
		m := ngsiemDataConnectionResourceModel{IngestURL: types.StringValue("https://captured/collector")}
		m.wrap(models.DataconnectionmanagementDataConnection{IngestURL: ""})
		if got := m.IngestURL.ValueString(); got != "https://captured/collector" {
			t.Errorf("ingest_url = %q, want the captured URL preserved", got)
		}
	})

	t.Run("nil read status becomes null", func(t *testing.T) {
		m := ngsiemDataConnectionResourceModel{}
		m.wrap(models.DataconnectionmanagementDataConnection{Status: nil})
		if !m.Status.IsNull() {
			t.Errorf("status = %v, want null for a nil read status", m.Status)
		}
	})
}
