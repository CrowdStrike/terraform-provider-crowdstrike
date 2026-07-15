package ngsiem

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
)

// TestCreateEnrichmentOverrideSerializesFalse proves the create override struct
// serializes enable_host_enrichment/enable_user_enrichment even when false,
// which the generated model drops due to omitempty.
func TestCreateEnrichmentOverrideSerializesFalse(t *testing.T) {
	base := models.DataconnectionmanagementCreateDataConnectionRequest{
		Name:                 "test",
		EnableHostEnrichment: false,
		EnableUserEnrichment: false,
	}

	// The generated model drops both false fields.
	generated, err := json.Marshal(base)
	if err != nil {
		t.Fatalf("marshal generated: %s", err)
	}
	if strings.Contains(string(generated), "enable_host_enrichment") {
		t.Fatalf("expected generated model to omit enable_host_enrichment; got %s", generated)
	}

	override := createDataConnectionRequestOverride{
		DataconnectionmanagementCreateDataConnectionRequest: base,
		EnableHostEnrichment: base.EnableHostEnrichment,
		EnableUserEnrichment: base.EnableUserEnrichment,
	}
	b, err := json.Marshal(override)
	if err != nil {
		t.Fatalf("marshal override: %s", err)
	}
	got := string(b)
	if !strings.Contains(got, `"enable_host_enrichment":false`) {
		t.Errorf("expected enable_host_enrichment:false in body; got %s", got)
	}
	if !strings.Contains(got, `"enable_user_enrichment":false`) {
		t.Errorf("expected enable_user_enrichment:false in body; got %s", got)
	}
	// The embedded field must not double-serialize.
	if strings.Count(got, "enable_host_enrichment") != 1 {
		t.Errorf("enable_host_enrichment should appear exactly once; got %s", got)
	}
}

// TestUpdateEnrichmentOverrideSerializesFalse proves the same for the update body.
func TestUpdateEnrichmentOverrideSerializesFalse(t *testing.T) {
	base := models.DataconnectionmanagementUpdateDataConnectionRequest{
		Name:                 "test",
		EnableHostEnrichment: false,
		EnableUserEnrichment: false,
	}

	override := updateDataConnectionRequestOverride{
		DataconnectionmanagementUpdateDataConnectionRequest: base,
		EnableHostEnrichment: base.EnableHostEnrichment,
		EnableUserEnrichment: base.EnableUserEnrichment,
	}
	b, err := json.Marshal(override)
	if err != nil {
		t.Fatalf("marshal override: %s", err)
	}
	got := string(b)
	if !strings.Contains(got, `"enable_host_enrichment":false`) {
		t.Errorf("expected enable_host_enrichment:false in body; got %s", got)
	}
	if !strings.Contains(got, `"enable_user_enrichment":false`) {
		t.Errorf("expected enable_user_enrichment:false in body; got %s", got)
	}
	if strings.Count(got, "enable_user_enrichment") != 1 {
		t.Errorf("enable_user_enrichment should appear exactly once; got %s", got)
	}
}

// TestEnrichmentOverrideSerializesTrue confirms true still serializes correctly.
func TestEnrichmentOverrideSerializesTrue(t *testing.T) {
	base := models.DataconnectionmanagementCreateDataConnectionRequest{
		Name:                 "test",
		EnableHostEnrichment: true,
		EnableUserEnrichment: true,
	}
	override := createDataConnectionRequestOverride{
		DataconnectionmanagementCreateDataConnectionRequest: base,
		EnableHostEnrichment: base.EnableHostEnrichment,
		EnableUserEnrichment: base.EnableUserEnrichment,
	}
	b, err := json.Marshal(override)
	if err != nil {
		t.Fatalf("marshal override: %s", err)
	}
	got := string(b)
	if !strings.Contains(got, `"enable_host_enrichment":true`) {
		t.Errorf("expected enable_host_enrichment:true in body; got %s", got)
	}
	if !strings.Contains(got, `"enable_user_enrichment":true`) {
		t.Errorf("expected enable_user_enrichment:true in body; got %s", got)
	}
}
