package ngsiemdataconnection

import (
	"encoding/json"
	"strings"
	"testing"
)

// The update body must omit the optional write-only fields the user left unset (nil enrichment
// pointers, empty log_sources) so the merge-update server keeps any value set out of band or before
// import, while still transmitting an explicit enrichment false and a cleared (empty) description.
// None of this is observable through the live API — those fields are never returned — so the contract
// is pinned here at the serialization layer.
// The create body must send an explicit enable_*_enrichment false — that is the whole reason it drops
// gofalcon's `,omitempty` on those bools (an omitted key would take the API's own default, which the
// read API never exposes for drift). Pinned here because enrichment is never returned, so the contract
// is unobservable through the live API; this also guards against a future "tidy" re-adding omitempty.
func TestCreateDataConnectionBodySerialization(t *testing.T) {
	b, err := json.Marshal(createDataConnectionBody{ConnectorID: "c", Name: "n", Parser: "p"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(b)
	for _, want := range []string{`"enable_host_enrichment":false`, `"enable_user_enrichment":false`} {
		if !strings.Contains(got, want) {
			t.Errorf("create body must send an explicit %s, got: %s", want, got)
		}
	}
}

func TestUpdateDataConnectionBodySerialization(t *testing.T) {
	t.Run("unset write-only fields are omitted", func(t *testing.T) {
		b, err := json.Marshal(updateDataConnectionBody{Name: "n", Parser: "p", Description: "d"})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		got := string(b)
		for _, key := range []string{"enable_host_enrichment", "enable_user_enrichment", "log_sources"} {
			if strings.Contains(got, key) {
				t.Errorf("unset %s should be omitted from the update body, got: %s", key, got)
			}
		}
	})

	t.Run("explicit enrichment false is transmitted", func(t *testing.T) {
		f := false
		b, err := json.Marshal(updateDataConnectionBody{Name: "n", Parser: "p", EnableHostEnrichment: &f})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if !strings.Contains(string(b), `"enable_host_enrichment":false`) {
			t.Errorf("explicit enrichment false must be sent, got: %s", b)
		}
	})

	t.Run("empty description is sent so removal clears in place", func(t *testing.T) {
		b, err := json.Marshal(updateDataConnectionBody{Name: "n", Parser: "p", Description: ""})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if !strings.Contains(string(b), `"description":""`) {
			t.Errorf("empty description must be sent to clear in place, got: %s", b)
		}
	})

	t.Run("set log_sources is transmitted", func(t *testing.T) {
		b, err := json.Marshal(updateDataConnectionBody{Name: "n", Parser: "p", LogSources: []string{"src-a"}})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if !strings.Contains(string(b), `"log_sources":["src-a"]`) {
			t.Errorf("set log_sources must be sent, got: %s", b)
		}
	})
}
