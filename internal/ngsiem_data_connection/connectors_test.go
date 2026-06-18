package ngsiemdataconnection

import (
	"errors"
	"fmt"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
)

func TestFindConnectorByName(t *testing.T) {
	conns := []connector{
		{ID: "c-1", Name: "HEC / HTTP Event Connector"},
		{ID: "c-2", Name: "AWS CloudTrail"},
	}

	t.Run("exact match returns the connector", func(t *testing.T) {
		got, err := findConnectorByName(conns, "AWS CloudTrail")
		if err != nil || got.ID != "c-2" {
			t.Fatalf("got (%+v, %v), want c-2", got, err)
		}
	})

	t.Run("match is case-sensitive (no fuzzy match)", func(t *testing.T) {
		if _, err := findConnectorByName(conns, "aws cloudtrail"); err == nil {
			t.Fatal("expected not-found error for a case-mismatched name")
		}
	})

	t.Run("no match errors", func(t *testing.T) {
		if _, err := findConnectorByName(conns, "Nope"); err == nil {
			t.Fatal("expected not-found error")
		}
	})

	t.Run("matched-but-empty-ID errors", func(t *testing.T) {
		if _, err := findConnectorByName([]connector{{ID: "", Name: "Ghost"}}, "Ghost"); err == nil {
			t.Fatal("expected an error when the matched connector has no ID")
		}
	})
}

func TestToConnector(t *testing.T) {
	t.Run("nil yields zero value", func(t *testing.T) {
		if got := toConnector(nil); got.ID != "" || got.Name != "" {
			t.Fatalf("nil connector should map to zero value, got %+v", got)
		}
	})

	t.Run("maps fields and derefs pointers", func(t *testing.T) {
		id, name, typ := "c-9", "My Connector", "hec"
		got := toConnector(&models.DataconnectionmanagementDataConnector{
			ID:          &id,
			Name:        &name,
			Type:        &typ,
			Description: "desc",
			Parsers:     []string{"aws-cloudtrail"},
		})
		if got.ID != "c-9" || got.Name != "My Connector" || got.Type != "hec" || got.Description != "desc" || len(got.Parsers) != 1 {
			t.Fatalf("unexpected mapping: %+v", got)
		}
	})
}

func TestPageDataConnections(t *testing.T) {
	conn := func(id string) *models.DataconnectionmanagementDataConnection {
		return &models.DataconnectionmanagementDataConnection{ID: &id, Name: &id}
	}

	t.Run("collects across pages until empty", func(t *testing.T) {
		pages := map[int64][]*models.DataconnectionmanagementDataConnection{
			0: {conn("a"), conn("b")},
			2: {conn("c")},
		}
		got, err := pageDataConnections(func(offset int64) ([]*models.DataconnectionmanagementDataConnection, error) {
			return pages[offset], nil // unknown offset -> empty -> end
		})
		if err != nil || len(got) != 3 {
			t.Fatalf("want 3 connections, got %d (err %v)", len(got), err)
		}
	})

	t.Run("propagates fetch error", func(t *testing.T) {
		want := errors.New("boom")
		if _, err := pageDataConnections(func(int64) ([]*models.DataconnectionmanagementDataConnection, error) {
			return nil, want
		}); !errors.Is(err, want) {
			t.Fatalf("want propagated error, got %v", err)
		}
	})
}

// The live connectors endpoint returns variable-size pages (often fewer than the requested limit)
// and advances by offset — e.g. 93, then 60, then 3, then empty. pageConnectors must collect all of
// them, not stop at the first short page.
func TestPageConnectorsVariablePageSizes(t *testing.T) {
	pages := [][]connector{
		makeConnectors(0, 93),
		makeConnectors(93, 60),
		makeConnectors(153, 3),
		{},
	}
	got, err := pageConnectors(func(offset int64) ([]connector, error) {
		idx := 0
		switch offset {
		case 0:
			idx = 0
		case 93:
			idx = 1
		case 153:
			idx = 2
		default:
			idx = 3
		}
		return pages[idx], nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 156 {
		t.Fatalf("want 156 connectors collected across variable pages, got %d", len(got))
	}
}

func TestPageConnectorsDeduplicates(t *testing.T) {
	// Overlapping pages (the endpoint can re-serve a connector across pages), ended by an empty page.
	// c-3 and c-4 repeat in the second page and must be deduped; the loop must keep going past the
	// overlapping page rather than stopping when a page "adds nothing new".
	pages := map[int64][]connector{
		0: makeConnectors(0, 5), // c-0..c-4
		5: makeConnectors(3, 5), // c-3..c-7 (c-3, c-4 are duplicates)
	}
	got, err := pageConnectors(func(offset int64) ([]connector, error) {
		return pages[offset], nil // unknown offset -> empty page -> end
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 8 {
		t.Fatalf("want 8 de-duplicated connectors (c-0..c-7), got %d", len(got))
	}
}

// A wholly-duplicate middle page must NOT end pagination early: connectors at higher offsets must
// still be collected. This is the F4 regression guard.
func TestPageConnectorsDoesNotStopOnDuplicatePage(t *testing.T) {
	pages := map[int64][]connector{
		0: makeConnectors(0, 3), // c-0..c-2
		3: makeConnectors(0, 3), // all duplicates of the first page
		6: makeConnectors(3, 2), // c-3, c-4 -- new, live beyond the duplicate page
	}
	got, err := pageConnectors(func(offset int64) ([]connector, error) {
		return pages[offset], nil // offset 8 -> empty -> end
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("want 5 connectors (c-0..c-4) collected past the duplicate page, got %d", len(got))
	}
}

// Connectors with an empty ID are skipped, and they must not prevent termination.
func TestPageConnectorsSkipsEmptyIDs(t *testing.T) {
	pages := map[int64][]connector{
		0: {{ID: "c-0", Name: "c-0"}, {ID: "", Name: "no-id"}, {ID: "c-1", Name: "c-1"}},
	}
	got, err := pageConnectors(func(offset int64) ([]connector, error) {
		return pages[offset], nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 connectors (empty-ID row skipped), got %d", len(got))
	}
}

func TestPageConnectorsEmpty(t *testing.T) {
	got, err := pageConnectors(func(int64) ([]connector, error) { return nil, nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0, got %d", len(got))
	}
}

func TestPageConnectorsPropagatesError(t *testing.T) {
	want := errors.New("boom")
	if _, err := pageConnectors(func(int64) ([]connector, error) { return nil, want }); !errors.Is(err, want) {
		t.Fatalf("want propagated error, got %v", err)
	}
}

func TestParseConnectionImportID(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		cid, conn, err := parseConnectionImportID("connector-1:connection-9")
		if err != nil || cid != "connector-1" || conn != "connection-9" {
			t.Fatalf("got (%q,%q,%v)", cid, conn, err)
		}
	})
	for _, bad := range []string{"", "noseparator", ":conn", "conn:", ":"} {
		t.Run("invalid "+bad, func(t *testing.T) {
			if _, _, err := parseConnectionImportID(bad); err == nil {
				t.Fatalf("expected error for %q", bad)
			}
		})
	}
}

func makeConnectors(start, n int) []connector {
	out := make([]connector, 0, n)
	for i := start; i < start+n; i++ {
		id := fmt.Sprintf("c-%d", i)
		out = append(out, connector{ID: id, Name: id})
	}
	return out
}
