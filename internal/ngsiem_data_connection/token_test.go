package ngsiemdataconnection

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	apiclient "github.com/crowdstrike/gofalcon/falcon/client"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// newTestClient builds a gofalcon client whose transport points at the given test server, so the
// ingest-token path exercises the real gofalcon operation (params, ClientOption overrides,
// tokenReader) rather than any hand-rolled HTTP. No auth is configured — the test server requires none.
func newTestClient(t *testing.T, serverURL string) *apiclient.CrowdStrikeAPISpecification {
	t.Helper()
	u, err := url.Parse(serverURL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}
	rt := httptransport.New(u.Host, "", []string{"http"})
	return apiclient.New(rt, strfmt.Default)
}

func TestDecodeTokenResponse(t *testing.T) {
	const okBody = `{"resources":{"token":"tok-123","ingest_url":"https://x/services/collector","expires_at":"t1"},"errors":null}`

	t.Run("200 object yields token", func(t *testing.T) {
		tok, err := decodeTokenResponse(http.StatusOK, []byte(okBody))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tok.Token != "tok-123" || tok.IngestURL == "" || tok.ExpiresAt != "t1" {
			t.Fatalf("unexpected token: %+v", tok)
		}
	})

	// 200-with-empty-token, 202, 429 and 5xx are all transient: empty token, no error, so the caller
	// keeps polling.
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"200 not-ready shape", http.StatusOK, `{"resources":{}}`},
		{"202 provisioning", http.StatusAccepted, `{"resources":{"error":"ConnectionNotReady"}}`},
		{"429 throttled", http.StatusTooManyRequests, `{"errors":[{"message":"rate limited"}]}`},
		{"500", http.StatusInternalServerError, `{"errors":[{"code":500}]}`},
		{"503", http.StatusServiceUnavailable, ``},
	} {
		t.Run("transient "+tc.name, func(t *testing.T) {
			tok, err := decodeTokenResponse(tc.status, []byte(tc.body))
			if err != nil {
				t.Fatalf("status %d should be transient, got error: %v", tc.status, err)
			}
			if tok.Token != "" {
				t.Fatalf("status %d should yield empty token, got %q", tc.status, tok.Token)
			}
		})
	}

	// Non-retryable client errors fail fast.
	for _, status := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound} {
		t.Run("fail fast", func(t *testing.T) {
			if _, err := decodeTokenResponse(status, []byte(`{"errors":[{"message":"nope"}]}`)); err == nil {
				t.Fatalf("status %d should fail fast", status)
			}
		})
	}

	// A 200 with no token but a populated errors array must fail fast (not poll for the full timeout).
	t.Run("200 with errors fails fast", func(t *testing.T) {
		_, err := decodeTokenResponse(http.StatusOK, []byte(`{"resources":{},"errors":[{"message":"invalid parser"}]}`))
		if err == nil {
			t.Fatal("200 with errors and no token should fail fast")
		}
		if !strings.Contains(err.Error(), "invalid parser") {
			t.Fatalf("error should surface the API message, got: %v", err)
		}
	})

	// A 200 whose body isn't valid JSON fails fast rather than polling to the timeout on a response
	// that will never yield a token.
	t.Run("200 malformed json fails fast", func(t *testing.T) {
		_, err := decodeTokenResponse(http.StatusOK, []byte(`{"resources": not-json`))
		if err == nil {
			t.Fatal("malformed JSON on a 200 should fail fast")
		}
	})
}

func TestRegenerateIngestTokenDecodesObjectResources(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/ngsiem/entities/connections/token/v1" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if got := r.URL.Query().Get("ids"); got != "abc" {
			t.Errorf("ids = %q, want abc", got)
		}
		// CrowdStrike returns `resources` as a bare OBJECT here (not a list).
		_, _ = w.Write([]byte(`{"resources":{"token":"tok-123","ingest_url":"https://x/collector","expires_at":"t1"}}`))
	}))
	defer srv.Close()

	tok, status, err := regenerateIngestToken(context.Background(), newTestClient(t, srv.URL), "abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != http.StatusOK || tok.Token != "tok-123" {
		t.Fatalf("status=%d tok=%+v", status, tok)
	}
}

// waitForIngestToken must keep polling while the connection is still provisioning (202) and return
// the token on the first 200 that carries one. This exercises the retry/poll loop end-to-end against
// a fake endpoint, the riskiest custom path in the package.
func TestWaitForIngestTokenPollsUntilReady(t *testing.T) {
	orig := tokenWaitInterval
	tokenWaitInterval = time.Millisecond
	t.Cleanup(func() { tokenWaitInterval = orig })

	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// First two polls: still provisioning. Third: token ready.
		if atomic.AddInt32(&calls, 1) < 3 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		_, _ = w.Write([]byte(`{"resources":{"token":"tok-xyz","ingest_url":"https://x/collector","expires_at":"t1"}}`))
	}))
	defer srv.Close()

	tok, err := waitForIngestToken(context.Background(), newTestClient(t, srv.URL), "id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.Token != "tok-xyz" || tok.IngestURL != "https://x/collector" {
		t.Fatalf("unexpected token: %+v", tok)
	}
	if n := atomic.LoadInt32(&calls); n < 3 {
		t.Fatalf("expected to poll through the 202s (>=3 calls), got %d", n)
	}
}

func TestRegenerateIngestTokenTransientAndFailFast(t *testing.T) {
	t.Run("202 transient", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusAccepted)
		}))
		defer srv.Close()
		tok, status, err := regenerateIngestToken(context.Background(), newTestClient(t, srv.URL), "id")
		if err != nil || tok.Token != "" || status != http.StatusAccepted {
			t.Fatalf("202 should be transient empty token: tok=%+v status=%d err=%v", tok, status, err)
		}
	})
	t.Run("403 fails fast", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":[{"message":"forbidden"}]}`))
		}))
		defer srv.Close()
		if _, _, err := regenerateIngestToken(context.Background(), newTestClient(t, srv.URL), "id"); err == nil {
			t.Fatal("403 should fail fast")
		}
	})
}
