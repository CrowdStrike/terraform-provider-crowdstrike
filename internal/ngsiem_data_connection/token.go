package ngsiemdataconnection

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	apiclient "github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ngsiem"
	"github.com/go-openapi/runtime"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// The ingest-token endpoint returns its 200 payload with `resources` as a bare object, but gofalcon
// models it as an array and can't decode the live response. We swap in a custom reader via the
// op.Reader hook and decode the object ourselves; the request still rides gofalcon's authenticated
// transport.

const defaultTokenWaitTimeout = 5 * time.Minute

// perAttemptTokenTimeout must stay below defaultTokenWaitTimeout so a single stalled poll can't consume
// the whole budget.
const perAttemptTokenTimeout = 30 * time.Second

// tokenWaitInterval is a var so tests can shorten the poll cadence.
var tokenWaitInterval = 2 * time.Second

type ingestToken struct {
	Token     string
	IngestURL string
	ExpiresAt string
}

// regenerateIngestToken requests a token, decoding the object-shaped response via tokenReader. The
// retry-vs-fail classification lives in decodeTokenResponse.
func regenerateIngestToken(ctx context.Context, client *apiclient.CrowdStrikeAPISpecification, id string) (ingestToken, int, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, perAttemptTokenTimeout)
	defer cancel()

	params := ngsiem.NewExternalRegenerateDataConnectionTokenParams()
	params.Context = attemptCtx
	params.Ids = id

	rd := &tokenReader{}
	_, _, err := client.Ngsiem.ExternalRegenerateDataConnectionToken(params, func(op *runtime.ClientOperation) {
		op.Reader = rd
	})
	if err != nil {
		if rd.err != nil { // reader ran and classified a non-retryable status
			return ingestToken{}, rd.status, rd.err
		}
		return ingestToken{}, rd.status, nil // reader never ran (transport/timeout): retry
	}
	return rd.tok, rd.status, nil
}

// waitForIngestToken polls regenerateIngestToken until a token is issued or the deadline passes.
func waitForIngestToken(ctx context.Context, client *apiclient.CrowdStrikeAPISpecification, id string) (ingestToken, error) {
	deadline := time.Now().Add(defaultTokenWaitTimeout)
	lastStatus := 0
	for {
		tok, status, err := regenerateIngestToken(ctx, client, id)
		if err != nil {
			return ingestToken{}, err
		}
		lastStatus = status
		if tok.Token != "" {
			return tok, nil
		}
		if time.Now().After(deadline) {
			return ingestToken{}, fmt.Errorf(
				"ingest token was not provisioned within %s (connection %s; last token-endpoint response: HTTP %d)",
				defaultTokenWaitTimeout, id, lastStatus,
			)
		}
		tflog.Trace(ctx, "ingest token not ready yet; polling", map[string]interface{}{
			"connection_id": id,
			"last_status":   lastStatus,
		})
		select {
		case <-ctx.Done():
			return ingestToken{}, ctx.Err()
		case <-time.After(tokenWaitInterval):
		}
	}
}

// tokenReader returns the generated OK type so the SDK's result type switch is satisfied; callers read
// the token/status off the struct, not the returned value.
type tokenReader struct {
	tok    ingestToken
	status int
	err    error
}

func (r *tokenReader) ReadResponse(response runtime.ClientResponse, _ runtime.Consumer) (interface{}, error) {
	r.status = response.Code()
	body, err := io.ReadAll(io.LimitReader(response.Body(), 1<<20))
	if err != nil {
		r.err = fmt.Errorf("reading ingest token response: %w", err)
		return nil, r.err
	}
	r.tok, r.err = decodeTokenResponse(response.Code(), body)
	if r.err != nil {
		return nil, r.err
	}
	return &ngsiem.ExternalRegenerateDataConnectionTokenOK{}, nil
}

// decodeTokenResponse maps a response to a token + retry decision: empty token + nil error means retry,
// a populated token means success, a non-nil error means fail fast. 202/429/5xx are retryable
// (provisioning / throttle / transient); a malformed 200 fails fast rather than polling to the timeout.
func decodeTokenResponse(status int, body []byte) (ingestToken, error) {
	if status == http.StatusAccepted ||
		status == http.StatusTooManyRequests ||
		status >= 500 {
		return ingestToken{}, nil
	}
	if status != http.StatusOK {
		return ingestToken{}, fmt.Errorf("ingest token request returned status %d: %s", status, truncate(strings.TrimSpace(string(body)), 512))
	}

	// `resources` is a bare object here, not an array (see the package-level note).
	var env struct {
		Resources struct {
			Token     string `json:"token"`
			IngestURL string `json:"ingest_url"`
			ExpiresAt string `json:"expires_at"`
		} `json:"resources"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return ingestToken{}, fmt.Errorf("decoding ingest token response (HTTP %d): %w; body: %s", status, err, truncate(strings.TrimSpace(string(body)), 512))
	}
	if env.Resources.Token != "" {
		return ingestToken{
			Token:     env.Resources.Token,
			IngestURL: env.Resources.IngestURL,
			ExpiresAt: env.Resources.ExpiresAt,
		}, nil
	}
	// A 200 with no token but a populated errors array (e.g. an invalid parser) won't ever yield a
	// token; fail fast with the message instead of polling.
	if len(env.Errors) > 0 {
		msgs := make([]string, 0, len(env.Errors))
		for _, e := range env.Errors {
			if e.Message != "" {
				msgs = append(msgs, e.Message)
			}
		}
		return ingestToken{}, fmt.Errorf("ingest token endpoint returned no token: %s", truncate(strings.Join(msgs, "; "), 512))
	}
	return ingestToken{}, nil // no token, no errors: not-ready; retry
}

// truncate caps s at maxLen bytes on a valid UTF-8 boundary (these strings land in diagnostics).
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	t := s[:maxLen]
	for len(t) > 0 && !utf8.ValidString(t) {
		t = t[:len(t)-1]
	}
	return t + "…(truncated)"
}
