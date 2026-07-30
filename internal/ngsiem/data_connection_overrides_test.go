package ngsiem

import (
	"context"
	"encoding/json"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client/ngsiem"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
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

// timeoutRecordingRequest mirrors how go-openapi builds an outgoing request: the
// per-request timeout is seeded with client.DefaultTimeout (30s) before the
// params writer runs, so a writer that never calls SetTimeout leaves the 30s cap
// in place.
type timeoutRecordingRequest struct {
	runtime.TestClientRequest
	timeout    time.Duration
	timeoutSet bool
	query      url.Values
}

func newTimeoutRecordingRequest() *timeoutRecordingRequest {
	return &timeoutRecordingRequest{timeout: cr.DefaultTimeout, query: url.Values{}}
}

func (r *timeoutRecordingRequest) SetTimeout(d time.Duration) error {
	r.timeout = d
	r.timeoutSet = true
	return nil
}

func (r *timeoutRecordingRequest) SetQueryParam(name string, values ...string) error {
	r.query[name] = values
	return nil
}

func (r *timeoutRecordingRequest) GetQueryParams() url.Values { return r.query }

// TestCreateEnrichmentOverrideInheritsParamsTimeout proves the create override
// inherits the per-request timeout from the params the call site built instead of
// leaving go-openapi's 30s DefaultTimeout in place.
func TestCreateEnrichmentOverrideInheritsParamsTimeout(t *testing.T) {
	body := &models.DataconnectionmanagementCreateDataConnectionRequest{Name: "test"}

	op := &runtime.ClientOperation{
		Params: ngsiem.NewExternalCreateDataConnectionParamsWithContext(context.Background()).
			WithBody(body),
	}
	withCreateEnrichmentOverride(body)(op)

	req := newTimeoutRecordingRequest()
	if err := op.Params.WriteToRequest(req, nil); err != nil {
		t.Fatalf("WriteToRequest: %s", err)
	}

	if !req.timeoutSet {
		t.Fatal("expected WriteToRequest to set the per-request timeout")
	}
	if req.timeout != 0 {
		t.Fatalf("expected the request to be bounded by the operation context, got a %s timeout", req.timeout)
	}
	if _, ok := req.GetBodyParam().(*createDataConnectionRequestOverride); !ok {
		t.Fatalf("expected the enrichment-corrected body, got %T", req.GetBodyParam())
	}
}

// TestUpdateEnrichmentOverrideInheritsParamsTimeout proves the same for update
// and that the required `ids` query param still reaches the request.
func TestUpdateEnrichmentOverrideInheritsParamsTimeout(t *testing.T) {
	body := &models.DataconnectionmanagementUpdateDataConnectionRequest{Name: "test"}

	op := &runtime.ClientOperation{
		Params: ngsiem.NewExternalUpdateDataConnectionParamsWithContext(context.Background()).
			WithIds("connection-id").
			WithBody(body),
	}
	withUpdateEnrichmentOverride(body)(op)

	req := newTimeoutRecordingRequest()
	if err := op.Params.WriteToRequest(req, nil); err != nil {
		t.Fatalf("WriteToRequest: %s", err)
	}

	if !req.timeoutSet {
		t.Fatal("expected WriteToRequest to set the per-request timeout")
	}
	if req.timeout != 0 {
		t.Fatalf("expected the request to be bounded by the operation context, got a %s timeout", req.timeout)
	}
	if _, ok := req.GetBodyParam().(*updateDataConnectionRequestOverride); !ok {
		t.Fatalf("expected the enrichment-corrected body, got %T", req.GetBodyParam())
	}
	if got := req.GetQueryParams().Get("ids"); got != "connection-id" {
		t.Fatalf("expected ids query param connection-id, got %q", got)
	}
}

// TestEnrichmentOverridesHonorExplicitTimeout proves the overrides delegate to
// the generated writer rather than hardcoding a timeout, so an explicit
// per-request timeout on the params is still honored.
func TestEnrichmentOverridesHonorExplicitTimeout(t *testing.T) {
	want := 2 * time.Minute

	createBody := &models.DataconnectionmanagementCreateDataConnectionRequest{Name: "test"}
	createOp := &runtime.ClientOperation{
		Params: ngsiem.NewExternalCreateDataConnectionParamsWithContext(context.Background()).
			WithBody(createBody).
			WithTimeout(want),
	}
	withCreateEnrichmentOverride(createBody)(createOp)

	createReq := newTimeoutRecordingRequest()
	if err := createOp.Params.WriteToRequest(createReq, nil); err != nil {
		t.Fatalf("create WriteToRequest: %s", err)
	}
	if createReq.timeout != want {
		t.Fatalf("expected create timeout %s, got %s", want, createReq.timeout)
	}

	updateBody := &models.DataconnectionmanagementUpdateDataConnectionRequest{Name: "test"}
	updateOp := &runtime.ClientOperation{
		Params: ngsiem.NewExternalUpdateDataConnectionParamsWithContext(context.Background()).
			WithIds("connection-id").
			WithBody(updateBody).
			WithTimeout(want),
	}
	withUpdateEnrichmentOverride(updateBody)(updateOp)

	updateReq := newTimeoutRecordingRequest()
	if err := updateOp.Params.WriteToRequest(updateReq, nil); err != nil {
		t.Fatalf("update WriteToRequest: %s", err)
	}
	if updateReq.timeout != want {
		t.Fatalf("expected update timeout %s, got %s", want, updateReq.timeout)
	}
}

// fakeClientResponse is a minimal runtime.ClientResponse for exercising a
// reader's ReadResponse with a canned status code and body.
type fakeClientResponse struct {
	code int
	body string
}

func (f fakeClientResponse) Code() int                  { return f.code }
func (f fakeClientResponse) Message() string            { return "" }
func (f fakeClientResponse) GetHeader(string) string    { return "" }
func (f fakeClientResponse) GetHeaders(string) []string { return nil }
func (f fakeClientResponse) Body() io.ReadCloser        { return io.NopCloser(strings.NewReader(f.body)) }

// TestRegenerateTokenReaderParsesObjectResources proves the reader parses the
// 200 envelope where `resources` is a single object, which the generated model
// (declaring resources as an array) fails to unmarshal.
func TestRegenerateTokenReaderParsesObjectResources(t *testing.T) {
	body := `{
      "meta": {"query_time": 0.1},
      "resources": {
        "token": "abc123",
        "ingest_url": "https://example.ingest.us-2.crowdstrike.com/services/collector",
        "created_at": "2026-07-15T17:25:54Z",
        "expires_at": "2126-07-16T17:25:54Z"
      }
    }`

	reader := &regenerateTokenReader{}
	if _, err := reader.ReadResponse(fakeClientResponse{code: 200, body: body}, runtime.JSONConsumer()); err != nil {
		t.Fatalf("ReadResponse: %s", err)
	}
	if reader.response == nil || reader.response.Resources == nil {
		t.Fatalf("expected parsed resources object, got %#v", reader.response)
	}
	if reader.response.Resources.Token == nil || *reader.response.Resources.Token != "abc123" {
		t.Errorf("expected token abc123; got %#v", reader.response.Resources.Token)
	}
	if reader.response.Resources.IngestURL == nil || *reader.response.Resources.IngestURL == "" {
		t.Errorf("expected ingest_url to be set; got %#v", reader.response.Resources.IngestURL)
	}
}
