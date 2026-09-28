package fusionsoar

import (
	"errors"
	"io"
	"net/url"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/workflows"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/clientoverrides"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// queryRecordingRequest records query parameters, which the go-openapi
// TestClientRequest discards.
type queryRecordingRequest struct {
	runtime.TestClientRequest
	query url.Values
}

func (r *queryRecordingRequest) SetQueryParam(name string, values ...string) error {
	r.query[name] = values
	return nil
}

func TestWithDefinitionBodyWritesYAMLBody(t *testing.T) {
	t.Parallel()

	body := "name: example\nid: abc\n"
	validateOnly := true
	generated := workflows.NewWorkflowDefinitionsUpdateParams().WithValidateOnly(&validateOnly)

	op := &runtime.ClientOperation{Params: generated}
	withDefinitionBody(body)(op)

	if len(op.ConsumesMediaTypes) != 1 || op.ConsumesMediaTypes[0] != clientoverrides.YAMLMime {
		t.Errorf("ConsumesMediaTypes = %v, want [application/yaml]", op.ConsumesMediaTypes)
	}

	req := &queryRecordingRequest{query: url.Values{}}
	if err := op.Params.WriteToRequest(req, strfmt.Default); err != nil {
		t.Fatalf("WriteToRequest returned error: %s", err)
	}

	reader, ok := req.GetBodyParam().(io.Reader)
	if !ok {
		t.Fatalf("body = %T, want an io.Reader", req.GetBodyParam())
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("reading body: %s", err)
	}
	if string(got) != body {
		t.Errorf("body = %q, want %q", got, body)
	}
	if req.query.Get("validate_only") != "true" {
		t.Errorf("validate_only = %q, want true", req.query.Get("validate_only"))
	}
}

type fakeResponse struct {
	code int
	body string
}

func (r fakeResponse) Code() int                  { return r.code }
func (r fakeResponse) Message() string            { return "" }
func (r fakeResponse) GetHeader(string) string    { return "" }
func (r fakeResponse) GetHeaders(string) []string { return nil }
func (r fakeResponse) Body() io.ReadCloser        { return io.NopCloser(strings.NewReader(r.body)) }

// readDefinitionSummaries runs response through the combined definitions
// reader override installed over the generated reader.
func readDefinitionSummaries(response runtime.ClientResponse) (any, definitionSummaryResponse, error) {
	var out definitionSummaryResponse
	op := &runtime.ClientOperation{Reader: &workflows.WorkflowDefinitionsCombinedReader{}}
	withDefinitionSummaryReader(&out)(op)

	result, err := op.Reader.ReadResponse(response, runtime.JSONConsumer())
	return result, out, err
}

// TestDefinitionSummaryReaderDecodesObjectParameters uses the shape the API
// returns for an on-demand trigger with inputs, which the generated model
// cannot decode because it types trigger.parameters as a string.
func TestDefinitionSummaryReaderDecodesObjectParameters(t *testing.T) {
	t.Parallel()

	body := `{
		"meta": {"pagination": {"total": 1}},
		"resources": [{
			"id": "b383d140fd9f409a98a6007d1608aad3",
			"name": "example",
			"trigger": {
				"name": "On demand",
				"type": "On demand",
				"parameters": {"type": "object", "properties": {"hash": {"type": "string"}}}
			},
			"enabled": true,
			"has_validation_errors": false,
			"version": 3
		}]
	}`

	result, got, err := readDefinitionSummaries(fakeResponse{code: 200, body: body})
	if err != nil {
		t.Fatalf("ReadResponse returned error: %s", err)
	}
	if _, ok := result.(*workflows.WorkflowDefinitionsCombinedOK); !ok {
		t.Errorf("result = %T, want *workflows.WorkflowDefinitionsCombinedOK", result)
	}

	want := definitionSummary{
		ID:                  "b383d140fd9f409a98a6007d1608aad3",
		Name:                "example",
		Enabled:             true,
		HasValidationErrors: false,
	}
	if len(got.Resources) != 1 || got.Resources[0] != want {
		t.Errorf("resources = %+v, want [%+v]", got.Resources, want)
	}
}

func TestDefinitionSummaryReaderDelegatesErrors(t *testing.T) {
	t.Parallel()

	_, got, err := readDefinitionSummaries(
		fakeResponse{code: 403, body: `{"errors":[{"code":403,"message":"access denied"}]}`},
	)

	var forbidden *workflows.WorkflowDefinitionsCombinedForbidden
	if !errors.As(err, &forbidden) {
		t.Errorf("error = %T, want *workflows.WorkflowDefinitionsCombinedForbidden", err)
	}
	if got.Resources != nil {
		t.Errorf("resources = %+v, want nil for a non-200 response", got.Resources)
	}
}
