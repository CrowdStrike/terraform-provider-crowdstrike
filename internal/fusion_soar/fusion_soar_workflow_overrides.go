package fusionsoar

import (
	"io"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client/workflows"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/clientoverrides"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// WorkflowDefinitionsUpdate is generated with a ModelsDefinitionUpdateRequestV2
// body that wraps the definition as {"id", "enabled", "Definition": {...}}. The
// API answers that shape with a 500. It accepts the definition YAML itself,
// with the workflow id as a top-level key, which is what the override below
// sends. The generated params writer still runs first so the validate_only
// query parameter and request timeout are applied. Sending application/yaml
// needs the producer registered by clientoverrides.RegisterYAMLProducer.
func withDefinitionBody(definition string) workflows.ClientOption {
	return func(op *runtime.ClientOperation) {
		op.ConsumesMediaTypes = []string{clientoverrides.YAMLMime}
		generated := op.Params
		op.Params = runtime.ClientRequestWriterFunc(func(r runtime.ClientRequest, reg strfmt.Registry) error {
			if err := generated.WriteToRequest(r, reg); err != nil {
				return err
			}
			return r.SetBodyParam(strings.NewReader(definition))
		})
	}
}

// WorkflowDefinitionsExport is generated to send both application/json and
// application/yaml as Accept values, which the API rejects with 406 Not
// Acceptable. The export is only available as YAML.
func withYAMLExport() workflows.ClientOption {
	return func(op *runtime.ClientOperation) {
		op.ProducesMediaTypes = []string{clientoverrides.YAMLMime}
	}
}

// The generated WorkflowDefinitionsCombined response models the full definition,
// but several nested types are wrong (for example trigger.parameters is typed
// as a string while the API returns an object), so decoding real workflows
// fails. The reader below decodes only the workflow metadata the provider uses;
// the definition itself is read through the YAML export.

// definitionSummary is the subset of a combined definitions entry the provider uses.
type definitionSummary struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Enabled             bool   `json:"enabled"`
	HasValidationErrors bool   `json:"has_validation_errors"`
}

type definitionSummaryResponse struct {
	Errors    []*models.MsaAPIError `json:"errors"`
	Resources []definitionSummary   `json:"resources"`
}

// withDefinitionSummaryReader returns a ClientOption that decodes a 200
// WorkflowDefinitionsCombined response into out and delegates every other
// status code to the generated reader.
func withDefinitionSummaryReader(out *definitionSummaryResponse) workflows.ClientOption {
	return func(op *runtime.ClientOperation) {
		generated := op.Reader
		op.Reader = runtime.ClientResponseReaderFunc(func(response runtime.ClientResponse, consumer runtime.Consumer) (any, error) {
			if response.Code() != 200 {
				return generated.ReadResponse(response, consumer)
			}
			if err := consumer.Consume(response.Body(), out); err != nil && err != io.EOF {
				return nil, err
			}
			return workflows.NewWorkflowDefinitionsCombinedOK(), nil
		})
	}
}
