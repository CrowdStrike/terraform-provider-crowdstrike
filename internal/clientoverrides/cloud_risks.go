package clientoverrides

import (
	"encoding/json"
	"io"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"
)

// DecodeCloudRisks corrects the decoding of models.RisksGetCloudRisksResponse.
//
// gofalcon declares models.RisksUnionCloudRisk.RemediationPlan and RiskSummary as
// strings, but the CombinedCloudRisks endpoint returns both as objects (a summary with
// a list of steps, and a narrative with adversaries), so the generated reader fails
// with:
//
//	json: cannot unmarshal object into Go struct field RisksGetCloudRisksResponse.resources.0.remediation_plan of type string
//
// The generated reader keeps handling status codes, response headers, and error
// payloads; only the consumer that decodes the success body is substituted. Both
// fields are discarded, because no part of them reaches state.
func DecodeCloudRisks(op *runtime.ClientOperation) {
	op.Reader = cloudRisksReader{inner: op.Reader}
}

type cloudRisksReader struct {
	inner runtime.ClientResponseReader
}

func (r cloudRisksReader) ReadResponse(
	response runtime.ClientResponse,
	consumer runtime.Consumer,
) (any, error) {
	return r.inner.ReadResponse(response, cloudRisksConsumer{inner: consumer})
}

type cloudRisksConsumer struct {
	inner runtime.Consumer
}

// Consume decodes a cloud risks response body, skipping the remediation plan and
// risk summary. Any other target is handed to the consumer the runtime picked for
// the operation.
func (c cloudRisksConsumer) Consume(reader io.Reader, target any) error {
	payload, ok := target.(*models.RisksGetCloudRisksResponse)
	if !ok {
		return c.inner.Consume(reader, target)
	}

	decoder := json.NewDecoder(reader)
	decoder.UseNumber()

	var decoded cloudRisksResp
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}

	*payload = decoded.RisksGetCloudRisksResponse
	payload.Resources = make([]*models.RisksUnionCloudRisk, 0, len(decoded.Resources))
	for _, resource := range decoded.Resources {
		if resource == nil {
			payload.Resources = append(payload.Resources, nil)
			continue
		}

		risk := resource.RisksUnionCloudRisk
		payload.Resources = append(payload.Resources, &risk)
	}

	return nil
}

// cloudRisksResp mirrors models.RisksGetCloudRisksResponse with resources whose
// remediation plan and risk summary are accepted in any shape. Embedding keeps every
// other field in step with the generated model, and the shallower fields win during
// decoding.
type cloudRisksResp struct {
	models.RisksGetCloudRisksResponse
	Resources []*cloudRiskResource `json:"resources"`
}

type cloudRiskResource struct {
	models.RisksUnionCloudRisk
	RemediationPlan json.RawMessage `json:"remediation_plan"`
	RiskSummary     json.RawMessage `json:"risk_summary"`
}
