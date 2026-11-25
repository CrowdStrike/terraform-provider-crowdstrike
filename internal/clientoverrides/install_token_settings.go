package clientoverrides

import (
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// SendInstallTokensRequired always includes tokens_required in a CustomerSettingsUpdate
// request body.
//
// gofalcon declares models.APICustomerSettingsPatchRequestV1.TokensRequired as a bool
// with omitempty, so false is never sent. The API leaves settings that are missing
// from the body unchanged, so a request that turns the requirement off has no effect
// and the CID keeps requiring installation tokens. The generated writer still sets the
// timeout and body; only the body is replaced with a copy that always carries
// tokens_required.
func SendInstallTokensRequired(op *runtime.ClientOperation) {
	op.Params = sendInstallTokensRequiredWriter{inner: op.Params}
}

type sendInstallTokensRequiredWriter struct {
	inner runtime.ClientRequestWriter
}

func (w sendInstallTokensRequiredWriter) WriteToRequest(
	request runtime.ClientRequest,
	registry strfmt.Registry,
) error {
	if err := w.inner.WriteToRequest(request, registry); err != nil {
		return err
	}

	body, ok := request.GetBodyParam().(*models.APICustomerSettingsPatchRequestV1)
	if !ok || body == nil {
		return nil
	}

	return request.SetBodyParam(installTokenSettingsReq{
		APICustomerSettingsPatchRequestV1: *body,
		TokensRequired:                    body.TokensRequired,
	})
}

// installTokenSettingsReq mirrors models.APICustomerSettingsPatchRequestV1. Embedding
// keeps every other field in step with the generated model, and the shallower
// TokensRequired field wins during encoding.
type installTokenSettingsReq struct {
	models.APICustomerSettingsPatchRequestV1
	TokensRequired bool `json:"tokens_required"`
}
