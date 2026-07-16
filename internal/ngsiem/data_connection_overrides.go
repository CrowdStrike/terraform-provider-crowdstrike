package ngsiem

import (
	"io"

	"github.com/crowdstrike/gofalcon/falcon/client/ngsiem"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// The generated gofalcon request models tag enable_host_enrichment and
// enable_user_enrichment as `json:",omitempty"`, so an explicit false is
// dropped from the request body and the server applies its own default (true).
// Both fields are required in this resource's schema, so a user's false must
// reach the API. The structs below embed the generated model and shadow the two
// bool fields without omitempty; Go's JSON encoder gives the outer field
// priority, so all other fields marshal from the embedded model normally while
// the enrichment flags always serialize. These are wired in via a ClientOption
// that overrides the operation's Params, avoiding an SDK regeneration.

type createDataConnectionRequestOverride struct {
	models.DataconnectionmanagementCreateDataConnectionRequest
	EnableHostEnrichment bool `json:"enable_host_enrichment"`
	EnableUserEnrichment bool `json:"enable_user_enrichment"`
}

type updateDataConnectionRequestOverride struct {
	models.DataconnectionmanagementUpdateDataConnectionRequest
	EnableHostEnrichment bool `json:"enable_host_enrichment"`
	EnableUserEnrichment bool `json:"enable_user_enrichment"`
}

// createDataConnectionParamsOverride serializes the create request body using
// the enrichment-corrected struct. It mirrors the generated
// ExternalCreateDataConnectionParams.WriteToRequest (body only).
type createDataConnectionParamsOverride struct {
	body *createDataConnectionRequestOverride
}

func (p *createDataConnectionParamsOverride) WriteToRequest(r runtime.ClientRequest, _ strfmt.Registry) error {
	if p.body != nil {
		if err := r.SetBodyParam(p.body); err != nil {
			return err
		}
	}
	return nil
}

// updateDataConnectionParamsOverride serializes the update request body using
// the enrichment-corrected struct. It mirrors the generated
// ExternalUpdateDataConnectionParams.WriteToRequest, including the required
// `ids` query param.
type updateDataConnectionParamsOverride struct {
	body *updateDataConnectionRequestOverride
	ids  string
}

func (p *updateDataConnectionParamsOverride) WriteToRequest(r runtime.ClientRequest, _ strfmt.Registry) error {
	var res []error
	if p.body != nil {
		if err := r.SetBodyParam(p.body); err != nil {
			return err
		}
	}
	if p.ids != "" {
		if err := r.SetQueryParam("ids", p.ids); err != nil {
			return err
		}
	}
	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// withCreateEnrichmentOverride returns a ClientOption that swaps in the
// enrichment-corrected create body serializer.
func withCreateEnrichmentOverride(body *models.DataconnectionmanagementCreateDataConnectionRequest) ngsiem.ClientOption {
	return func(op *runtime.ClientOperation) {
		op.Params = &createDataConnectionParamsOverride{
			body: &createDataConnectionRequestOverride{
				DataconnectionmanagementCreateDataConnectionRequest: *body,
				EnableHostEnrichment: body.EnableHostEnrichment,
				EnableUserEnrichment: body.EnableUserEnrichment,
			},
		}
	}
}

// withUpdateEnrichmentOverride returns a ClientOption that swaps in the
// enrichment-corrected update body serializer, preserving the `ids` query param.
func withUpdateEnrichmentOverride(body *models.DataconnectionmanagementUpdateDataConnectionRequest, ids string) ngsiem.ClientOption {
	return func(op *runtime.ClientOperation) {
		op.Params = &updateDataConnectionParamsOverride{
			body: &updateDataConnectionRequestOverride{
				DataconnectionmanagementUpdateDataConnectionRequest: *body,
				EnableHostEnrichment: body.EnableHostEnrichment,
				EnableUserEnrichment: body.EnableUserEnrichment,
			},
			ids: ids,
		}
	}
}

// The ExternalCreateConnectorConfig 201 body is the standard envelope
// `{ meta, resources: { id } }`, but the generated reader parses it into
// DataconnectionmanagementGenericCreateResponse, whose `id` is a top-level
// field. The real id lives under `resources.id`, so the generated Payload.ID is
// always nil. The reader below parses the correct envelope shape so the created
// id is available directly, avoiding a list-and-diff scan of the connector's
// configs. It is wired in via a ClientOption that overrides the operation's
// Reader.

// createConnectorConfigResponse mirrors the 201 envelope the API actually
// returns for ExternalCreateConnectorConfig.
type createConnectorConfigResponse struct {
	Meta      *models.MsaMetaInfo                                   `json:"meta"`
	Errors    []*models.MsaAPIError                                 `json:"errors"`
	Resources *models.DataconnectionmanagementGenericCreateResponse `json:"resources"`
}

// createConnectorConfigReader deserializes the ExternalCreateConnectorConfig 201
// response into createConnectorConfigResponse, delegating all other status codes
// to the generated reader.
type createConnectorConfigReader struct {
	original runtime.ClientResponseReader
	response *createConnectorConfigResponse
}

func (r *createConnectorConfigReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	if response.Code() == 201 {
		body := &createConnectorConfigResponse{}
		if err := consumer.Consume(response.Body(), body); err != nil && err != io.EOF {
			return nil, err
		}
		r.response = body
		return ngsiem.NewExternalCreateConnectorConfigCreated(), nil
	}
	return r.original.ReadResponse(response, consumer)
}

// withCreateConnectorConfigReader returns a ClientOption that swaps in a reader
// parsing the real 201 envelope. The reader stores the parsed body so the
// caller can read the created config id after the call returns.
func withCreateConnectorConfigReader(reader *createConnectorConfigReader) ngsiem.ClientOption {
	return func(op *runtime.ClientOperation) {
		reader.original = op.Reader
		op.Reader = reader
	}
}

// The ExternalRegenerateDataConnectionToken 200 body is the standard envelope
// `{ meta, resources: { token, ingest_url, created_at, expires_at } }`, but the
// generated model types `resources` as an array
// (`[]*DataconnectionmanagementConnectionToken`) while the API returns a single
// object. The generated reader therefore fails with "cannot unmarshal object
// into ... resources of type []*...". The reader below parses the real object
// shape. Other status codes (notably 202 ConnectionNotReady) are delegated to
// the generated reader.

// regenerateTokenResponse mirrors the 200 envelope the API actually returns for
// ExternalRegenerateDataConnectionToken.
type regenerateTokenResponse struct {
	Meta      *models.MsaMetaInfo                             `json:"meta"`
	Errors    []*models.MsaAPIError                           `json:"errors"`
	Resources *models.DataconnectionmanagementConnectionToken `json:"resources"`
}

// regenerateTokenReader deserializes the ExternalRegenerateDataConnectionToken
// 200 response into regenerateTokenResponse, delegating all other status codes
// to the generated reader.
type regenerateTokenReader struct {
	original runtime.ClientResponseReader
	response *regenerateTokenResponse
}

func (r *regenerateTokenReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (any, error) {
	if response.Code() == 200 {
		body := &regenerateTokenResponse{}
		if err := consumer.Consume(response.Body(), body); err != nil && err != io.EOF {
			return nil, err
		}
		r.response = body
		return ngsiem.NewExternalRegenerateDataConnectionTokenOK(), nil
	}
	return r.original.ReadResponse(response, consumer)
}

// withRegenerateTokenReader returns a ClientOption that swaps in a reader
// parsing the real 200 envelope. The reader stores the parsed body so the caller
// can read the minted token after the call returns.
func withRegenerateTokenReader(reader *regenerateTokenReader) ngsiem.ClientOption {
	return func(op *runtime.ClientOperation) {
		reader.original = op.Reader
		op.Reader = reader
	}
}
