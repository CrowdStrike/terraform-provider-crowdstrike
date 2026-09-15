// Package clientoverrides holds gofalcon ClientOperation overrides that correct
// generated SDK behavior the provider cannot express through the generated models.
package clientoverrides

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"
)

// DecodeExclusionsGroups corrects the decoding of models.ExclusionsRespV1.
//
// gofalcon declares models.ExclusionsExclusionV1.Groups as []string, but the ML
// exclusion endpoints and CreateSVExclusionsV1 return an array of host group objects,
// so the generated reader fails with:
//
//	json: cannot unmarshal object into ExclusionsRespV1.resources.0.groups.0 of type string
//
// The generated reader keeps handling status codes, response headers, and error
// payloads; only the consumer that decodes the success body is substituted. Host group
// objects are reduced to their IDs, the only part of a group that reaches state.
func DecodeExclusionsGroups(op *runtime.ClientOperation) {
	op.Reader = exclusionsGroupsReader{inner: op.Reader}
}

type exclusionsGroupsReader struct {
	inner runtime.ClientResponseReader
}

func (r exclusionsGroupsReader) ReadResponse(
	response runtime.ClientResponse,
	consumer runtime.Consumer,
) (any, error) {
	return r.inner.ReadResponse(response, exclusionsGroupsConsumer{inner: consumer})
}

type exclusionsGroupsConsumer struct {
	inner runtime.Consumer
}

// Consume decodes an exclusions response body, correcting the groups field. Any other
// target is handed to the consumer the runtime picked for the operation.
func (c exclusionsGroupsConsumer) Consume(reader io.Reader, target any) error {
	payload, ok := target.(*models.ExclusionsRespV1)
	if !ok {
		return c.inner.Consume(reader, target)
	}

	decoder := json.NewDecoder(reader)
	decoder.UseNumber()

	var decoded exclusionsResp
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}

	*payload = decoded.ExclusionsRespV1
	payload.Resources = make([]*models.ExclusionsExclusionV1, 0, len(decoded.Resources))
	for _, resource := range decoded.Resources {
		if resource == nil {
			payload.Resources = append(payload.Resources, nil)
			continue
		}

		exclusion := resource.ExclusionsExclusionV1
		exclusion.Groups = resource.Groups
		payload.Resources = append(payload.Resources, &exclusion)
	}

	return nil
}

// exclusionsResp mirrors models.ExclusionsRespV1 with resources whose groups decode
// through hostGroupIDs. Embedding keeps every other field in step with the generated
// model, and the shallower Resources field wins during decoding.
type exclusionsResp struct {
	models.ExclusionsRespV1
	Resources []*exclusionResource `json:"resources"`
}

type exclusionResource struct {
	models.ExclusionsExclusionV1
	Groups hostGroupIDs `json:"groups"`
}

// hostGroupIDs holds host group IDs decoded from a groups field that the API returns
// as either an array of host group objects or an array of bare IDs.
type hostGroupIDs []string

// UnmarshalJSON accepts both shapes and keeps only the IDs. Groups with an empty ID are
// dropped: in Flight Control setups the API returns placeholder groups with no ID for
// host groups assigned in a child CID.
func (h *hostGroupIDs) UnmarshalJSON(data []byte) error {
	var groups []*struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &groups); err == nil {
		ids := make(hostGroupIDs, 0, len(groups))
		for _, group := range groups {
			if group != nil && group.ID != "" {
				ids = append(ids, group.ID)
			}
		}
		*h = ids
		return nil
	}

	var ids []string
	if err := json.Unmarshal(data, &ids); err != nil {
		return fmt.Errorf("groups: expected host group objects or IDs: %w", err)
	}
	*h = ids

	return nil
}
