package ioaexclusion

import (
	"io"

	"github.com/crowdstrike/gofalcon/falcon/client/ioa_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// The gofalcon-generated V2 update model tags optional string fields with
// `omitempty`, which drops empty strings from the PATCH body. A non-nil pointer
// to an empty string lets Terraform explicitly clear a configured value while
// retaining the generated model for all other fields.
type ioaExclusionUpdateRequest struct {
	models.DomainSsIoaExclusionUpdateReqV2

	Comment             *string `json:"comment,omitempty"`
	Description         *string `json:"description,omitempty"`
	GrandparentClRegex  *string `json:"grandparent_cl_regex,omitempty"`
	GrandparentIfnRegex *string `json:"grandparent_ifn_regex,omitempty"`
	ParentClRegex       *string `json:"parent_cl_regex,omitempty"`
	ParentIfnRegex      *string `json:"parent_ifn_regex,omitempty"`
}

type ioaExclusionsUpdateRequest struct {
	Exclusions []*ioaExclusionUpdateRequest `json:"exclusions"`
}

// ioaExclusionsUpdateParams implements runtime.ClientRequestWriter so the
// request body above replaces the generated update params writer.
type ioaExclusionsUpdateParams struct {
	Body *ioaExclusionsUpdateRequest
}

func (p *ioaExclusionsUpdateParams) WriteToRequest(r runtime.ClientRequest, _ strfmt.Registry) error {
	if p.Body == nil {
		return nil
	}

	return r.SetBodyParam(p.Body)
}

// ioaExclusionsCreateReader overrides the generated SsIoaExclusionsCreateV2
// reader. The live API returns HTTP 201 on a successful create, but the
// generated reader only registers a 200 success case and treats 201 as an
// unexpected APIError. This reader maps 201 onto the generated 200 success
// struct and delegates every other status code to the original reader.
type ioaExclusionsCreateReader struct {
	original *ioa_exclusions.SsIoaExclusionsCreateV2Reader
}

func (r *ioaExclusionsCreateReader) ReadResponse(
	response runtime.ClientResponse,
	consumer runtime.Consumer,
) (any, error) {
	if response.Code() == 201 {
		result := ioa_exclusions.NewSsIoaExclusionsCreateV2OK()
		result.Payload = new(models.DomainSsIoaExclusionsRespV2)
		if err := consumer.Consume(response.Body(), result.Payload); err != nil && err != io.EOF {
			return nil, err
		}
		return result, nil
	}

	return r.original.ReadResponse(response, consumer)
}
