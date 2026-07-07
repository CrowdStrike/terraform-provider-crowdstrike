package ioaexclusion

import (
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
