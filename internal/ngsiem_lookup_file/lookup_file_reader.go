package lookupfile

import (
	"bytes"
	"io"

	"github.com/crowdstrike/gofalcon/falcon/client/ngsiem"
	"github.com/go-openapi/runtime"
)

// lookupFileReader is a custom response reader that captures the binary
// response body from GetLookupFile, which the generated SDK reader discards.
type lookupFileReader struct {
	buf *bytes.Buffer
}

func (r *lookupFileReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	if response.Code() == 200 {
		r.buf = &bytes.Buffer{}
		if _, err := io.Copy(r.buf, response.Body()); err != nil {
			return nil, err
		}
		return &ngsiem.GetLookupFileOK{}, nil
	}

	return nil, runtime.NewAPIError(
		"[GET /ngsiem-content/entities/lookupfiles/v1] GetLookupFile",
		response,
		response.Code(),
	)
}
