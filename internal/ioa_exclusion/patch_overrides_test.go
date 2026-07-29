package ioaexclusion

import (
	"testing"
	"time"

	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// timeoutRecordingRequest mirrors how go-openapi builds an outgoing request: the
// per-request timeout is seeded with client.DefaultTimeout (30s) before the
// params writer runs, so a writer that never calls SetTimeout leaves the 30s cap
// in place.
type timeoutRecordingRequest struct {
	runtime.TestClientRequest
	timeout    time.Duration
	timeoutSet bool
}

func newTimeoutRecordingRequest() *timeoutRecordingRequest {
	return &timeoutRecordingRequest{timeout: cr.DefaultTimeout}
}

func (r *timeoutRecordingRequest) SetTimeout(d time.Duration) error {
	r.timeout = d
	r.timeoutSet = true
	return nil
}

func TestIOAExclusionsUpdateParamsClearDefaultTimeout(t *testing.T) {
	t.Parallel()

	body := &ioaExclusionsUpdateRequest{
		Exclusions: []*ioaExclusionUpdateRequest{{}},
	}
	req := newTimeoutRecordingRequest()

	err := (&ioaExclusionsUpdateParams{Body: body}).WriteToRequest(req, nil)
	require.NoError(t, err)

	assert.True(t, req.timeoutSet, "WriteToRequest should override the default request timeout")
	assert.Equal(t, time.Duration(0), req.timeout, "request should be bounded by the operation context, not a per-request timeout")
	assert.Equal(t, body, req.GetBodyParam())
}
