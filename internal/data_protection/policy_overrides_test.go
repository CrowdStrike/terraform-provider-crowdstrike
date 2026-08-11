// Unit tests for the gofalcon client overrides the data protection policy resource
// installs: the corrected request bodies, the params writers that substitute them,
// and the response reader that decodes fields the generated models cannot hold.
//
// This is an internal test file so the overrides can be exercised directly. Only the
// acceptance tests need the external package, because internal/acctest pulls in the
// provider and would close an import cycle.
package dataprotection

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client/data_protection_configuration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// timeoutRecordingRequest mirrors how go-openapi builds an outgoing request: the
// per-request timeout is seeded with client.DefaultTimeout (30s) before the params
// writer runs, so a writer that never calls SetTimeout leaves the 30s cap in place.
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

// TestPolicyPatchOverrideSendsEmptyDescription is the guard against a gofalcon
// regeneration silently restoring omitempty on the patch description: without the
// override an empty description is dropped and the API preserves the old value,
// so a description removed from configuration can never be cleared.
func TestPolicyPatchOverrideSendsEmptyDescription(t *testing.T) {
	t.Parallel()

	patch := &models.PolicymanagerExternalPolicyPatch{
		ID:          utils.Addr("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		IsEnabled:   utils.Addr(false),
		Name:        "policy",
		Description: "",
	}

	generated, err := json.Marshal(patch)
	require.NoError(t, err)
	assert.NotContains(
		t,
		string(generated),
		`"description"`,
		"the generated model is expected to drop an empty description; if this fails, gofalcon was fixed and the override can be removed",
	)

	overridden, err := json.Marshal(&policyPatchOverride{
		PolicymanagerExternalPolicyPatch: *patch,
		Description:                      patch.Description,
	})
	require.NoError(t, err)
	assert.Contains(t, string(overridden), `"description":""`)
}

func TestPolicyPatchOverridePreservesOtherFields(t *testing.T) {
	t.Parallel()

	patch := &models.PolicymanagerExternalPolicyPatch{
		ID:          utils.Addr("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		IsEnabled:   utils.Addr(true),
		Name:        "policy",
		Description: "a description",
	}

	body, err := json.Marshal(&policyPatchOverride{
		PolicymanagerExternalPolicyPatch: *patch,
		Description:                      patch.Description,
	})
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(body, &decoded))

	assert.Equal(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", decoded["id"])
	assert.Equal(t, true, decoded["is_enabled"])
	assert.Equal(t, "policy", decoded["name"])
	assert.Equal(t, "a description", decoded["description"])
	// nil host_groups and policy_properties serialize as null, which the API
	// treats as "preserve" rather than "clear".
	assert.Contains(t, decoded, "host_groups")
	assert.Nil(t, decoded["host_groups"])
	assert.Contains(t, decoded, "policy_properties")
	assert.Nil(t, decoded["policy_properties"])
}

// TestPolicyPatchParamsOverrideDelegatesToGenerated proves the override keeps
// everything the generated writer contributes: the cleared per-request timeout
// and the required platform_name query parameter.
func TestPolicyPatchParamsOverrideDelegatesToGenerated(t *testing.T) {
	t.Parallel()

	generatedRan := false
	req := newTimeoutRecordingRequest()

	body := &policyUpdateRequestOverride{
		Resources: []*policyPatchOverride{{Description: ""}},
	}
	override := &policyBodyParamsOverride{
		generated: runtime.ClientRequestWriterFunc(
			func(r runtime.ClientRequest, _ strfmt.Registry) error {
				generatedRan = true
				return r.SetTimeout(0)
			},
		),
		body: body,
	}

	require.NoError(t, override.WriteToRequest(req, nil))

	assert.True(t, generatedRan, "the override must delegate to the generated writer")
	assert.True(t, req.timeoutSet, "the generated writer clears the 30s default timeout")
	assert.Equal(t, time.Duration(0), req.timeout)
	assert.Equal(t, override.body, req.GetBodyParam())
}

// TestPolicyPostParamsOverrideDelegatesToGenerated is the create-path counterpart:
// the POST body is overridden too, so the same delegation has to hold or the
// platform_name query parameter and the cleared timeout are lost.
func TestPolicyPostParamsOverrideDelegatesToGenerated(t *testing.T) {
	t.Parallel()

	generatedRan := false
	req := newTimeoutRecordingRequest()

	body := &policyCreateRequestOverride{
		Resources: []*policyPostOverride{
			{PolicyProperties: &policyPropertiesOverride{}},
		},
	}

	op := &runtime.ClientOperation{
		Params: runtime.ClientRequestWriterFunc(
			func(r runtime.ClientRequest, _ strfmt.Registry) error {
				generatedRan = true
				return r.SetTimeout(0)
			},
		),
	}
	withPolicyPostOverride(body)(op)

	params, ok := op.Params.(*policyBodyParamsOverride)
	require.True(t, ok, "the option must replace the operation params")
	require.NoError(t, params.WriteToRequest(req, nil))

	assert.True(t, generatedRan, "the override must delegate to the generated writer")
	assert.True(t, req.timeoutSet, "the generated writer clears the 30s default timeout")
	assert.Equal(t, time.Duration(0), req.timeout)
	assert.Equal(t, body, req.GetBodyParam())
}

func TestWithPolicyPatchOverrideBuildsCorrectedBody(t *testing.T) {
	t.Parallel()

	body := &policyUpdateRequestOverride{
		Resources: []*policyPatchOverride{
			{
				PolicymanagerExternalPolicyPatch: models.PolicymanagerExternalPolicyPatch{
					ID: utils.Addr("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
				},
				Description: "",
			},
			{
				PolicymanagerExternalPolicyPatch: models.PolicymanagerExternalPolicyPatch{
					ID: utils.Addr("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
				},
				Description: "kept",
			},
		},
	}

	op := &runtime.ClientOperation{}
	withPolicyPatchOverride(body)(op)

	params, ok := op.Params.(*policyBodyParamsOverride)
	require.True(t, ok, "the option must replace the operation params")
	assert.Equal(t, body, params.body)
	assert.Nil(t, params.generated, "there is no generated writer on a bare operation")
}

// clipboardWebOriginPlan is the smallest plan that drives expandPolicyProperties for
// the write-body assertions below. The three collection attributes need a typed null
// rather than a zero value, and no other setting affects the one field under test.
func clipboardWebOriginPlan() dataProtectionPolicyResourceModel {
	return dataProtectionPolicyResourceModel{
		PlatformName:             types.StringValue(platformWindows),
		Classifications:          types.SetNull(types.StringType),
		BeExcludeDomains:         types.SetNull(types.StringType),
		EujCustomDropdownOptions: types.ListNull(types.StringType),
		ClipboardWebOrigin:       types.BoolValue(true),
	}
}

// TestClipboardWebOriginReachesBothWriteBodies covers the unmodeled
// enable_clipboard_web_origin field on the write path. The assertion on the plain
// generated model is deliberate: when it starts failing, gofalcon models the field
// and the override can be deleted.
func TestClipboardWebOriginReachesBothWriteBodies(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	properties := expandPolicyProperties(
		context.Background(),
		policyWrite{plan: clipboardWebOriginPlan(), builtinHeader: "BUILT-IN HEADER SENTENCE."},
		&diags,
	)
	require.False(t, diags.HasError())

	generated, err := json.Marshal(&properties.PolicymanagerPolicyProperties)
	require.NoError(t, err)
	assert.NotContains(
		t,
		string(generated),
		`"enable_clipboard_web_origin"`,
		"the generated model is expected to drop the field; if this fails, gofalcon was fixed and the override can be removed",
	)

	post, err := json.Marshal(&policyCreateRequestOverride{
		Resources: []*policyPostOverride{
			{
				PolicymanagerExternalPolicyPost: models.PolicymanagerExternalPolicyPost{
					Name:        utils.Addr("policy"),
					Description: utils.Addr(""),
				},
				PolicyProperties: properties,
			},
		},
	})
	require.NoError(t, err)
	assert.Contains(t, string(post), `"enable_clipboard_web_origin":true`)

	patch, err := json.Marshal(&policyUpdateRequestOverride{
		Resources: []*policyPatchOverride{
			{
				PolicymanagerExternalPolicyPatch: models.PolicymanagerExternalPolicyPatch{
					ID: utils.Addr("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
				},
				PolicyProperties: properties,
			},
		},
	})
	require.NoError(t, err)
	assert.Contains(t, string(patch), `"enable_clipboard_web_origin":true`)
}

// stubClientResponse is a runtime.ClientResponse fixture. go-openapi exposes
// TestClientRequest but no response counterpart, so the reader override needs this
// to be exercised without a live transport.
type stubClientResponse struct {
	code    int
	headers map[string]string
	body    string
}

func (r stubClientResponse) Code() int { return r.code }

func (r stubClientResponse) Message() string { return http.StatusText(r.code) }

func (r stubClientResponse) GetHeader(name string) string { return r.headers[name] }

func (r stubClientResponse) GetHeaders(name string) []string {
	if value, ok := r.headers[name]; ok {
		return []string{value}
	}

	return nil
}

func (r stubClientResponse) Body() io.ReadCloser {
	return io.NopCloser(strings.NewReader(r.body))
}

// recordingResponseReader stands in for the generated reader so delegation can be
// observed.
type recordingResponseReader struct {
	calledWithCode int
}

func (r *recordingResponseReader) ReadResponse(
	response runtime.ClientResponse,
	_ runtime.Consumer,
) (any, error) {
	r.calledWithCode = response.Code()

	return nil, errors.New("delegated to the generated reader")
}

// TestPolicyGetReaderOverrideDecodesExtendedProperties covers the read half of the
// unmodeled enable_clipboard_web_origin field: without it clipboard_web_origin could
// never be confirmed and every non-default value would fail with Terraform's
// produced-inconsistent-result error.
func TestPolicyGetReaderOverrideDecodesExtendedProperties(t *testing.T) {
	t.Parallel()

	reader, option := withPolicyGetOverride()
	op := &runtime.ClientOperation{Reader: &recordingResponseReader{}}
	option(op)
	require.Same(t, reader, op.Reader, "the option must install the override reader")

	response := stubClientResponse{
		code: 200,
		headers: map[string]string{
			"X-CS-TRACEID":          "trace-id",
			"X-RateLimit-Limit":     "6000",
			"X-RateLimit-Remaining": "5999",
		},
		body: `{
			"meta": {"trace_id": "trace-id", "query_time": 0.01},
			"errors": [{"code": 404, "message": "policy not found"}],
			"resources": [{
				"id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"platform_name": "win",
				"policy_properties": {
					"enable_clipboard_web_origin": true,
					"inspection_depth": "deep_scan",
					"euj_dialog_timeout": 300
				}
			}]
		}`,
	}

	result, err := reader.ReadResponse(response, runtime.JSONConsumer())
	require.NoError(t, err)

	ok, isOK := result.(*data_protection_configuration.EntitiesPolicyGetV2OK)
	require.True(t, isOK, "a 200 must still produce the concrete generated type, got %T", result)
	require.NotNil(t, ok.Payload)
	assert.Equal(t, "trace-id", ok.XCSTRACEID)
	assert.Equal(t, int64(6000), ok.XRateLimitLimit)
	assert.Equal(t, int64(5999), ok.XRateLimitRemaining)

	// meta and errors decode into the embedded model, so the existing payload-error
	// classification keeps working on the returned response.
	require.NotNil(t, ok.Payload.Meta)
	require.NotNil(t, ok.Payload.Meta.TraceID)
	assert.Equal(t, "trace-id", *ok.Payload.Meta.TraceID)
	require.Len(t, ok.Payload.Errors, 1)
	require.NotNil(t, ok.Payload.Errors[0].Code)
	assert.Equal(t, int32(404), *ok.Payload.Errors[0].Code)

	// The extended resources travel out through the reader, because the generated
	// response type cannot hold them.
	require.NotNil(t, reader.extended)
	require.Len(t, reader.extended.Resources, 1)
	policy := reader.extended.Resources[0]
	require.NotNil(t, policy.ID)
	assert.Equal(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", *policy.ID)
	require.NotNil(t, policy.PolicyProperties)
	require.NotNil(t, policy.PolicyProperties.EnableClipboardWebOrigin)
	assert.True(t, *policy.PolicyProperties.EnableClipboardWebOrigin)
	assert.Equal(t, "deep_scan", policy.PolicyProperties.InspectionDepth)
	assert.Equal(t, int32(300), policy.PolicyProperties.EujDialogTimeout)
}

// TestPolicyGetReaderOverrideDelegatesNon200 keeps the typed errors tferrors
// understands reaching the caller, and leaves the body unconsumed on those paths.
func TestPolicyGetReaderOverrideDelegatesNon200(t *testing.T) {
	t.Parallel()

	for _, code := range []int{400, 403, 404, 429, 500} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			t.Parallel()

			generated := &recordingResponseReader{}
			reader, option := withPolicyGetOverride()
			option(&runtime.ClientOperation{Reader: generated})

			result, err := reader.ReadResponse(
				stubClientResponse{code: code, body: `{"errors":[]}`},
				runtime.JSONConsumer(),
			)

			require.Error(t, err)
			assert.Nil(t, result)
			assert.Equal(t, code, generated.calledWithCode, "the generated reader must handle this code")
			assert.Nil(t, reader.extended, "a non-200 body must not be consumed by the override")
		})
	}
}
