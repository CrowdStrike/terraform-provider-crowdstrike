package dataprotection

import (
	"errors"
	"io"

	"github.com/crowdstrike/gofalcon/falcon/client/data_protection_configuration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	openapierrors "github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// Client overrides for gofalcon defects on the data protection policy models. All
// of it goes away once gofalcon is fixed.
//
// Serialization defects, where `omitempty` on a Go value type makes the field's
// legitimate zero value unsendable:
//
//	PolicymanagerPolicyProperties.EnableScreenCapture  bool    cannot send false
//	PolicymanagerPolicyProperties.BeExcludeDomains     string  cannot send ""
//	PolicymanagerPolicyProperties.EujDialogBoxLogo     string  cannot send ""
//	PolicymanagerExternalPolicyPatch.Description       string  cannot send ""
//
// PolicymanagerEUJOption.ID is the inverse: required with no omitempty, so a nil id
// serializes as `"id":null` on a custom justification, where the key has to be
// absent entirely.
//
// be_exclude_domains and euj_dialog_box_logo are load-bearing rather than edge
// cases. Neither has a companion enum saying "ignore the text", so sending the empty
// string is the only way to clear one, and the API accepts it on both.
//
// The three collapsed message texts need no override. Each is paired with a source
// enum the provider always sends, so selecting `default` reverts the policy to
// Falcon's fixed built-in text; the stale custom text left behind is inert, and Read
// reports the attribute as null whenever the source is not `custom`. Sending "" is
// rejected outright: the API answers `400 "custom_allow_notification check failed:
// length must be at least 2 and at max 256"`, and custom_block_notification carries
// the same minimum.
//
// Model gaps, where the field exists on the wire but gofalcon does not declare it,
// so it can be neither sent nor read:
//
//	policy_properties.enable_clipboard_web_origin  bool  both platforms
//	policy_properties.enable_ocr                   bool  Mac only
//
// Each needs a request override so it can be sent on POST and PATCH, and the
// response-reader override below so the confirming read can see it. Without the
// reader half neither attribute could ever be confirmed and every non-default value
// would fail with Terraform's produced-inconsistent-result error.
//
// Each struct embeds the generated model and shadows only the affected field. Go
// resolves the shallower field first for both encoding and decoding, so every other
// field marshals and unmarshals through the embedded model unchanged. None of the
// embedded models declares a custom MarshalJSON or UnmarshalJSON, which is what
// makes the embedding safe in both directions. A shadowed field's embedded
// counterpart is never populated in either direction: `properties.BeExcludeDomains`
// resolves to the outer field, which is the one that serializes and the one the
// decoder fills, so only reaching explicitly through
// `properties.PolicymanagerPolicyProperties` would see the stale zero value.

// policyPropertiesOverride corrects the settings gofalcon cannot serialize and
// adds the two it does not model.
type policyPropertiesOverride struct {
	models.PolicymanagerPolicyProperties

	// A pointer rather than a value bool: nil omits the field, which is required
	// on Mac, and false is sendable, which the generated value type cannot
	// express.
	EnableScreenCapture *bool `json:"enable_screen_capture,omitempty"`

	// Shadowed without omitempty so the empty string reaches the wire and the
	// remote value is actually cleared.
	BeExcludeDomains string `json:"be_exclude_domains"`
	EujDialogBoxLogo string `json:"euj_dialog_box_logo"`

	// Shadowed so custom justifications can omit the id key.
	EujDropdownOptions *eujDropdownOptionsOverride `json:"euj_dropdown_options,omitempty"`

	// Not declared by gofalcon.
	EnableClipboardWebOrigin *bool `json:"enable_clipboard_web_origin,omitempty"`
	EnableOCR                *bool `json:"enable_ocr,omitempty"`
}

// eujOptionOverride corrects PolicymanagerEUJOption, whose required id carries no
// omitempty and therefore serializes as `"id":null` when nil. The two built-in
// justifications must send an id equal to their own text, and custom
// justifications must omit the key entirely, which only omitempty can express.
type eujOptionOverride struct {
	Default       *bool   `json:"default"`
	ID            *string `json:"id,omitempty"`
	Justification *string `json:"justification"`
	Selected      *bool   `json:"selected"`
}

// eujDropdownOptionsOverride mirrors PolicymanagerEUJDropdownOptions with the
// corrected option type.
type eujDropdownOptionsOverride struct {
	Justifications []*eujOptionOverride `json:"justifications"`
}

// policyPostOverride carries the corrected settings on the create body.
type policyPostOverride struct {
	models.PolicymanagerExternalPolicyPost
	PolicyProperties *policyPropertiesOverride `json:"policy_properties,omitempty"`
}

// policyCreateRequestOverride mirrors PolicymanagerCreatePoliciesRequest with the
// corrected resource element type.
type policyCreateRequestOverride struct {
	Resources []*policyPostOverride `json:"resources"`
}

// policyPatchOverride sends description on every update so a description that is
// removed from configuration is actually cleared remotely. Without this the
// generated omitempty drops the empty string and the API preserves the old value.
// It also carries the corrected settings.
type policyPatchOverride struct {
	models.PolicymanagerExternalPolicyPatch
	Description      string                    `json:"description"`
	PolicyProperties *policyPropertiesOverride `json:"policy_properties"`
}

// policyUpdateRequestOverride mirrors PolicymanagerUpdatePoliciesRequest with the
// corrected resource element type.
type policyUpdateRequestOverride struct {
	Resources []*policyPatchOverride `json:"resources"`
}

// policyBodyParamsOverride serializes a request body using the corrected structs.
// It delegates to the generated params writer so the request keeps everything the
// call site configured, notably the per-request timeout and the required
// platform_name query parameter, then replaces the body.
type policyBodyParamsOverride struct {
	generated runtime.ClientRequestWriter
	body      any
}

func (p *policyBodyParamsOverride) WriteToRequest(
	r runtime.ClientRequest,
	reg strfmt.Registry,
) error {
	if p.generated != nil {
		if err := p.generated.WriteToRequest(r, reg); err != nil {
			return err
		}
	}

	if p.body != nil {
		if err := r.SetBodyParam(p.body); err != nil {
			return err
		}
	}

	return nil
}

// withPolicyPostOverride returns a ClientOption that swaps in a create body whose
// policy_properties carries the fields gofalcon does not model.
func withPolicyPostOverride(
	body *policyCreateRequestOverride,
) data_protection_configuration.ClientOption {
	return withPolicyBodyOverride(body)
}

// withPolicyPatchOverride returns a ClientOption that swaps in the
// clearing-capable update body serializer.
func withPolicyPatchOverride(
	body *policyUpdateRequestOverride,
) data_protection_configuration.ClientOption {
	return withPolicyBodyOverride(body)
}

// withPolicyBodyOverride replaces the operation's params writer with one that
// delegates to the generated writer and then substitutes the corrected body.
func withPolicyBodyOverride(body any) data_protection_configuration.ClientOption {
	return func(op *runtime.ClientOperation) {
		op.Params = &policyBodyParamsOverride{generated: op.Params, body: body}
	}
}

// policiesResponseOverride mirrors PolicymanagerPoliciesResponse with the extended
// resource type. Only `resources` is shadowed, so `meta` and `errors` decode into
// the embedded model and stay usable for payload-error classification.
type policiesResponseOverride struct {
	models.PolicymanagerPoliciesResponse
	Resources []*policyOverride `json:"resources"`
}

// policyOverride mirrors PolicymanagerExternalPolicy with the extended properties.
type policyOverride struct {
	models.PolicymanagerExternalPolicy
	PolicyProperties *policyPropertiesOverride `json:"policy_properties"`
}

// policyGetReaderOverride reads the policy GET response into the extended models.
//
// The generated client method returns a concrete *EntitiesPolicyGetV2OK and type
// asserts on it, so a 200 still has to produce one. The extended resources
// therefore travel out through this struct rather than through the response, and
// the caller reads them from extended after the call returns.
//
// Every other status code is delegated to the generated reader untouched, so the
// typed errors tferrors already understands keep being produced and the body is
// not consumed twice.
type policyGetReaderOverride struct {
	generated runtime.ClientResponseReader
	extended  *policiesResponseOverride
}

func (o *policyGetReaderOverride) ReadResponse(
	response runtime.ClientResponse,
	consumer runtime.Consumer,
) (any, error) {
	if response.Code() != 200 {
		return o.generated.ReadResponse(response, consumer)
	}

	// Reproduces the generated EntitiesPolicyGetV2OK.readResponse, which is
	// unexported and cannot be reused.
	result := data_protection_configuration.NewEntitiesPolicyGetV2OK()

	if traceID := response.GetHeader("X-CS-TRACEID"); traceID != "" {
		result.XCSTRACEID = traceID
	}

	if limit := response.GetHeader("X-RateLimit-Limit"); limit != "" {
		value, err := swag.ConvertInt64(limit)
		if err != nil {
			return nil, openapierrors.InvalidType("X-RateLimit-Limit", "header", "int64", limit)
		}
		result.XRateLimitLimit = value
	}

	if remaining := response.GetHeader("X-RateLimit-Remaining"); remaining != "" {
		value, err := swag.ConvertInt64(remaining)
		if err != nil {
			return nil, openapierrors.InvalidType("X-RateLimit-Remaining", "header", "int64", remaining)
		}
		result.XRateLimitRemaining = value
	}

	extended := new(policiesResponseOverride)
	if err := consumer.Consume(response.Body(), extended); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	o.extended = extended

	// The embedded model carries meta and errors, so the existing payload-error
	// classification keeps working on the returned response.
	result.Payload = &extended.PolicymanagerPoliciesResponse

	return result, nil
}

// withPolicyGetOverride returns the reader that collects the extended resources
// and the ClientOption that installs it. The reader is returned rather than
// reached through the response because the generated response type cannot hold
// the extended resources.
func withPolicyGetOverride() (*policyGetReaderOverride, data_protection_configuration.ClientOption) {
	reader := &policyGetReaderOverride{}

	return reader, func(op *runtime.ClientOperation) {
		reader.generated = op.Reader
		op.Reader = reader
	}
}
