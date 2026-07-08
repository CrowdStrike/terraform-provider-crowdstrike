package correlationrules

import (
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// The gofalcon-generated patch models tag several fields with `omitempty`,
// which drops empty strings and `false` booleans from the JSON body. The
// correlation rules API supports clearing those fields (description, comment,
// case_template_id, notification config_id/plugin_id/severity) and flipping
// use_ingest_time back to false via PATCH, so the `omitempty` tags turn real
// API capabilities into perceived limitations.
//
// The types below embed the generated models and shadow the problematic
// fields with pointer variants. A nil pointer still serializes as "absent"
// (via omitempty on the outer tag), but a non-nil pointer to an empty string
// or to `false` serializes as an explicit value. Go's encoder prefers the
// outer field over the embedded field for matching JSON tags, so all other
// fields keep marshaling from the embedded struct. See
// agentic-docs/docs/go-openapi-client-operation-overrides.md for the pattern.

type patchRuleNotificationConfig struct {
	models.CorrelationrulesapiPatchRuleNotificationConfigV1

	ConfigID *string `json:"config_id,omitempty"`
	PluginID *string `json:"plugin_id,omitempty"`
	Severity *string `json:"severity,omitempty"`
}

type patchRuleNotification struct {
	models.CorrelationrulesapiPatchRuleNotificationsV1

	Config *patchRuleNotificationConfig `json:"config,omitempty"`
}

type patchRuleSearch struct {
	models.CorrelationrulesapiPatchRuleSearchV1

	CaseTemplateID *string `json:"case_template_id,omitempty"`
	UseIngestTime  *bool   `json:"use_ingest_time,omitempty"`
}

type rulePatchRequest struct {
	models.CorrelationrulesapiRulePatchRequestV1

	Description            *string                  `json:"description,omitempty"`
	Comment                *string                  `json:"comment,omitempty"`
	Search                 *patchRuleSearch         `json:"search,omitempty"`
	Notifications          []*patchRuleNotification `json:"notifications"`
	GuardrailNotifications []*patchRuleNotification `json:"guardrail_notifications"`
}

// patchRuleParams implements runtime.ClientRequestWriter so the shadowed body
// replaces the generated params writer on the Update call.
type patchRuleParams struct {
	Body []*rulePatchRequest
}

func (p *patchRuleParams) WriteToRequest(r runtime.ClientRequest, _ strfmt.Registry) error {
	if p.Body == nil {
		return nil
	}
	return r.SetBodyParam(p.Body)
}
