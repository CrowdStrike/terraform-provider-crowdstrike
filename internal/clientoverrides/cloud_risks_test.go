package clientoverrides

import (
	"io"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCloudRisksConsumer covers the remediation plan and risk summary shapes a cloud
// risks response can carry. Every one of them must decode without error.
func TestCloudRisksConsumer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{
			name: "object fields",
			body: `{"resources":[{"id":"risk-1","remediation_plan":{"summary":"fix it","steps":[{"title":"step one","confidence":"High","links":[{"label":"View remediation","target":"identityIsAdmin"}],"prerequisites":["access"],"validations":["check"]}]},"risk_summary":{"narrative":"an attacker could","adversaries":[]}}]}`,
		},
		{
			name: "string fields",
			body: `{"resources":[{"id":"risk-1","remediation_plan":"fix it","risk_summary":"an attacker could"}]}`,
		},
		{
			name: "null fields",
			body: `{"resources":[{"id":"risk-1","remediation_plan":null,"risk_summary":null}]}`,
		},
		{
			name: "absent fields",
			body: `{"resources":[{"id":"risk-1"}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var payload models.RisksGetCloudRisksResponse
			err := cloudRisksConsumer{inner: runtime.JSONConsumer()}.
				Consume(strings.NewReader(tt.body), &payload)
			require.NoError(t, err)

			require.Len(t, payload.Resources, 1)
			assert.Equal(t, "risk-1", *payload.Resources[0].ID)
			assert.Empty(t, payload.Resources[0].RemediationPlan)
			assert.Empty(t, payload.Resources[0].RiskSummary)
		})
	}
}

// TestCloudRisksConsumerKeepsSiblingFields guards the embedded-struct decoding:
// shadowing the remediation plan and risk summary must not drop any other field of
// the response or the risk.
func TestCloudRisksConsumerKeepsSiblingFields(t *testing.T) {
	t.Parallel()

	body := `{
		"meta": {"trace_id": "trace-1"},
		"errors": [{"code": 400, "message": "boom"}],
		"resources": [{
			"id": "risk-1",
			"account_id": "account-1",
			"account_name": "Account One",
			"asset_gcrn": "gcrn-1",
			"asset_id": "asset-1",
			"asset_name": "Asset One",
			"asset_region": "us-east-1",
			"asset_type": "instance",
			"provider": "aws",
			"rule_id": "rule-1",
			"rule_name": "Rule One",
			"rule_description": "Rule description",
			"service_category": "Compute",
			"severity": "High",
			"status": "Open",
			"first_seen": "2026-01-01T00:00:00Z",
			"last_seen": "2026-01-02T00:00:00Z",
			"resolved_at": "2026-01-03T00:00:00Z",
			"remediation_plan": {"summary": "fix it", "steps": []},
			"risk_summary": {"narrative": "an attacker could", "adversaries": []}
		}, null]
	}`

	var payload models.RisksGetCloudRisksResponse
	err := cloudRisksConsumer{inner: runtime.JSONConsumer()}.
		Consume(strings.NewReader(body), &payload)
	require.NoError(t, err)

	require.NotNil(t, payload.Meta)
	assert.Equal(t, "trace-1", *payload.Meta.TraceID)
	require.Len(t, payload.Errors, 1)
	assert.Equal(t, "boom", *payload.Errors[0].Message)

	require.Len(t, payload.Resources, 2)
	assert.Nil(t, payload.Resources[1])

	risk := payload.Resources[0]
	assert.Equal(t, "risk-1", *risk.ID)
	assert.Equal(t, "account-1", *risk.AccountID)
	assert.Equal(t, "Account One", *risk.AccountName)
	assert.Equal(t, "gcrn-1", *risk.AssetGcrn)
	assert.Equal(t, "asset-1", *risk.AssetID)
	assert.Equal(t, "Asset One", *risk.AssetName)
	assert.Equal(t, "us-east-1", risk.AssetRegion)
	assert.Equal(t, "instance", *risk.AssetType)
	assert.Equal(t, "aws", *risk.Provider)
	assert.Equal(t, "rule-1", *risk.RuleID)
	assert.Equal(t, "Rule One", *risk.RuleName)
	assert.Equal(t, "Rule description", *risk.RuleDescription)
	assert.Equal(t, "Compute", *risk.ServiceCategory)
	assert.Equal(t, "High", *risk.Severity)
	assert.Equal(t, "Open", *risk.Status)
	assert.Equal(t, "2026-01-01T00:00:00.000Z", risk.FirstSeen.String())
	assert.Equal(t, "2026-01-02T00:00:00.000Z", risk.LastSeen.String())
	assert.Equal(t, "2026-01-03T00:00:00.000Z", risk.ResolvedAt.String())
}

// TestCloudRisksConsumerDelegates checks that a target this override does not correct
// is handed to the consumer the runtime picked for the operation.
func TestCloudRisksConsumerDelegates(t *testing.T) {
	t.Parallel()

	var payload models.MsaspecResponseFields
	err := cloudRisksConsumer{inner: runtime.JSONConsumer()}.Consume(
		strings.NewReader(`{"errors":[{"code":403,"message":"access denied"}]}`),
		&payload,
	)
	require.NoError(t, err)

	require.Len(t, payload.Errors, 1)
	assert.Equal(t, "access denied", *payload.Errors[0].Message)
}

// TestCloudRisksConsumerEmptyBody documents that an empty body yields io.EOF, which
// the generated readers tolerate.
func TestCloudRisksConsumerEmptyBody(t *testing.T) {
	t.Parallel()

	var payload models.RisksGetCloudRisksResponse
	err := cloudRisksConsumer{inner: runtime.JSONConsumer()}.
		Consume(strings.NewReader(""), &payload)
	assert.ErrorIs(t, err, io.EOF)
}

// TestDecodeCloudRisksWrapsReader checks the ClientOption swaps the reader in place
// rather than replacing the generated one.
func TestDecodeCloudRisksWrapsReader(t *testing.T) {
	t.Parallel()

	original := runtime.ClientResponseReaderFunc(
		func(runtime.ClientResponse, runtime.Consumer) (any, error) { return nil, nil },
	)
	op := &runtime.ClientOperation{Reader: original}

	DecodeCloudRisks(op)

	wrapped, ok := op.Reader.(cloudRisksReader)
	require.True(t, ok, "expected the reader to be wrapped, got %T", op.Reader)
	assert.NotNil(t, wrapped.inner)
}
