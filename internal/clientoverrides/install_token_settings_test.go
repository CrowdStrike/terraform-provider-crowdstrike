package clientoverrides

import (
	"encoding/json"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/installation_tokens_settings"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/strfmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSendInstallTokensRequired sends requests through the generated
// CustomerSettingsUpdate method and checks the body that would reach the API.
func TestSendInstallTokensRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		body     *models.APICustomerSettingsPatchRequestV1
		opts     []installation_tokens_settings.ClientOption
		expected string
	}{
		{
			name:     "false is sent",
			body:     &models.APICustomerSettingsPatchRequestV1{TokensRequired: false},
			opts:     []installation_tokens_settings.ClientOption{SendInstallTokensRequired},
			expected: `{"tokens_required":false}`,
		},
		{
			name:     "true is sent",
			body:     &models.APICustomerSettingsPatchRequestV1{TokensRequired: true},
			opts:     []installation_tokens_settings.ClientOption{SendInstallTokensRequired},
			expected: `{"tokens_required":true}`,
		},
		{
			name:     "max active tokens kept",
			body:     &models.APICustomerSettingsPatchRequestV1{TokensRequired: false, MaxActiveTokens: 25},
			opts:     []installation_tokens_settings.ClientOption{SendInstallTokensRequired},
			expected: `{"tokens_required":false,"max_active_tokens":25}`,
		},
		{
			name:     "without the override false is dropped",
			body:     &models.APICustomerSettingsPatchRequestV1{TokensRequired: false},
			expected: `{}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			transport := &capturingTransport{}
			_, err := installation_tokens_settings.New(transport, strfmt.Default).CustomerSettingsUpdate(
				&installation_tokens_settings.CustomerSettingsUpdateParams{Body: tt.body},
				tt.opts...,
			)
			require.ErrorIs(t, err, errCaptured)

			body, err := json.Marshal(transport.request.Body)
			require.NoError(t, err)
			assert.JSONEq(t, tt.expected, string(body))
		})
	}
}

// TestSendInstallTokensRequiredWithoutBody checks that a request without a body is
// left untouched.
func TestSendInstallTokensRequiredWithoutBody(t *testing.T) {
	t.Parallel()

	transport := &capturingTransport{}
	_, err := installation_tokens_settings.New(transport, strfmt.Default).CustomerSettingsUpdate(
		&installation_tokens_settings.CustomerSettingsUpdateParams{},
		SendInstallTokensRequired,
	)
	require.ErrorIs(t, err, errCaptured)
	assert.Nil(t, transport.request.Body)
}
