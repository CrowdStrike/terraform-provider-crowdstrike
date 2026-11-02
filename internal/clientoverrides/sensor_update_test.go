package clientoverrides

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/sensor_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOmitSensorUpdateBuild sends requests through the generated
// UpdateSensorUpdatePoliciesV2 method and checks the body that would reach the API.
func TestOmitSensorUpdateBuild(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		settings *models.SensorUpdateSettingsReqV2
		opts     []sensor_update_policies.ClientOption
		expected string
	}{
		{
			name: "build dropped, siblings kept",
			settings: &models.SensorUpdateSettingsReqV2{
				Build:               "19004",
				UninstallProtection: "ENABLED",
				Variants: []*models.SensorUpdateBuildReqV1{
					{Build: utils.Addr("19312"), Platform: utils.Addr("LinuxArm64")},
				},
				Scheduler: &models.PolicySensorUpdateScheduler{
					Enabled:  utils.Addr(true),
					Timezone: utils.Addr("Etc/UTC"),
					Schedules: []*models.PolicySensorUpdateSchedule{
						{Start: utils.Addr("02:00"), End: utils.Addr("06:00"), Days: []int64{1}},
					},
				},
			},
			opts: []sensor_update_policies.ClientOption{OmitSensorUpdateBuild},
			expected: `{"resources":[{"id":"policy-1","name":"name","description":"desc","settings":{
				"uninstall_protection":"ENABLED",
				"variants":[{"build":"19312","platform":"LinuxArm64"}],
				"scheduler":{"enabled":true,"timezone":"Etc/UTC","schedules":[{"start":"02:00","end":"06:00","days":[1]}]}
			}}]}`,
		},
		{
			name:     "empty build dropped",
			settings: &models.SensorUpdateSettingsReqV2{Build: ""},
			opts:     []sensor_update_policies.ClientOption{OmitSensorUpdateBuild},
			expected: `{"resources":[{"id":"policy-1","name":"name","description":"desc","settings":{"variants":null,"scheduler":null}}]}`,
		},
		{
			name:     "no settings",
			opts:     []sensor_update_policies.ClientOption{OmitSensorUpdateBuild},
			expected: `{"resources":[{"id":"policy-1","name":"name","description":"desc"}]}`,
		},
		{
			name:     "without the override an empty build is still sent",
			settings: &models.SensorUpdateSettingsReqV2{Build: ""},
			expected: `{"resources":[{"id":"policy-1","name":"name","description":"desc","settings":{"build":"","variants":null,"scheduler":null}}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			transport := &capturingTransport{}
			_, err := sensor_update_policies.New(transport, strfmt.Default).UpdateSensorUpdatePoliciesV2(
				&sensor_update_policies.UpdateSensorUpdatePoliciesV2Params{
					Body: &models.SensorUpdateUpdatePoliciesReqV2{
						Resources: []*models.SensorUpdateUpdatePolicyReqV2{
							{ID: utils.Addr("policy-1"), Name: "name", Description: "desc", Settings: tt.settings},
						},
					},
				},
				tt.opts...,
			)
			require.ErrorIs(t, err, errCaptured)

			body, err := json.Marshal(transport.request.Body)
			require.NoError(t, err)
			assert.JSONEq(t, tt.expected, string(body))
		})
	}
}

var errCaptured = errors.New("request captured")

// capturingTransport writes the operation's params onto a request and stops before
// anything is sent.
type capturingTransport struct {
	request runtime.TestClientRequest
}

func (c *capturingTransport) Submit(op *runtime.ClientOperation) (any, error) {
	if err := op.Params.WriteToRequest(&c.request, strfmt.Default); err != nil {
		return nil, err
	}
	return nil, errCaptured
}
