package sensorupdatepolicy

import (
	"errors"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/sensor_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/stretchr/testify/assert"
)

func TestNewAPIError(t *testing.T) {
	t.Parallel()

	var code int32 = 400
	const guidanceMsg = "build value may be incorrect or no longer supported"

	tests := []struct {
		name         string
		err          error
		wantGuidance bool
	}{
		{
			name: "invalid build on create",
			err: &sensor_update_policies.CreateSensorUpdatePoliciesV2BadRequest{
				Payload: &models.SensorUpdateRespV2{
					Errors: []*models.MsaAPIError{
						{Code: &code, Message: utils.Addr("invalid build 99999")},
					},
				},
			},
			wantGuidance: true,
		},
		{
			name: "invalid build on update",
			err: &sensor_update_policies.UpdateSensorUpdatePoliciesV2BadRequest{
				Payload: &models.SensorUpdateRespV2{
					Errors: []*models.MsaAPIError{
						{Code: &code, Message: utils.Addr("invalid build 99999")},
					},
				},
			},
			wantGuidance: true,
		},
		{
			name: "non-build bad request",
			err: &sensor_update_policies.CreateSensorUpdatePoliciesV2BadRequest{
				Payload: &models.SensorUpdateRespV2{
					Errors: []*models.MsaAPIError{
						{Code: &code, Message: utils.Addr("some other error")},
					},
				},
			},
			wantGuidance: false,
		},
		{
			name:         "generic error",
			err:          errors.New("connection refused"),
			wantGuidance: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := newAPIError(tferrors.Create, tt.err, apiScopesReadWrite)
			if tt.wantGuidance {
				assert.Contains(t, d.Detail(), guidanceMsg)
			} else {
				assert.NotContains(t, d.Detail(), guidanceMsg)
			}
		})
	}
}
