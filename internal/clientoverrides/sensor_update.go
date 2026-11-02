package clientoverrides

import (
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// OmitSensorUpdateBuild leaves settings.build out of an UpdateSensorUpdatePoliciesV2
// request body.
//
// gofalcon serializes models.SensorUpdateSettingsReqV2.Build without omitempty so that
// an empty string can turn off sensor updates, which means every update request carries
// a build. The API validates each build it receives, even one equal to the policy's
// current build, and rejects builds that are no longer available with:
//
//	400 invalid build 18909
//
// A request without settings.build keeps the policy's current build, so callers apply
// this override when the build is unchanged. The generated writer still sets the
// timeout and body; only the body is replaced with a copy that drops the build.
func OmitSensorUpdateBuild(op *runtime.ClientOperation) {
	op.Params = omitSensorUpdateBuildWriter{inner: op.Params}
}

type omitSensorUpdateBuildWriter struct {
	inner runtime.ClientRequestWriter
}

func (w omitSensorUpdateBuildWriter) WriteToRequest(
	request runtime.ClientRequest,
	registry strfmt.Registry,
) error {
	if err := w.inner.WriteToRequest(request, registry); err != nil {
		return err
	}

	body, ok := request.GetBodyParam().(*models.SensorUpdateUpdatePoliciesReqV2)
	if !ok || body == nil {
		return nil
	}

	return request.SetBodyParam(withoutSensorUpdateBuild(body))
}

func withoutSensorUpdateBuild(body *models.SensorUpdateUpdatePoliciesReqV2) sensorUpdatePoliciesReq {
	req := sensorUpdatePoliciesReq{
		SensorUpdateUpdatePoliciesReqV2: *body,
		Resources:                       make([]*sensorUpdatePolicyReq, 0, len(body.Resources)),
	}

	for _, resource := range body.Resources {
		if resource == nil {
			req.Resources = append(req.Resources, nil)
			continue
		}

		policy := &sensorUpdatePolicyReq{SensorUpdateUpdatePolicyReqV2: *resource}
		if resource.Settings != nil {
			policy.Settings = &sensorUpdateSettingsReq{SensorUpdateSettingsReqV2: *resource.Settings}
		}
		req.Resources = append(req.Resources, policy)
	}

	return req
}

// sensorUpdatePoliciesReq mirrors models.SensorUpdateUpdatePoliciesReqV2 with resources
// whose settings drop the build. Embedding keeps every other field in step with the
// generated model, and the shallower Resources field wins during encoding.
type sensorUpdatePoliciesReq struct {
	models.SensorUpdateUpdatePoliciesReqV2
	Resources []*sensorUpdatePolicyReq `json:"resources"`
}

type sensorUpdatePolicyReq struct {
	models.SensorUpdateUpdatePolicyReqV2
	Settings *sensorUpdateSettingsReq `json:"settings,omitempty"`
}

type sensorUpdateSettingsReq struct {
	models.SensorUpdateSettingsReqV2
	// Build shadows the embedded build and is never set, so omitempty drops the key.
	Build *string `json:"build,omitempty"`
}
