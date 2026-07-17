package sensorupdatepolicy

type (
	SensorUpdatePoliciesDataSource      = sensorUpdatePoliciesDataSource
	SensorUpdatePoliciesDataSourceModel = sensorUpdatePoliciesDataSourceModel
	SensorUpdatePolicyResourceModel     = sensorUpdatePolicyResourceModel
	PolicyRef                           = policyRef
)

var (
	FilterPoliciesByIDs        = filterPoliciesByIDs
	FilterPoliciesByAttributes = filterPoliciesByAttributes
	WrapSensorUpdatePolicy     = (*sensorUpdatePolicyResourceModel).wrap

	FilterPoliciesByCID = filterPoliciesByCID
	DistinctCIDs        = distinctCIDs
	StripChecksum       = stripChecksum
)

// NewPolicyRef builds a policyRef for tests in the external test package.
func NewPolicyRef(id, cid, name string) policyRef {
	return policyRef{id: id, cid: cid, name: name}
}
