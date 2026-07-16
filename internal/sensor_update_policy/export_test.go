package sensorupdatepolicy

type (
	SensorUpdatePoliciesDataSource      = sensorUpdatePoliciesDataSource
	SensorUpdatePoliciesDataSourceModel = sensorUpdatePoliciesDataSourceModel
	SensorUpdatePolicyResourceModel     = sensorUpdatePolicyResourceModel
)

var (
	FilterPoliciesByIDs        = filterPoliciesByIDs
	FilterPoliciesByAttributes = filterPoliciesByAttributes
	WrapSensorUpdatePolicy     = (*sensorUpdatePolicyResourceModel).wrap
)
