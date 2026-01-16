package fcs

type (
	CloudAWSAccountResource      = cloudAWSAccountResource
	CloudAWSAccountModel         = cloudAWSAccountModel
	AssetInventoryOptions        = assetInventoryOptions
	RealtimeVisibilityOptions    = realtimeVisibilityOptions
	IDPOptions                   = idpOptions
	SensorManagementOptions      = sensorManagementOptions
	DSPMOptions                  = dspmOptions
	VulnerabilityScanningOptions = vulnerabilityScanningOptions
	SettingsConfig               = settingsConfig
)

var (
	NewSettingsConfig               = newSettingsConfig
	BuildProductsFromModel          = (*cloudAWSAccountResource).buildProductsFromModel
	UpdateFeatureStatesFromProducts = updateFeatureStatesFromProducts
)
