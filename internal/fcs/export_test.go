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
	AzureTenantFeatures          = azureTenantFeatures
	EventhubSettings             = eventhubSettings
)

var (
	NewSettingsConfig               = newSettingsConfig
	BuildProductsFromModel          = (*cloudAWSAccountResource).buildProductsFromModel
	UpdateFeatureStatesFromProducts = updateFeatureStatesFromProducts
	BuildPatchAccount               = buildPatchAccount

	FlattenEventhubSettings    = flattenEventhubSettings
	FlattenAzureTenantFeatures = flattenAzureTenantFeatures
	EventhubSettingsAttrTypes  = eventhubSettings{}.attrTypes
)
