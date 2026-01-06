package fcs

import (
	"context"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildProductsFromModel(t *testing.T) {
	tests := []struct {
		name     string
		model    cloudAWSAccountModel
		expected []*models.RestAccountProductRequestExtV1
	}{
		{
			name: "minimal configuration with only asset inventory",
			model: cloudAWSAccountModel{
				AssetInventory: &assetInventoryOptions{
					Enabled: types.BoolValue(true),
				},
			},
			expected: []*models.RestAccountProductRequestExtV1{
				{
					Product:  stringPtr("cspm"),
					Features: []string{"iom"},
				},
			},
		},
		{
			name: "all features enabled",
			model: cloudAWSAccountModel{
				AssetInventory: &assetInventoryOptions{
					Enabled: types.BoolValue(true),
				},
				RealtimeVisibility: &realtimeVisibilityOptions{
					Enabled: types.BoolValue(true),
				},
				SensorManagement: &sensorManagementOptions{
					Enabled: types.BoolValue(true),
				},
				DSPM: &dspmOptions{
					Enabled: types.BoolValue(true),
				},
				VulnerabilityScanning: &vulnerabilityScanningOptions{
					Enabled: types.BoolValue(true),
				},
				IDP: &idpOptions{
					Enabled: types.BoolValue(true),
				},
			},
			expected: []*models.RestAccountProductRequestExtV1{
				{
					Product:  stringPtr("cspm"),
					Features: []string{"iom", "ioa", "sensormgmt", "dspm", "vulnerability_scanning"},
				},
				{
					Product:  stringPtr("idp"),
					Features: []string{"default"},
				},
			},
		},
		{
			name: "selective features enabled",
			model: cloudAWSAccountModel{
				AssetInventory: &assetInventoryOptions{
					Enabled: types.BoolValue(true),
				},
				RealtimeVisibility: &realtimeVisibilityOptions{
					Enabled: types.BoolValue(true),
				},
				SensorManagement: &sensorManagementOptions{
					Enabled: types.BoolValue(false),
				},
				DSPM: &dspmOptions{
					Enabled: types.BoolValue(true),
				},
				VulnerabilityScanning: &vulnerabilityScanningOptions{
					Enabled: types.BoolValue(false),
				},
				IDP: &idpOptions{
					Enabled: types.BoolValue(false),
				},
			},
			expected: []*models.RestAccountProductRequestExtV1{
				{
					Product:  stringPtr("cspm"),
					Features: []string{"iom", "ioa", "dspm"},
				},
			},
		},
		{
			name: "nil feature options treated as disabled",
			model: cloudAWSAccountModel{
				AssetInventory:        nil,
				RealtimeVisibility:    nil,
				SensorManagement:      nil,
				DSPM:                  nil,
				VulnerabilityScanning: nil,
				IDP:                   nil,
			},
			expected: []*models.RestAccountProductRequestExtV1{
				{
					Product:  stringPtr("cspm"),
					Features: []string{"iom"},
				},
			},
		},
		{
			name: "only IDP enabled with asset inventory",
			model: cloudAWSAccountModel{
				AssetInventory: &assetInventoryOptions{
					Enabled: types.BoolValue(true),
				},
				RealtimeVisibility: &realtimeVisibilityOptions{
					Enabled: types.BoolValue(false),
				},
				SensorManagement: &sensorManagementOptions{
					Enabled: types.BoolValue(false),
				},
				DSPM: &dspmOptions{
					Enabled: types.BoolValue(false),
				},
				VulnerabilityScanning: &vulnerabilityScanningOptions{
					Enabled: types.BoolValue(false),
				},
				IDP: &idpOptions{
					Enabled: types.BoolValue(true),
				},
			},
			expected: []*models.RestAccountProductRequestExtV1{
				{
					Product:  stringPtr("cspm"),
					Features: []string{"iom"},
				},
				{
					Product:  stringPtr("idp"),
					Features: []string{"default"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &cloudAWSAccountResource{}
			result := r.buildProductsFromModel(tt.model)

			require.Equal(t, len(tt.expected), len(result))

			for i, expectedProduct := range tt.expected {
				assert.Equal(t, *expectedProduct.Product, *result[i].Product)
				assert.ElementsMatch(t, expectedProduct.Features, result[i].Features)
			}
		})
	}
}

func TestBuildProductsDelta(t *testing.T) {
	tests := []struct {
		name             string
		model            cloudAWSAccountModel
		currentAccount   *models.DomainCloudAWSAccountV1
		expectedEnabled  []*models.RestAccountProductRequestExtV1
		expectedDisabled []*models.RestAccountProductRequestExtV1
	}{
		{
			name: "enable new features",
			model: cloudAWSAccountModel{
				AssetInventory: &assetInventoryOptions{
					Enabled: types.BoolValue(true),
				},
				RealtimeVisibility: &realtimeVisibilityOptions{
					Enabled: types.BoolValue(true),
				},
				DSPM: &dspmOptions{
					Enabled: types.BoolValue(true),
				},
			},
			currentAccount: &models.DomainCloudAWSAccountV1{
				Products: []*models.DomainProductFeatures{
					{
						Product:  stringPtr("cspm"),
						Features: []string{"iom"},
					},
				},
			},
			expectedEnabled: []*models.RestAccountProductRequestExtV1{
				{
					Product:  stringPtr("cspm"),
					Features: []string{"ioa", "dspm"},
				},
			},
			expectedDisabled: []*models.RestAccountProductRequestExtV1{},
		},
		{
			name: "disable features",
			model: cloudAWSAccountModel{
				AssetInventory: &assetInventoryOptions{
					Enabled: types.BoolValue(true),
				},
			},
			currentAccount: &models.DomainCloudAWSAccountV1{
				Products: []*models.DomainProductFeatures{
					{
						Product:  stringPtr("cspm"),
						Features: []string{"iom", "ioa", "dspm"},
					},
					{
						Product:  stringPtr("idp"),
						Features: []string{"default"},
					},
				},
			},
			expectedEnabled: []*models.RestAccountProductRequestExtV1{},
			expectedDisabled: []*models.RestAccountProductRequestExtV1{
				{
					Product:  stringPtr("cspm"),
					Features: []string{"ioa", "dspm"},
				},
				{
					Product:  stringPtr("idp"),
					Features: []string{"default"},
				},
			},
		},
		{
			name: "mixed enable and disable",
			model: cloudAWSAccountModel{
				AssetInventory: &assetInventoryOptions{
					Enabled: types.BoolValue(true),
				},
				RealtimeVisibility: &realtimeVisibilityOptions{
					Enabled: types.BoolValue(false),
				},
				VulnerabilityScanning: &vulnerabilityScanningOptions{
					Enabled: types.BoolValue(true),
				},
				IDP: &idpOptions{
					Enabled: types.BoolValue(true),
				},
			},
			currentAccount: &models.DomainCloudAWSAccountV1{
				Products: []*models.DomainProductFeatures{
					{
						Product:  stringPtr("cspm"),
						Features: []string{"iom", "ioa", "dspm"},
					},
				},
			},
			expectedEnabled: []*models.RestAccountProductRequestExtV1{
				{
					Product:  stringPtr("cspm"),
					Features: []string{"vulnerability_scanning"},
				},
				{
					Product:  stringPtr("idp"),
					Features: []string{"default"},
				},
			},
			expectedDisabled: []*models.RestAccountProductRequestExtV1{
				{
					Product:  stringPtr("cspm"),
					Features: []string{"ioa", "dspm"},
				},
			},
		},
		{
			name: "no changes",
			model: cloudAWSAccountModel{
				AssetInventory: &assetInventoryOptions{
					Enabled: types.BoolValue(true),
				},
				RealtimeVisibility: &realtimeVisibilityOptions{
					Enabled: types.BoolValue(true),
				},
				IDP: &idpOptions{
					Enabled: types.BoolValue(true),
				},
			},
			currentAccount: &models.DomainCloudAWSAccountV1{
				Products: []*models.DomainProductFeatures{
					{
						Product:  stringPtr("cspm"),
						Features: []string{"iom", "ioa"},
					},
					{
						Product:  stringPtr("idp"),
						Features: []string{"default"},
					},
				},
			},
			expectedEnabled:  []*models.RestAccountProductRequestExtV1{},
			expectedDisabled: []*models.RestAccountProductRequestExtV1{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &cloudAWSAccountResource{}
			enabled, disabled := r.buildProductsDelta(tt.model, tt.currentAccount)

			require.Equal(t, len(tt.expectedEnabled), len(enabled))
			require.Equal(t, len(tt.expectedDisabled), len(disabled))

			// Check enabled products (order-independent)
			expectedEnabledMap := make(map[string][]string)
			for _, expectedProduct := range tt.expectedEnabled {
				expectedEnabledMap[*expectedProduct.Product] = expectedProduct.Features
			}

			for _, actualProduct := range enabled {
				expectedFeatures, exists := expectedEnabledMap[*actualProduct.Product]
				require.True(t, exists, "Unexpected enabled product: %s", *actualProduct.Product)
				assert.ElementsMatch(t, expectedFeatures, actualProduct.Features)
			}

			// Check disabled products (order-independent)
			expectedDisabledMap := make(map[string][]string)
			for _, expectedProduct := range tt.expectedDisabled {
				expectedDisabledMap[*expectedProduct.Product] = expectedProduct.Features
			}

			for _, actualProduct := range disabled {
				expectedFeatures, exists := expectedDisabledMap[*actualProduct.Product]
				require.True(t, exists, "Unexpected disabled product: %s", *actualProduct.Product)
				assert.ElementsMatch(t, expectedFeatures, actualProduct.Features)
			}
		})
	}
}

func TestUpdateFeatureStatesFromProducts(t *testing.T) {
	tests := []struct {
		name          string
		initialModel  cloudAWSAccountModel
		products      []*models.DomainProductFeatures
		cloudAccount  *models.DomainCloudAWSAccountV1
		expectedModel cloudAWSAccountModel
	}{
		{
			name: "update from products with all features",
			initialModel: cloudAWSAccountModel{
				RealtimeVisibility: &realtimeVisibilityOptions{
					Enabled: types.BoolValue(false),
				},
				SensorManagement: &sensorManagementOptions{
					Enabled: types.BoolValue(false),
				},
				DSPM: &dspmOptions{
					Enabled: types.BoolValue(false),
				},
				VulnerabilityScanning: &vulnerabilityScanningOptions{
					Enabled: types.BoolValue(false),
				},
				IDP: &idpOptions{
					Enabled: types.BoolValue(false),
				},
			},
			products: []*models.DomainProductFeatures{
				{
					Product:  stringPtr("cspm"),
					Features: []string{"iom", "ioa", "sensormgmt", "dspm", "vulnerability_scanning"},
				},
				{
					Product:  stringPtr("idp"),
					Features: []string{"default"},
				},
			},
			cloudAccount: &models.DomainCloudAWSAccountV1{
				ResourceMetadata: &models.DomainAWSAccountResourceMetadata{
					AwsCloudtrailRegion: "us-east-1",
				},
			},
			expectedModel: cloudAWSAccountModel{
				RealtimeVisibility: &realtimeVisibilityOptions{
					Enabled:          types.BoolValue(true),
					CloudTrailRegion: types.StringValue("us-east-1"),
				},
				SensorManagement: &sensorManagementOptions{
					Enabled: types.BoolValue(true),
				},
				DSPM: &dspmOptions{
					Enabled: types.BoolValue(true),
				},
				VulnerabilityScanning: &vulnerabilityScanningOptions{
					Enabled: types.BoolValue(true),
				},
				IDP: &idpOptions{
					Enabled: types.BoolValue(true),
					Status:  types.StringValue("configured"),
				},
			},
		},
		{
			name: "update with selective features",
			initialModel: cloudAWSAccountModel{
				RealtimeVisibility: &realtimeVisibilityOptions{
					Enabled: types.BoolValue(false),
				},
				SensorManagement: &sensorManagementOptions{
					Enabled: types.BoolValue(false),
				},
				DSPM: &dspmOptions{
					Enabled: types.BoolValue(false),
				},
				VulnerabilityScanning: &vulnerabilityScanningOptions{
					Enabled: types.BoolValue(false),
				},
				IDP: &idpOptions{
					Enabled: types.BoolValue(false),
				},
			},
			products: []*models.DomainProductFeatures{
				{
					Product:  stringPtr("cspm"),
					Features: []string{"iom", "dspm"},
				},
			},
			cloudAccount: &models.DomainCloudAWSAccountV1{
				ResourceMetadata: &models.DomainAWSAccountResourceMetadata{},
			},
			expectedModel: cloudAWSAccountModel{
				RealtimeVisibility: &realtimeVisibilityOptions{
					Enabled: types.BoolValue(false),
				},
				SensorManagement: &sensorManagementOptions{
					Enabled: types.BoolValue(false),
				},
				DSPM: &dspmOptions{
					Enabled: types.BoolValue(true),
				},
				VulnerabilityScanning: &vulnerabilityScanningOptions{
					Enabled: types.BoolValue(false),
				},
				IDP: &idpOptions{
					Enabled: types.BoolValue(false),
					Status:  types.StringNull(),
				},
			},
		},
		{
			name: "handle nil IDP initialization",
			initialModel: cloudAWSAccountModel{
				IDP: nil,
			},
			products: []*models.DomainProductFeatures{
				{
					Product:  stringPtr("cspm"),
					Features: []string{"iom"},
				},
			},
			cloudAccount: &models.DomainCloudAWSAccountV1{
				ResourceMetadata: &models.DomainAWSAccountResourceMetadata{},
			},
			expectedModel: cloudAWSAccountModel{
				IDP: &idpOptions{
					Enabled: types.BoolValue(false),
					Status:  types.StringNull(),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &cloudAWSAccountResource{}
			ctx := context.Background()

			r.updateFeatureStatesFromProducts(ctx, &tt.initialModel, tt.products, tt.cloudAccount)

			// Verify Asset Inventory (updateFeatureStatesFromProducts doesn't handle AssetInventory)
			// AssetInventory is handled separately in populateModelFromCloudAccount

			// Verify Realtime Visibility
			if tt.expectedModel.RealtimeVisibility != nil {
				require.NotNil(t, tt.initialModel.RealtimeVisibility)
				assert.Equal(t, tt.expectedModel.RealtimeVisibility.Enabled, tt.initialModel.RealtimeVisibility.Enabled)
				if !tt.expectedModel.RealtimeVisibility.CloudTrailRegion.IsNull() {
					assert.Equal(t, tt.expectedModel.RealtimeVisibility.CloudTrailRegion, tt.initialModel.RealtimeVisibility.CloudTrailRegion)
				}
			}

			// Verify Sensor Management
			if tt.expectedModel.SensorManagement != nil {
				require.NotNil(t, tt.initialModel.SensorManagement)
				assert.Equal(t, tt.expectedModel.SensorManagement.Enabled, tt.initialModel.SensorManagement.Enabled)
			}

			// Verify DSPM
			if tt.expectedModel.DSPM != nil {
				require.NotNil(t, tt.initialModel.DSPM)
				assert.Equal(t, tt.expectedModel.DSPM.Enabled, tt.initialModel.DSPM.Enabled)
			}

			// Verify Vulnerability Scanning
			if tt.expectedModel.VulnerabilityScanning != nil {
				require.NotNil(t, tt.initialModel.VulnerabilityScanning)
				assert.Equal(t, tt.expectedModel.VulnerabilityScanning.Enabled, tt.initialModel.VulnerabilityScanning.Enabled)
			}

			// Verify IDP
			if tt.expectedModel.IDP != nil {
				require.NotNil(t, tt.initialModel.IDP)
				assert.Equal(t, tt.expectedModel.IDP.Enabled, tt.initialModel.IDP.Enabled)
				assert.Equal(t, tt.expectedModel.IDP.Status, tt.initialModel.IDP.Status)
			}
		})
	}
}

func TestUpdateFeatureStatesFromProducts_IDPDisableTransition(t *testing.T) {
	// This test specifically addresses the IDP disable workflow issue where
	// the status field changes from "configured" to null, ensuring we handle
	// the transition correctly without causing plan/apply inconsistencies

	tests := []struct {
		name         string
		initialModel cloudAWSAccountModel
		products     []*models.DomainProductFeatures
		cloudAccount *models.DomainCloudAWSAccountV1
		description  string
	}{
		{
			name:        "IDP enabled to disabled transition",
			description: "When IDP is disabled, status should change from 'configured' to null",
			initialModel: cloudAWSAccountModel{
				IDP: &idpOptions{
					Enabled: types.BoolValue(true),
					Status:  types.StringValue("configured"), // Starting with configured status
				},
			},
			products: []*models.DomainProductFeatures{
				{
					Product:  stringPtr("cspm"),
					Features: []string{"iom"}, // No IDP product = disabled
				},
			},
			cloudAccount: &models.DomainCloudAWSAccountV1{
				ResourceMetadata: &models.DomainAWSAccountResourceMetadata{},
			},
		},
		{
			name:        "IDP already disabled remains disabled",
			description: "When IDP is already disabled, status should remain null",
			initialModel: cloudAWSAccountModel{
				IDP: &idpOptions{
					Enabled: types.BoolValue(false),
					Status:  types.StringNull(), // Already null
				},
			},
			products: []*models.DomainProductFeatures{
				{
					Product:  stringPtr("cspm"),
					Features: []string{"iom"}, // No IDP product = disabled
				},
			},
			cloudAccount: &models.DomainCloudAWSAccountV1{
				ResourceMetadata: &models.DomainAWSAccountResourceMetadata{},
			},
		},
		{
			name:        "IDP disabled to enabled transition",
			description: "When IDP is enabled, status should change from null to 'configured'",
			initialModel: cloudAWSAccountModel{
				IDP: &idpOptions{
					Enabled: types.BoolValue(false),
					Status:  types.StringNull(), // Starting with null status
				},
			},
			products: []*models.DomainProductFeatures{
				{
					Product:  stringPtr("cspm"),
					Features: []string{"iom"},
				},
				{
					Product:  stringPtr("idp"), // IDP product present = enabled
					Features: []string{"default"},
				},
			},
			cloudAccount: &models.DomainCloudAWSAccountV1{
				ResourceMetadata: &models.DomainAWSAccountResourceMetadata{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &cloudAWSAccountResource{}
			ctx := context.Background()

			// Capture initial status for comparison
			initialStatus := tt.initialModel.IDP.Status

			// Apply the update
			r.updateFeatureStatesFromProducts(ctx, &tt.initialModel, tt.products, tt.cloudAccount)

			// Verify the transition behavior
			require.NotNil(t, tt.initialModel.IDP, "IDP should not be nil after update")

			// Check if IDP should be enabled based on products
			hasIDP := false
			for _, product := range tt.products {
				if product.Product != nil && *product.Product == "idp" {
					hasIDP = true
					break
				}
			}

			// Verify enabled state matches product presence
			assert.Equal(t, hasIDP, tt.initialModel.IDP.Enabled.ValueBool(),
				"IDP enabled state should match product presence")

			// Verify status transitions correctly
			if hasIDP {
				assert.True(t, tt.initialModel.IDP.Status.ValueString() == "configured",
					"When IDP is enabled, status should be 'configured', got: %v", tt.initialModel.IDP.Status)
			} else {
				assert.True(t, tt.initialModel.IDP.Status.IsNull(),
					"When IDP is disabled, status should be null, got: %v", tt.initialModel.IDP.Status)
			}

			// Log the transition for debugging
			t.Logf("Test: %s", tt.description)
			t.Logf("Initial status: %v, Final status: %v", initialStatus, tt.initialModel.IDP.Status)
			t.Logf("Has IDP product: %v, IDP enabled: %v", hasIDP, tt.initialModel.IDP.Enabled.ValueBool())
		})
	}
}

func TestResolveAgentlessScanningRoleNameV1(t *testing.T) {
	tests := []struct {
		name         string
		cloudAccount *models.DomainCloudAWSAccountV1
		expected     string
	}{
		{
			name:         "returns empty string for nil account",
			cloudAccount: nil,
			expected:     "",
		},
		{
			name: "returns empty string for account with no settings",
			cloudAccount: &models.DomainCloudAWSAccountV1{
				AccountID: "123456789012",
			},
			expected: "",
		},
		{
			name: "returns DSPM role when available (takes precedence)",
			cloudAccount: &models.DomainCloudAWSAccountV1{
				AccountID: "123456789012",
				Settings: map[string]interface{}{
					"dspm.role":                   "MyDSPMRole",
					"vulnerability_scanning.role": "MyVulnRole",
				},
			},
			expected: "MyDSPMRole",
		},
		{
			name: "returns vulnerability scanning role when DSPM not available",
			cloudAccount: &models.DomainCloudAWSAccountV1{
				AccountID: "123456789012",
				Settings: map[string]interface{}{
					"vulnerability_scanning.role": "MyVulnRole",
				},
			},
			expected: "MyVulnRole",
		},
		{
			name: "returns DSPM role name from ARN (takes precedence)",
			cloudAccount: &models.DomainCloudAWSAccountV1{
				AccountID: "123456789012",
				Settings: map[string]interface{}{
					"dspm.role":                   "arn:aws:iam::176074773390:role/CrowdStrikeAgentlessScanningIntegrationRole",
					"vulnerability_scanning.role": "arn:aws:iam::176074773390:role/MyVulnRole",
				},
			},
			expected: "CrowdStrikeAgentlessScanningIntegrationRole",
		},
		{
			name: "returns vulnerability scanning role name from ARN when DSPM not available",
			cloudAccount: &models.DomainCloudAWSAccountV1{
				AccountID: "123456789012",
				Settings: map[string]interface{}{
					"vulnerability_scanning.role": "arn:aws:iam::176074773390:role/MyVulnRole",
				},
			},
			expected: "MyVulnRole",
		},
		{
			name: "returns empty string when no roles in settings",
			cloudAccount: &models.DomainCloudAWSAccountV1{
				AccountID: "123456789012",
				Settings: map[string]interface{}{
					"other.setting": "value",
				},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			result := resolveAgentlessScanningRoleNameV1(ctx, tt.cloudAccount)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPopulateModelFromCloudAccount(t *testing.T) {
	tests := []struct {
		name         string
		initialModel cloudAWSAccountModel
		cloudAccount *models.DomainCloudAWSAccountV1
		expected     cloudAWSAccountModel
	}{
		{
			name:         "populate basic account information",
			initialModel: cloudAWSAccountModel{},
			cloudAccount: &models.DomainCloudAWSAccountV1{
				AccountID:      "123456789012",
				AccountType:    "commercial",
				OrganizationID: "o-1234567890",
				IsMaster:       true,
				TargetOus:      []string{"ou-abcd-efghijk", "r-abcd"},
				ResourceMetadata: &models.DomainAWSAccountResourceMetadata{
					ExternalID:              "external-123",
					IntermediateRoleArn:     "arn:aws:iam::111122223333:role/CrowdStrikeCSPMConnector",
					IamRoleArn:              "arn:aws:iam::123456789012:role/CrowdStrikeRole",
					EventbusName:            "cs-eventbus",
					AwsEventbusArn:          "arn:aws:events:us-east-1:123456789012:event-bus/cs-eventbus",
					AwsCloudtrailBucketName: "cloudtrail-bucket",
				},
				Products: []*models.DomainProductFeatures{
					{
						Product:  stringPtr("cspm"),
						Features: []string{"iom", "ioa"},
					},
				},
			},
			expected: cloudAWSAccountModel{
				AccountID:                     types.StringValue("123456789012"),
				AccountType:                   types.StringValue("commercial"),
				DeploymentMethod:              types.StringValue("terraform-native"),
				OrganizationID:                types.StringValue("o-1234567890"),
				IsOrgManagementAccount:        types.BoolValue(true),
				ExternalID:                    types.StringValue("external-123"),
				IntermediateRoleArn:           types.StringValue("arn:aws:iam::111122223333:role/CrowdStrikeCSPMConnector"),
				IamRoleArn:                    types.StringValue("arn:aws:iam::123456789012:role/CrowdStrikeRole"),
				IamRoleName:                   types.StringValue("CrowdStrikeRole"),
				EventbusName:                  types.StringValue("cs-eventbus"),
				EventbusArn:                   types.StringValue("arn:aws:events:us-east-1:123456789012:event-bus/cs-eventbus"),
				CloudTrailBucketName:          types.StringValue("cloudtrail-bucket"),
				DspmRoleArn:                   types.StringValue(""),
				DspmRoleName:                  types.StringValue(""),
				VulnerabilityScanningRoleArn:  types.StringValue(""),
				VulnerabilityScanningRoleName: types.StringValue(""),
				AgentlessScanningRoleName:     types.StringValue(""),
				AssetInventory: &assetInventoryOptions{
					Enabled: types.BoolValue(true),
				},
			},
		},
		{
			name:         "populate with DSPM and vulnerability scanning roles from settings",
			initialModel: cloudAWSAccountModel{},
			cloudAccount: &models.DomainCloudAWSAccountV1{
				AccountID:   "123456789012",
				AccountType: "commercial",
				ResourceMetadata: &models.DomainAWSAccountResourceMetadata{
					ExternalID: "external-123",
				},
				Settings: map[string]interface{}{
					"dspm.role":                           "MyDSPMRole",
					"dspm.host.account":                   "555666777888",
					"vulnerability_scanning.role":         "MyVulnRole",
					"vulnerability_scanning.host.account": "999888777666",
				},
				Products: []*models.DomainProductFeatures{},
			},
			expected: cloudAWSAccountModel{
				AccountID:                     types.StringValue("123456789012"),
				AccountType:                   types.StringValue("commercial"),
				DeploymentMethod:              types.StringValue("terraform-native"),
				IsOrgManagementAccount:        types.BoolValue(false),
				ExternalID:                    types.StringValue("external-123"),
				IntermediateRoleArn:           types.StringValue(""),
				IamRoleArn:                    types.StringValue(""),
				IamRoleName:                   types.StringValue(""),
				EventbusName:                  types.StringValue(""),
				EventbusArn:                   types.StringValue(""),
				CloudTrailBucketName:          types.StringValue(""),
				DspmRoleArn:                   types.StringValue("arn:aws:iam::555666777888:role/MyDSPMRole"),
				DspmRoleName:                  types.StringValue("MyDSPMRole"),
				VulnerabilityScanningRoleArn:  types.StringValue("arn:aws:iam::999888777666:role/MyVulnRole"),
				VulnerabilityScanningRoleName: types.StringValue("MyVulnRole"),
				AgentlessScanningRoleName:     types.StringValue("MyDSPMRole"),
				AssetInventory: &assetInventoryOptions{
					Enabled: types.BoolValue(true),
				},
			},
		},
		{
			name: "populate with nil asset inventory",
			initialModel: cloudAWSAccountModel{
				AssetInventory: nil,
			},
			cloudAccount: &models.DomainCloudAWSAccountV1{
				AccountID:   "123456789012",
				AccountType: "commercial",
				ResourceMetadata: &models.DomainAWSAccountResourceMetadata{
					ExternalID: "external-123",
				},
				Products: []*models.DomainProductFeatures{},
			},
			expected: cloudAWSAccountModel{
				AccountID:                     types.StringValue("123456789012"),
				AccountType:                   types.StringValue("commercial"),
				DeploymentMethod:              types.StringValue("terraform-native"),
				IsOrgManagementAccount:        types.BoolValue(false),
				ExternalID:                    types.StringValue("external-123"),
				IntermediateRoleArn:           types.StringValue(""),
				IamRoleArn:                    types.StringValue(""),
				IamRoleName:                   types.StringValue(""),
				EventbusName:                  types.StringValue(""),
				EventbusArn:                   types.StringValue(""),
				CloudTrailBucketName:          types.StringValue(""),
				DspmRoleArn:                   types.StringValue(""),
				DspmRoleName:                  types.StringValue(""),
				VulnerabilityScanningRoleArn:  types.StringValue(""),
				VulnerabilityScanningRoleName: types.StringValue(""),
				AgentlessScanningRoleName:     types.StringValue(""),
				AssetInventory: &assetInventoryOptions{
					Enabled: types.BoolValue(true),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &cloudAWSAccountResource{}
			ctx := context.Background()

			diags := r.populateModelFromCloudAccount(ctx, &tt.initialModel, tt.cloudAccount)
			assert.False(t, diags.HasError(), "Expected no diagnostics errors")

			// Verify basic fields
			assert.Equal(t, tt.expected.AccountID, tt.initialModel.AccountID)
			assert.Equal(t, tt.expected.AccountType, tt.initialModel.AccountType)
			assert.Equal(t, tt.expected.DeploymentMethod, tt.initialModel.DeploymentMethod)

			// Verify organization info
			assert.Equal(t, tt.expected.OrganizationID, tt.initialModel.OrganizationID)
			assert.Equal(t, tt.expected.IsOrgManagementAccount, tt.initialModel.IsOrgManagementAccount)

			// Verify computed fields
			assert.Equal(t, tt.expected.ExternalID, tt.initialModel.ExternalID)
			assert.Equal(t, tt.expected.IntermediateRoleArn, tt.initialModel.IntermediateRoleArn)
			assert.Equal(t, tt.expected.IamRoleArn, tt.initialModel.IamRoleArn)
			assert.Equal(t, tt.expected.IamRoleName, tt.initialModel.IamRoleName)
			assert.Equal(t, tt.expected.EventbusName, tt.initialModel.EventbusName)
			assert.Equal(t, tt.expected.EventbusArn, tt.initialModel.EventbusArn)
			assert.Equal(t, tt.expected.CloudTrailBucketName, tt.initialModel.CloudTrailBucketName)

			// Verify AssetInventory is always initialized and enabled
			require.NotNil(t, tt.initialModel.AssetInventory)
			assert.Equal(t, tt.expected.AssetInventory.Enabled, tt.initialModel.AssetInventory.Enabled)
		})
	}
}

func TestExtractCloudAccountFields(t *testing.T) {
	tests := []struct {
		name         string
		cloudAccount *models.DomainCloudAWSAccountV1
		expected     *CloudAccountFields
	}{
		{
			name: "basic account with ResourceMetadata",
			cloudAccount: &models.DomainCloudAWSAccountV1{
				AccountID:          "123456789012",
				OrganizationID:     "o-example12345",
				AccountType:        "commercial",
				IsMaster:           true,
				TargetOus:          []string{"ou-root-123", "ou-dev-456"},
				ResourceNamePrefix: "test-prefix",
				ResourceNameSuffix: "test-suffix",
				ResourceMetadata: &models.DomainAWSAccountResourceMetadata{
					ExternalID:              "external-123",
					IntermediateRoleArn:     "arn:aws:iam::111111111111:role/intermediate",
					IamRoleArn:              "arn:aws:iam::123456789012:role/CrowdStrike-CSPM-Role",
					EventbusName:            "crowdstrike-eventbus",
					AwsEventbusArn:          "arn:aws:events:us-east-1:123456789012:event-bus/crowdstrike-eventbus",
					AwsCloudtrailBucketName: "crowdstrike-cloudtrail-bucket",
					AwsCloudtrailRegion:     "us-east-1",
				},
				Products: []*models.DomainProductFeatures{
					{
						Product:  stringPtr("cspm"),
						Features: []string{"iom", "ioa", "sensormgmt", "dspm", "vulnerability_scanning"},
					},
					{
						Product: stringPtr("idp"),
					},
				},
			},
			expected: &CloudAccountFields{
				AccountID:                    "123456789012",
				OrganizationID:               "o-example12345",
				TargetOUs:                    []string{"ou-root-123", "ou-dev-456"},
				IsOrgManagementAccount:       true,
				AccountType:                  "commercial",
				ExternalID:                   "external-123",
				IntermediateRoleArn:          "arn:aws:iam::111111111111:role/intermediate",
				IamRoleArn:                   "arn:aws:iam::123456789012:role/CrowdStrike-CSPM-Role",
				EventbusName:                 "crowdstrike-eventbus",
				EventbusArn:                  "arn:aws:events:us-east-1:123456789012:event-bus/crowdstrike-eventbus",
				CloudTrailBucketName:         "crowdstrike-cloudtrail-bucket",
				CloudTrailRegion:             "us-east-1",
				ResourceNamePrefix:           "test-prefix",
				ResourceNameSuffix:           "test-suffix",
				AssetInventoryEnabled:        true, // Always enabled
				RealtimeVisibilityEnabled:    true, // ioa feature
				IDPEnabled:                   true, // idp product
				SensorManagementEnabled:      true, // sensormgmt feature
				DSPMEnabled:                  true, // dspm feature
				VulnerabilityScanningEnabled: true, // vulnerability_scanning feature
				// Note: Role ARNs and names would be empty without settings
				DspmRoleArn:                   "",
				DspmRoleName:                  "",
				VulnerabilityScanningRoleArn:  "",
				VulnerabilityScanningRoleName: "",
				AgentlessScanningRoleName:     "", // Would be computed by resolveAgentlessScanningRoleNameV1
			},
		},
		{
			name: "minimal account without ResourceMetadata",
			cloudAccount: &models.DomainCloudAWSAccountV1{
				AccountID:   "987654321098",
				AccountType: "gov",
				IsMaster:    false,
				Products: []*models.DomainProductFeatures{
					{
						Product:  stringPtr("cspm"),
						Features: []string{"iom"}, // Only asset inventory
					},
				},
			},
			expected: &CloudAccountFields{
				AccountID:                     "987654321098",
				OrganizationID:                "",
				TargetOUs:                     nil,
				IsOrgManagementAccount:        false,
				AccountType:                   "gov",
				ExternalID:                    "",
				IntermediateRoleArn:           "",
				IamRoleArn:                    "",
				EventbusName:                  "",
				EventbusArn:                   "",
				CloudTrailBucketName:          "",
				CloudTrailRegion:              "",
				ResourceNamePrefix:            "",
				ResourceNameSuffix:            "",
				AssetInventoryEnabled:         true, // Always enabled
				RealtimeVisibilityEnabled:     false,
				IDPEnabled:                    false,
				SensorManagementEnabled:       false,
				DSPMEnabled:                   false,
				VulnerabilityScanningEnabled:  false,
				DspmRoleArn:                   "",
				DspmRoleName:                  "",
				VulnerabilityScanningRoleArn:  "",
				VulnerabilityScanningRoleName: "",
				AgentlessScanningRoleName:     "",
			},
		},
		{
			name: "account with selective features",
			cloudAccount: &models.DomainCloudAWSAccountV1{
				AccountID:   "555555555555",
				AccountType: "commercial",
				IsMaster:    false,
				ResourceMetadata: &models.DomainAWSAccountResourceMetadata{
					IamRoleArn: "arn:aws:iam::555555555555:role/TestRole",
				},
				Products: []*models.DomainProductFeatures{
					{
						Product:  stringPtr("cspm"),
						Features: []string{"iom", "ioa"}, // Asset inventory and realtime visibility only
					},
				},
			},
			expected: &CloudAccountFields{
				AccountID:                     "555555555555",
				OrganizationID:                "",
				TargetOUs:                     nil,
				IsOrgManagementAccount:        false,
				AccountType:                   "commercial",
				ExternalID:                    "",
				IntermediateRoleArn:           "",
				IamRoleArn:                    "arn:aws:iam::555555555555:role/TestRole",
				EventbusName:                  "",
				EventbusArn:                   "",
				CloudTrailBucketName:          "",
				CloudTrailRegion:              "",
				ResourceNamePrefix:            "",
				ResourceNameSuffix:            "",
				AssetInventoryEnabled:         true,
				RealtimeVisibilityEnabled:     true,  // ioa feature enabled
				IDPEnabled:                    false, // No idp product
				SensorManagementEnabled:       false, // sensormgmt feature not enabled
				DSPMEnabled:                   false, // dspm feature not enabled
				VulnerabilityScanningEnabled:  false, // vulnerability_scanning feature not enabled
				DspmRoleArn:                   "",
				DspmRoleName:                  "",
				VulnerabilityScanningRoleArn:  "",
				VulnerabilityScanningRoleName: "",
				AgentlessScanningRoleName:     "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			result := extractCloudAccountFields(ctx, tt.cloudAccount)

			// Verify all fields match expected values
			assert.Equal(t, tt.expected.AccountID, result.AccountID)
			assert.Equal(t, tt.expected.OrganizationID, result.OrganizationID)
			assert.Equal(t, tt.expected.TargetOUs, result.TargetOUs)
			assert.Equal(t, tt.expected.IsOrgManagementAccount, result.IsOrgManagementAccount)
			assert.Equal(t, tt.expected.AccountType, result.AccountType)
			assert.Equal(t, tt.expected.ExternalID, result.ExternalID)
			assert.Equal(t, tt.expected.IntermediateRoleArn, result.IntermediateRoleArn)
			assert.Equal(t, tt.expected.IamRoleArn, result.IamRoleArn)
			assert.Equal(t, tt.expected.EventbusName, result.EventbusName)
			assert.Equal(t, tt.expected.EventbusArn, result.EventbusArn)
			assert.Equal(t, tt.expected.CloudTrailBucketName, result.CloudTrailBucketName)
			assert.Equal(t, tt.expected.CloudTrailRegion, result.CloudTrailRegion)
			assert.Equal(t, tt.expected.ResourceNamePrefix, result.ResourceNamePrefix)
			assert.Equal(t, tt.expected.ResourceNameSuffix, result.ResourceNameSuffix)

			// Verify feature flags
			assert.Equal(t, tt.expected.AssetInventoryEnabled, result.AssetInventoryEnabled)
			assert.Equal(t, tt.expected.RealtimeVisibilityEnabled, result.RealtimeVisibilityEnabled)
			assert.Equal(t, tt.expected.IDPEnabled, result.IDPEnabled)
			assert.Equal(t, tt.expected.SensorManagementEnabled, result.SensorManagementEnabled)
			assert.Equal(t, tt.expected.DSPMEnabled, result.DSPMEnabled)
			assert.Equal(t, tt.expected.VulnerabilityScanningEnabled, result.VulnerabilityScanningEnabled)

			// Verify role fields (these would be empty without settings in these test cases)
			assert.Equal(t, tt.expected.DspmRoleArn, result.DspmRoleArn)
			assert.Equal(t, tt.expected.DspmRoleName, result.DspmRoleName)
			assert.Equal(t, tt.expected.VulnerabilityScanningRoleArn, result.VulnerabilityScanningRoleArn)
			assert.Equal(t, tt.expected.VulnerabilityScanningRoleName, result.VulnerabilityScanningRoleName)
			assert.Equal(t, tt.expected.AgentlessScanningRoleName, result.AgentlessScanningRoleName)
		})
	}
}

// Helper function to create string pointer.
func stringPtr(s string) *string {
	return &s
}
