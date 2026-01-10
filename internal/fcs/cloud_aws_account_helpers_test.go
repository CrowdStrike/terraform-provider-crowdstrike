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
				IDP: nil, // User didn't configure IDP
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
				IDP: nil, // Remains nil (consistent with other features)
			},
		},
		{
			name: "handle configured IDP with product enabled",
			initialModel: cloudAWSAccountModel{
				IDP: &idpOptions{}, // User configured IDP
			},
			products: []*models.DomainProductFeatures{
				{
					Product: stringPtr("idp"), // IDP product enabled
				},
			},
			cloudAccount: &models.DomainCloudAWSAccountV1{
				ResourceMetadata: &models.DomainAWSAccountResourceMetadata{},
			},
			expectedModel: cloudAWSAccountModel{
				IDP: &idpOptions{
					Enabled: types.BoolValue(true),
					Status:  types.StringValue("configured"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			updateFeatureStatesFromProducts(ctx, &tt.initialModel, tt.products, tt.cloudAccount)

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

			// Verify IDP (only if expected to be configured)
			if tt.expectedModel.IDP != nil {
				require.NotNil(t, tt.initialModel.IDP)
				assert.Equal(t, tt.expectedModel.IDP.Enabled, tt.initialModel.IDP.Enabled)
				assert.Equal(t, tt.expectedModel.IDP.Status, tt.initialModel.IDP.Status)
			} else {
				// If expected model doesn't have IDP, actual should also be nil
				assert.Nil(t, tt.initialModel.IDP)
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
			ctx := context.Background()

			// Capture initial status for comparison
			initialStatus := tt.initialModel.IDP.Status

			// Apply the update
			updateFeatureStatesFromProducts(ctx, &tt.initialModel, tt.products, tt.cloudAccount)

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
				AssetInventory:                nil, // Not configured by user, so remains nil
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
				AssetInventory:                nil, // Not configured by user, so remains nil
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
				AssetInventory:                nil, // Started as nil and remains nil (consistent behavior)
			},
		},
		{
			name: "populate with configured asset inventory",
			initialModel: cloudAWSAccountModel{
				AssetInventory: &assetInventoryOptions{}, // User configured this feature
			},
			cloudAccount: &models.DomainCloudAWSAccountV1{
				AccountID:   "777888999000",
				AccountType: "commercial",
				ResourceMetadata: &models.DomainAWSAccountResourceMetadata{
					ExternalID: "external-456",
				},
				Products: []*models.DomainProductFeatures{
					{
						Product:  stringPtr("cspm"),
						Features: []string{"iom"}, // Asset inventory feature enabled
					},
				},
			},
			expected: cloudAWSAccountModel{
				AccountID:                     types.StringValue("777888999000"),
				AccountType:                   types.StringValue("commercial"),
				DeploymentMethod:              types.StringValue("terraform-native"),
				IsOrgManagementAccount:        types.BoolValue(false),
				ExternalID:                    types.StringValue("external-456"),
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
					Enabled: types.BoolValue(true), // iom feature enabled in products
				},
			},
		},
		{
			name:         "handle nil cloudAccount",
			initialModel: cloudAWSAccountModel{},
			cloudAccount: nil,
			expected:     cloudAWSAccountModel{}, // Should remain unchanged due to error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &cloudAWSAccountResource{}
			ctx := context.Background()

			diags := r.populateModelFromCloudAccount(ctx, &tt.initialModel, tt.cloudAccount)

			if tt.name == "handle nil cloudAccount" {
				assert.True(t, diags.HasError(), "Expected diagnostics error for nil cloudAccount")
				return // Skip field validation for error case
			}

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

			// Verify AssetInventory behaves like other features (only set if configured)
			if tt.initialModel.AssetInventory != nil {
				require.NotNil(t, tt.initialModel.AssetInventory)
				assert.Equal(t, tt.expected.AssetInventory.Enabled, tt.initialModel.AssetInventory.Enabled)
			} else if tt.expected.AssetInventory != nil {
				// If test expects AssetInventory but initial model doesn't have it,
				// it means the test setup is incorrect for the new behavior
				t.Errorf("Test expects AssetInventory but initialModel doesn't have it configured")
			}
		})
	}
}

// Helper function to create string pointer.
func stringPtr(s string) *string {
	return &s
}
