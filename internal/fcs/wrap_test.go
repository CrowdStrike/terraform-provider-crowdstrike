package fcs_test

import (
	"context"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/fcs"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrap_DSPMRoleHandling(t *testing.T) {
	tests := []struct {
		name               string
		dspmRoleFromAPI    string
		dspmHostAccountID  string
		expectedRoleName   types.String
		expectedRoleArn    types.String
		expectRoleNameNull bool
		expectRoleArnNull  bool
	}{
		{
			name:               "DSPM role name from API - should set both name and ARN",
			dspmRoleFromAPI:    "my-custom-dspm-role",
			dspmHostAccountID:  "",
			expectedRoleName:   types.StringValue("my-custom-dspm-role"),
			expectedRoleArn:    types.StringValue("arn:aws:iam::123456789012:role/my-custom-dspm-role"),
			expectRoleNameNull: false,
			expectRoleArnNull:  false,
		},
		{
			name:               "DSPM role ARN from API - should extract name and preserve ARN",
			dspmRoleFromAPI:    "arn:aws:iam::123456789012:role/arn-based-role",
			dspmHostAccountID:  "",
			expectedRoleName:   types.StringValue("arn-based-role"),
			expectedRoleArn:    types.StringValue("arn:aws:iam::123456789012:role/arn-based-role"),
			expectRoleNameNull: false,
			expectRoleArnNull:  false,
		},
		{
			name:               "Empty DSPM role from API - should set both as null",
			dspmRoleFromAPI:    "",
			dspmHostAccountID:  "",
			expectedRoleName:   types.StringNull(),
			expectedRoleArn:    types.StringNull(),
			expectRoleNameNull: true,
			expectRoleArnNull:  true,
		},
		{
			name:               "DSPM role with custom host account ID",
			dspmRoleFromAPI:    "cross-account-role",
			dspmHostAccountID:  "999999999999",
			expectedRoleName:   types.StringValue("cross-account-role"),
			expectedRoleArn:    types.StringValue("arn:aws:iam::999999999999:role/cross-account-role"), // Uses custom host account ID from settings
			expectRoleNameNull: false,
			expectRoleArnNull:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Create a model with DSPM enabled
			model := &fcs.CloudAWSAccountModel{
				AccountID:   types.StringValue("123456789012"),
				AccountType: types.StringValue("commercial"),
				DSPM: &fcs.DSPMOptions{
					Enabled:  types.BoolValue(true),
					RoleName: types.StringNull(),
				},
			}

			// Create mock settings
			settings := map[string]interface{}{
				"dspm.role": tt.dspmRoleFromAPI,
			}
			if tt.dspmHostAccountID != "" {
				settings["dspm.host.account"] = tt.dspmHostAccountID
			}

			// Create mock cloud account
			cloudAccount := &models.DomainCloudAWSAccountV1{
				AccountID:   "123456789012",
				AccountType: "commercial",
				ResourceMetadata: &models.DomainAWSAccountResourceMetadata{
					ExternalID:          "test-external-id",
					IntermediateRoleArn: "arn:aws:iam::123456789012:role/intermediate-role",
					IamRoleArn:          "arn:aws:iam::123456789012:role/iam-role",
				},
				Settings: settings,
				Products: []*models.DomainProductFeatures{
					{
						Product:  stringPtr("cspm"),
						Features: []string{"iom", "dspm"},
					},
				},
			}

			// Call the wrap function
			diags := fcs.Wrap(model, ctx, cloudAccount)
			require.False(t, diags.HasError(), "wrap function should not return errors")

			// Verify the results
			if tt.expectRoleNameNull {
				assert.True(t, model.DspmRoleName.IsNull(), "DSPM role name should be null")
			} else {
				assert.Equal(t, tt.expectedRoleName, model.DspmRoleName, "DSPM role name mismatch")
			}

			if tt.expectRoleArnNull {
				assert.True(t, model.DspmRoleArn.IsNull(), "DSPM role ARN should be null")
			} else {
				assert.Equal(t, tt.expectedRoleArn, model.DspmRoleArn, "DSPM role ARN mismatch")
			}
		})
	}
}

func TestWrap_VulnerabilityScanningRoleHandling(t *testing.T) {
	tests := []struct {
		name               string
		vulnRoleFromAPI    string
		vulnHostAccountID  string
		expectedRoleName   types.String
		expectedRoleArn    types.String
		expectRoleNameNull bool
		expectRoleArnNull  bool
	}{
		{
			name:               "Vuln scanning role name from API - should set both name and ARN",
			vulnRoleFromAPI:    "my-vuln-role",
			vulnHostAccountID:  "",
			expectedRoleName:   types.StringValue("my-vuln-role"),
			expectedRoleArn:    types.StringValue("arn:aws:iam::123456789012:role/my-vuln-role"),
			expectRoleNameNull: false,
			expectRoleArnNull:  false,
		},
		{
			name:               "Empty vuln scanning role from API - should set both as null",
			vulnRoleFromAPI:    "",
			vulnHostAccountID:  "",
			expectedRoleName:   types.StringNull(),
			expectedRoleArn:    types.StringNull(),
			expectRoleNameNull: true,
			expectRoleArnNull:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Create a model with vulnerability scanning enabled
			model := &fcs.CloudAWSAccountModel{
				AccountID:   types.StringValue("123456789012"),
				AccountType: types.StringValue("commercial"),
				VulnerabilityScanning: &fcs.VulnerabilityScanningOptions{
					Enabled:  types.BoolValue(true),
					RoleName: types.StringNull(),
				},
			}

			// Create mock settings
			settings := map[string]interface{}{
				"vulnerability_scanning.role": tt.vulnRoleFromAPI,
			}
			if tt.vulnHostAccountID != "" {
				settings["vulnerability_scanning.host.account"] = tt.vulnHostAccountID
			}

			// Create mock cloud account
			cloudAccount := &models.DomainCloudAWSAccountV1{
				AccountID:   "123456789012",
				AccountType: "commercial",
				ResourceMetadata: &models.DomainAWSAccountResourceMetadata{
					ExternalID:          "test-external-id",
					IntermediateRoleArn: "arn:aws:iam::123456789012:role/intermediate-role",
					IamRoleArn:          "arn:aws:iam::123456789012:role/iam-role",
				},
				Settings: settings,
				Products: []*models.DomainProductFeatures{
					{
						Product:  stringPtr("cspm"),
						Features: []string{"iom", "vulnerability_scanning"},
					},
				},
			}

			// Call the wrap function
			diags := fcs.Wrap(model, ctx, cloudAccount)
			require.False(t, diags.HasError(), "wrap function should not return errors")

			// Verify the results
			if tt.expectRoleNameNull {
				assert.True(t, model.VulnerabilityScanningRoleName.IsNull(), "Vulnerability scanning role name should be null")
			} else {
				assert.Equal(t, tt.expectedRoleName, model.VulnerabilityScanningRoleName, "Vulnerability scanning role name mismatch")
			}

			if tt.expectRoleArnNull {
				assert.True(t, model.VulnerabilityScanningRoleArn.IsNull(), "Vulnerability scanning role ARN should be null")
			} else {
				assert.Equal(t, tt.expectedRoleArn, model.VulnerabilityScanningRoleArn, "Vulnerability scanning role ARN mismatch")
			}
		})
	}
}

func TestWrap_EmptyRoleHandlingConsistency(t *testing.T) {
	t.Run("Both DSPM and vulnerability scanning with empty roles should be null", func(t *testing.T) {
		ctx := context.Background()

		// Create a model with both features enabled but no role names from API
		model := &fcs.CloudAWSAccountModel{
			AccountID:   types.StringValue("123456789012"),
			AccountType: types.StringValue("commercial"),
			DSPM: &fcs.DSPMOptions{
				Enabled:  types.BoolValue(true),
				RoleName: types.StringNull(),
			},
			VulnerabilityScanning: &fcs.VulnerabilityScanningOptions{
				Enabled:  types.BoolValue(true),
				RoleName: types.StringNull(),
			},
		}

		// Create mock cloud account with empty settings (simulating API not ready)
		cloudAccount := &models.DomainCloudAWSAccountV1{
			AccountID:   "123456789012",
			AccountType: "commercial",
			ResourceMetadata: &models.DomainAWSAccountResourceMetadata{
				ExternalID:          "test-external-id",
				IntermediateRoleArn: "arn:aws:iam::123456789012:role/intermediate-role",
				IamRoleArn:          "arn:aws:iam::123456789012:role/iam-role",
			},
			Settings: map[string]interface{}{
				"dspm.role":                   "",
				"vulnerability_scanning.role": "",
			},
			Products: []*models.DomainProductFeatures{
				{
					Product:  stringPtr("cspm"),
					Features: []string{"iom", "dspm", "vulnerability_scanning"},
				},
			},
		}

		// Call the wrap function
		diags := fcs.Wrap(model, ctx, cloudAccount)
		require.False(t, diags.HasError(), "wrap function should not return errors")

		// Verify all role fields are null when empty (not empty strings)
		assert.True(t, model.DspmRoleName.IsNull(), "DSPM role name should be null, not empty string")
		assert.True(t, model.DspmRoleArn.IsNull(), "DSPM role ARN should be null, not empty string")
		assert.True(t, model.VulnerabilityScanningRoleName.IsNull(), "Vulnerability scanning role name should be null, not empty string")
		assert.True(t, model.VulnerabilityScanningRoleArn.IsNull(), "Vulnerability scanning role ARN should be null, not empty string")

		// Verify they are not empty strings (which would cause the inconsistency error)
		assert.False(t, model.DspmRoleName.Equal(types.StringValue("")), "DSPM role name should not be empty string")
		assert.False(t, model.DspmRoleArn.Equal(types.StringValue("")), "DSPM role ARN should not be empty string")
		assert.False(t, model.VulnerabilityScanningRoleName.Equal(types.StringValue("")), "Vulnerability scanning role name should not be empty string")
		assert.False(t, model.VulnerabilityScanningRoleArn.Equal(types.StringValue("")), "Vulnerability scanning role ARN should not be empty string")
	})
}

// Helper function to create string pointers.
func stringPtr(s string) *string {
	return &s
}
