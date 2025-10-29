package fcs

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/stretchr/testify/assert"
)

const (
	testAccountID = "123456789012"
	testDSPMRole  = "dspm-role"
	testVulnRole  = "vuln-role"
)

var (
	testDSPMRoleArn = fmt.Sprintf("arn:aws:iam::%s:role/%s", testAccountID, testDSPMRole)
	testVulnRoleArn = fmt.Sprintf("arn:aws:iam::%s:role/%s", testAccountID, testVulnRole)
)

func TestGetRoleNameFromArn(t *testing.T) {
	tests := []struct {
		name   string
		arn    string
		output string
	}{
		{
			name:   "Valid DSPM role arn",
			arn:    testDSPMRoleArn,
			output: testDSPMRole,
		},
		{
			name:   "Valid Vuln role arn",
			arn:    testVulnRoleArn,
			output: testVulnRole,
		},
		{
			name:   "Invalid role arn",
			arn:    "arn:aws:iam::123456789013",
			output: "",
		},
		{
			name:   "Empty arn",
			arn:    "",
			output: "",
		},
		{
			name:   "Arn with path - should return empty (not supported)",
			arn:    fmt.Sprintf("arn:aws:iam::%s:role/path/to/role-name", testAccountID),
			output: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getRoleNameFromArn(tt.arn); got != tt.output {
				t.Errorf("getRoleNameFromArn() = %v, want %v", got, tt.output)
			}
		})
	}
}

func TestComputeAgentlessScanningRoleName(t *testing.T) {
	tests := []struct {
		name          string
		cspmAccount   *models.DomainAWSAccountV2
		expected      string
		expectedError bool
	}{
		{
			name: "DSPM enabled with role - should return DSPM role",
			cspmAccount: &models.DomainAWSAccountV2{
				DspmEnabled:                  true,
				DspmRoleArn:                  testDSPMRoleArn,
				VulnerabilityScanningEnabled: false,
			},
			expected:      testDSPMRole,
			expectedError: false,
		},
		{
			name: "Both DSPM and Vuln enabled - should return DSPM role (precedence)",
			cspmAccount: &models.DomainAWSAccountV2{
				DspmEnabled:                  true,
				DspmRoleArn:                  testDSPMRoleArn,
				VulnerabilityScanningEnabled: true,
				Settings: map[string]string{
					AWSVulnerabilityScanningCustomRoleKey: testVulnRoleArn,
				},
			},
			expected:      testDSPMRole,
			expectedError: false,
		},
		{
			name: "Only Vuln enabled with role - should return Vuln role",
			cspmAccount: &models.DomainAWSAccountV2{
				DspmEnabled:                  false,
				VulnerabilityScanningEnabled: true,
				Settings: map[string]string{
					AWSVulnerabilityScanningCustomRoleKey: testVulnRoleArn,
				},
			},
			expected:      testVulnRole,
			expectedError: false,
		},
		{
			name: "Neither enabled - should return empty string",
			cspmAccount: &models.DomainAWSAccountV2{
				DspmEnabled:                  false,
				VulnerabilityScanningEnabled: false,
			},
			expected:      "",
			expectedError: false,
		},
		{
			name: "DSPM enabled but empty role ARN - should return empty string",
			cspmAccount: &models.DomainAWSAccountV2{
				DspmEnabled:                  true,
				DspmRoleArn:                  "",
				VulnerabilityScanningEnabled: false,
			},
			expected:      "",
			expectedError: false,
		},
		{
			name: "Vuln enabled but no settings - should return empty string",
			cspmAccount: &models.DomainAWSAccountV2{
				DspmEnabled:                  false,
				VulnerabilityScanningEnabled: true,
				Settings:                     nil,
			},
			expected:      "",
			expectedError: false,
		},
		{
			name: "Vuln enabled but empty settings map - should return empty string",
			cspmAccount: &models.DomainAWSAccountV2{
				DspmEnabled:                  false,
				VulnerabilityScanningEnabled: true,
				Settings:                     map[string]string{},
			},
			expected:      "",
			expectedError: false,
		},
		{
			name: "Vuln enabled with empty role ARN in settings - should return empty string",
			cspmAccount: &models.DomainAWSAccountV2{
				DspmEnabled:                  false,
				VulnerabilityScanningEnabled: true,
				Settings: map[string]string{
					AWSVulnerabilityScanningCustomRoleKey: "",
				},
			},
			expected:      "",
			expectedError: false,
		},
		{
			name: "Vuln enabled with invalid settings type - should return error",
			cspmAccount: &models.DomainAWSAccountV2{
				DspmEnabled:                  false,
				VulnerabilityScanningEnabled: true,
				Settings:                     "invalid-settings-type",
			},
			expected:      "",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := computeAgentlessScanningRoleName(tt.cspmAccount)
			assert.Equal(t, tt.expected, got)
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
