package fcs

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
)

const (
	testAccountID    = "123456789012"
	testDSPMRoleName = "dspm-role"
	testVulnRoleName = "vuln-role"
)

var (
	testDSPMRoleArn = fmt.Sprintf("arn:aws:iam::%s:role/%s", testAccountID, testDSPMRoleName)
	testVulnRoleArn = fmt.Sprintf("arn:aws:iam::%s:role/%s", testAccountID, testVulnRoleName)
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
			output: testDSPMRoleName,
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
		name        string
		cspmAccount *models.DomainAWSAccountV2
		expected    string
	}{
		{
			name: "DSPM enabled with role - should return DSPM role",
			cspmAccount: &models.DomainAWSAccountV2{
				DspmEnabled:                  true,
				DspmRoleArn:                  testDSPMRoleArn,
				VulnerabilityScanningEnabled: false,
			},
			expected: testDSPMRoleName,
		},
		{
			name: "Both DSPM and Vuln enabled - should return DSPM role (precedence)",
			cspmAccount: &models.DomainAWSAccountV2{
				DspmEnabled:                  true,
				DspmRoleArn:                  testDSPMRoleArn,
				VulnerabilityScanningEnabled: true,
				VulnerabilityScanningRoleArn: testVulnRoleArn,
			},
			expected: testDSPMRoleName,
		},
		{
			name: "Only Vuln enabled with role - should return Vuln role",
			cspmAccount: &models.DomainAWSAccountV2{
				DspmEnabled:                  false,
				VulnerabilityScanningEnabled: true,
				VulnerabilityScanningRoleArn: testVulnRoleArn,
			},
			expected: testVulnRoleName,
		},
		{
			name: "Neither enabled - should return empty string",
			cspmAccount: &models.DomainAWSAccountV2{
				DspmEnabled:                  false,
				VulnerabilityScanningEnabled: false,
			},
			expected: "",
		},
		{
			name: "DSPM enabled but empty role ARN - should return empty string",
			cspmAccount: &models.DomainAWSAccountV2{
				DspmEnabled:                  true,
				DspmRoleArn:                  "",
				VulnerabilityScanningEnabled: false,
			},
			expected: "",
		},
		{
			name: "Vuln enabled but no role arn - should return empty string",
			cspmAccount: &models.DomainAWSAccountV2{
				DspmEnabled:                  false,
				VulnerabilityScanningEnabled: true,
			},
			expected: "",
		},
		{
			name: "Vuln enabled with empty role ARN - should return empty string",
			cspmAccount: &models.DomainAWSAccountV2{
				DspmEnabled:                  false,
				VulnerabilityScanningEnabled: true,
				VulnerabilityScanningRoleArn: "",
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveAgentlessScanningRoleName(tt.cspmAccount)
			if got != tt.expected {
				t.Errorf("resolveAgentlessScanningRoleName() = %v, want %v", got, tt.expected)
			}
		})
	}
}
