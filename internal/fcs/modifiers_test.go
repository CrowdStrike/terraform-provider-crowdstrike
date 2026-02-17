package fcs_test

import (
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/fcs"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

func TestShouldInvalidateDSPMRoleField(t *testing.T) {
	tests := []struct {
		name     string
		plan     fcs.CloudAWSAccountModel
		state    fcs.CloudAWSAccountModel
		expected bool
	}{
		{
			name: "no changes",
			plan: fcs.CloudAWSAccountModel{
				DSPM:               &fcs.DSPMOptions{RoleName: types.StringValue("role1")},
				ResourceNamePrefix: types.StringValue(""),
				ResourceNameSuffix: types.StringValue(""),
			},
			state: fcs.CloudAWSAccountModel{
				DSPM:               &fcs.DSPMOptions{RoleName: types.StringValue("role1")},
				ResourceNamePrefix: types.StringValue(""),
				ResourceNameSuffix: types.StringValue(""),
			},
			expected: false,
		},
		{
			name: "dspm role name changed",
			plan: fcs.CloudAWSAccountModel{
				DSPM:               &fcs.DSPMOptions{RoleName: types.StringValue("role2")},
				ResourceNamePrefix: types.StringValue(""),
				ResourceNameSuffix: types.StringValue(""),
			},
			state: fcs.CloudAWSAccountModel{
				DSPM:               &fcs.DSPMOptions{RoleName: types.StringValue("role1")},
				ResourceNamePrefix: types.StringValue(""),
				ResourceNameSuffix: types.StringValue(""),
			},
			expected: true,
		},
		{
			name: "prefix changed",
			plan: fcs.CloudAWSAccountModel{
				DSPM:               &fcs.DSPMOptions{RoleName: types.StringValue("role1")},
				ResourceNamePrefix: types.StringValue("new-"),
				ResourceNameSuffix: types.StringValue(""),
			},
			state: fcs.CloudAWSAccountModel{
				DSPM:               &fcs.DSPMOptions{RoleName: types.StringValue("role1")},
				ResourceNamePrefix: types.StringValue(""),
				ResourceNameSuffix: types.StringValue(""),
			},
			expected: true,
		},
		{
			name: "suffix changed",
			plan: fcs.CloudAWSAccountModel{
				DSPM:               &fcs.DSPMOptions{RoleName: types.StringValue("role1")},
				ResourceNamePrefix: types.StringValue(""),
				ResourceNameSuffix: types.StringValue("-new"),
			},
			state: fcs.CloudAWSAccountModel{
				DSPM:               &fcs.DSPMOptions{RoleName: types.StringValue("role1")},
				ResourceNamePrefix: types.StringValue(""),
				ResourceNameSuffix: types.StringValue(""),
			},
			expected: true,
		},
		{
			name: "both prefix and suffix changed",
			plan: fcs.CloudAWSAccountModel{
				DSPM:               &fcs.DSPMOptions{RoleName: types.StringValue("role1")},
				ResourceNamePrefix: types.StringValue("new-"),
				ResourceNameSuffix: types.StringValue("-new"),
			},
			state: fcs.CloudAWSAccountModel{
				DSPM:               &fcs.DSPMOptions{RoleName: types.StringValue("role1")},
				ResourceNamePrefix: types.StringValue("old-"),
				ResourceNameSuffix: types.StringValue("-old"),
			},
			expected: true,
		},
		{
			name: "nil dspm but prefix changed",
			plan: fcs.CloudAWSAccountModel{
				DSPM:               nil,
				ResourceNamePrefix: types.StringValue("new-"),
				ResourceNameSuffix: types.StringValue(""),
			},
			state: fcs.CloudAWSAccountModel{
				DSPM:               nil,
				ResourceNamePrefix: types.StringValue(""),
				ResourceNameSuffix: types.StringValue(""),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fcs.ShouldInvalidateDSPMRoleField(tt.plan, tt.state)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestShouldInvalidateVulnerabilityScanningRoleField(t *testing.T) {
	tests := []struct {
		name     string
		plan     fcs.CloudAWSAccountModel
		state    fcs.CloudAWSAccountModel
		expected bool
	}{
		{
			name: "no changes",
			plan: fcs.CloudAWSAccountModel{
				VulnerabilityScanning: &fcs.VulnerabilityScanningOptions{RoleName: types.StringValue("role1")},
				ResourceNamePrefix:    types.StringValue(""),
				ResourceNameSuffix:    types.StringValue(""),
			},
			state: fcs.CloudAWSAccountModel{
				VulnerabilityScanning: &fcs.VulnerabilityScanningOptions{RoleName: types.StringValue("role1")},
				ResourceNamePrefix:    types.StringValue(""),
				ResourceNameSuffix:    types.StringValue(""),
			},
			expected: false,
		},
		{
			name: "vuln scanning role name changed",
			plan: fcs.CloudAWSAccountModel{
				VulnerabilityScanning: &fcs.VulnerabilityScanningOptions{RoleName: types.StringValue("role2")},
				ResourceNamePrefix:    types.StringValue(""),
				ResourceNameSuffix:    types.StringValue(""),
			},
			state: fcs.CloudAWSAccountModel{
				VulnerabilityScanning: &fcs.VulnerabilityScanningOptions{RoleName: types.StringValue("role1")},
				ResourceNamePrefix:    types.StringValue(""),
				ResourceNameSuffix:    types.StringValue(""),
			},
			expected: true,
		},
		{
			name: "prefix changed",
			plan: fcs.CloudAWSAccountModel{
				VulnerabilityScanning: &fcs.VulnerabilityScanningOptions{RoleName: types.StringValue("role1")},
				ResourceNamePrefix:    types.StringValue("new-"),
				ResourceNameSuffix:    types.StringValue(""),
			},
			state: fcs.CloudAWSAccountModel{
				VulnerabilityScanning: &fcs.VulnerabilityScanningOptions{RoleName: types.StringValue("role1")},
				ResourceNamePrefix:    types.StringValue(""),
				ResourceNameSuffix:    types.StringValue(""),
			},
			expected: true,
		},
		{
			name: "suffix changed",
			plan: fcs.CloudAWSAccountModel{
				VulnerabilityScanning: &fcs.VulnerabilityScanningOptions{RoleName: types.StringValue("role1")},
				ResourceNamePrefix:    types.StringValue(""),
				ResourceNameSuffix:    types.StringValue("-new"),
			},
			state: fcs.CloudAWSAccountModel{
				VulnerabilityScanning: &fcs.VulnerabilityScanningOptions{RoleName: types.StringValue("role1")},
				ResourceNamePrefix:    types.StringValue(""),
				ResourceNameSuffix:    types.StringValue(""),
			},
			expected: true,
		},
		{
			name: "nil vuln scanning but prefix changed",
			plan: fcs.CloudAWSAccountModel{
				VulnerabilityScanning: nil,
				ResourceNamePrefix:    types.StringValue("new-"),
				ResourceNameSuffix:    types.StringValue(""),
			},
			state: fcs.CloudAWSAccountModel{
				VulnerabilityScanning: nil,
				ResourceNamePrefix:    types.StringValue(""),
				ResourceNameSuffix:    types.StringValue(""),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fcs.ShouldInvalidateVulnerabilityScanningRoleField(tt.plan, tt.state)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestShouldInvalidateAgentlessScanningRoleField(t *testing.T) {
	tests := []struct {
		name     string
		plan     fcs.CloudAWSAccountModel
		state    fcs.CloudAWSAccountModel
		expected bool
	}{
		{
			name: "no changes",
			plan: fcs.CloudAWSAccountModel{
				DSPM:                  &fcs.DSPMOptions{RoleName: types.StringValue("role1")},
				VulnerabilityScanning: &fcs.VulnerabilityScanningOptions{RoleName: types.StringValue("role1")},
				ResourceNamePrefix:    types.StringValue(""),
				ResourceNameSuffix:    types.StringValue(""),
			},
			state: fcs.CloudAWSAccountModel{
				DSPM:                  &fcs.DSPMOptions{RoleName: types.StringValue("role1")},
				VulnerabilityScanning: &fcs.VulnerabilityScanningOptions{RoleName: types.StringValue("role1")},
				ResourceNamePrefix:    types.StringValue(""),
				ResourceNameSuffix:    types.StringValue(""),
			},
			expected: false,
		},
		{
			name: "prefix changed invalidates agentless",
			plan: fcs.CloudAWSAccountModel{
				DSPM:                  &fcs.DSPMOptions{RoleName: types.StringValue("role1")},
				VulnerabilityScanning: &fcs.VulnerabilityScanningOptions{RoleName: types.StringValue("role1")},
				ResourceNamePrefix:    types.StringValue("new-"),
				ResourceNameSuffix:    types.StringValue(""),
			},
			state: fcs.CloudAWSAccountModel{
				DSPM:                  &fcs.DSPMOptions{RoleName: types.StringValue("role1")},
				VulnerabilityScanning: &fcs.VulnerabilityScanningOptions{RoleName: types.StringValue("role1")},
				ResourceNamePrefix:    types.StringValue(""),
				ResourceNameSuffix:    types.StringValue(""),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fcs.ShouldInvalidateAgentlessScanningRoleField(tt.plan, tt.state)
			assert.Equal(t, tt.expected, result)
		})
	}
}
