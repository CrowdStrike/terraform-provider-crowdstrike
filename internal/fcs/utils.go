package fcs

import (
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/models"
)

func getRoleNameFromArn(arn string) string {
	arnParts := strings.Split(arn, "/")
	if len(arnParts) == 2 {
		return arnParts[1]
	}
	// If it's not in ARN format and doesn't contain "arn:" prefix, assume it's already a role name
	if !strings.Contains(arn, "/") && !strings.HasPrefix(arn, "arn:") && arn != "" {
		return arn
	}
	return ""
}

// resolveAgentlessScanningRoleName retrieves agentless scanning role name from CSPM account.
// DSPM role takes precedence over vulnerability scanning role.
func resolveAgentlessScanningRoleName(cspmAccount *models.DomainAWSAccountV2) string {
	agentlessScanningRoleName := getRoleNameFromArn(cspmAccount.DspmRoleArn)
	if cspmAccount.DspmEnabled {
		return agentlessScanningRoleName
	}

	// Try fallback to vulnerability scanning role if DSPM is not enabled
	if cspmAccount.VulnerabilityScanningEnabled {
		agentlessScanningRoleName = getRoleNameFromArn(cspmAccount.VulnerabilityScanningRoleArn)
	}

	return agentlessScanningRoleName
}
