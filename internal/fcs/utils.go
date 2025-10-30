package fcs

import (
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/models"
)

func getRoleNameFromArn(arn string) string {
	arnParts := strings.Split(arn, "/")
	if len(arnParts) == 2 {
		return arnParts[1]
	}
	return ""
}

// resolveAgentlessScanningRoleName retrieves agentless scanning role name from CSPM account.
// DSPM role takes precedence over vulnerability scanning role.
func resolveAgentlessScanningRoleName(cspmAccount *models.DomainAWSAccountV2) (string, error) {
	if cspmAccount.DspmEnabled {
		return getRoleNameFromArn(cspmAccount.DspmRoleArn), nil
	}

	// Try fallback to vulnerability scanning role if DSPM is not enabled
	if cspmAccount.VulnerabilityScanningEnabled {
		settings, err := getAccountSettings(cspmAccount)
		if err != nil {
			return "", fmt.Errorf("failed to get vulnerability scanning role arn: %w", err)
		}
		return getRoleNameFromArn(settings.VulnerabilityScanningRole), nil
	}

	return "", nil
}
