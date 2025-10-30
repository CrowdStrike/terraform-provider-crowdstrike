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

// computeAgentlessScanningRoleName computes the agentless scanning role name using OR logic.
func computeAgentlessScanningRoleName(cspmAccount *models.DomainAWSAccountV2) (string, error) {
	// DSPM has precedence
	if cspmAccount.DspmEnabled {
		return getRoleNameFromArn(cspmAccount.DspmRoleArn), nil
	}

	// try fallback to vulnerability scanning role if DSPM is not enabled
	if cspmAccount.VulnerabilityScanningEnabled {
		settings, err := getAccountSettings(cspmAccount)
		if err != nil {
			return "", fmt.Errorf("failed to get vulnerability scanning role arn: %w", err)
		}
		return getRoleNameFromArn(settings.VulnerabilityScanningRole), nil
	}

	return "", nil
}
