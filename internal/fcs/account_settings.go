package fcs

import (
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-viper/mapstructure/v2"
)

const AWSVulnerabilityScanningCustomRoleKey = "vulnerability_scanning.role"

// AccountSettings represents the settings structure returned by the CrowdStrike API.
type AccountSettings struct {
	VulnerabilityScanningRole string `mapstructure:"vulnerability_scanning.role"`
}

// getAccountSettings safely extracts settings from cspmAccount.
func getAccountSettings(cspmAccount *models.DomainAWSAccountV2) (*AccountSettings, error) {
	if cspmAccount.Settings == nil {
		return &AccountSettings{}, nil
	}

	var settings AccountSettings
	if err := mapstructure.Decode(cspmAccount.Settings, &settings); err != nil {
		return nil, fmt.Errorf("failed to parse account settings: %w", err)
	}

	return &settings, nil
}
