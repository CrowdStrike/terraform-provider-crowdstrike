package fcs

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ParseRegionsFromSettings is a test wrapper for parseRegionsFromSettings
// that provides a default oldState for testing the parsing logic.
func ParseRegionsFromSettings(ctx context.Context, settings interface{}, state *cloudAWSAccountModel) diag.Diagnostics {
	// Create a default oldState where all regions are set to known empty lists
	// This simulates the old behavior for testing purposes where regions would always be parsed from API settings
	oldState := &cloudAWSAccountModel{
		RealtimeVisibility: &realtimeVisibilityOptions{
			Regions: types.ListValueMust(types.StringType, []attr.Value{}), // Empty but known list
		},
		DSPM: &dspmOptions{
			Regions: types.ListValueMust(types.StringType, []attr.Value{}), // Empty but known list
		},
		VulnerabilityScanning: &vulnerabilityScanningOptions{
			Regions: types.ListValueMust(types.StringType, []attr.Value{}), // Empty but known list
		},
	}

	// Special case: if settings are nil or invalid, use null regions in oldState
	// so they remain null (simulating the old behavior)
	if settings == nil {
		oldState.RealtimeVisibility.Regions = types.ListNull(types.StringType)
		oldState.DSPM.Regions = types.ListNull(types.StringType)
		oldState.VulnerabilityScanning.Regions = types.ListNull(types.StringType)
	} else if _, ok := settings.(map[string]string); !ok {
		// Wrong type (e.g., map[string]interface{})
		oldState.RealtimeVisibility.Regions = types.ListNull(types.StringType)
		oldState.DSPM.Regions = types.ListNull(types.StringType)
		oldState.VulnerabilityScanning.Regions = types.ListNull(types.StringType)
	}

	return parseRegionsFromSettings(ctx, settings, state, oldState)
}

type (
	CloudAWSAccountModel         = cloudAWSAccountModel
	RealtimeVisibilityOptions    = realtimeVisibilityOptions
	DSPMOptions                  = dspmOptions
	VulnerabilityScanningOptions = vulnerabilityScanningOptions
)
