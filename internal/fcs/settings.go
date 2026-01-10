package fcs

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type settingsConfig struct {
	RTVDRegions types.List

	LogIngestionMethod         types.String
	LogIngestionS3BucketName   types.String
	LogIngestionSnsTopicArn    types.String
	LogIngestionS3BucketPrefix types.String
	LogIngestionKmsKeyArn      types.String

	// DSPM and Vulnerability Scanning role settings
	DSPMRoleName                       types.String
	DSPMHostAccountID                  types.String
	VulnerabilityScanningRoleName      types.String
	VulnerabilityScanningHostAccountID types.String
}

func parseRegionString(ctx context.Context, regionStr string, diags *diag.Diagnostics) types.List {
	if regionStr == "" {
		return types.ListNull(types.StringType)
	}
	parts := strings.Split(regionStr, ",")
	regions := make([]string, 0, len(parts))
	for _, region := range parts {
		trimmed := strings.TrimSpace(region)
		if trimmed != "" {
			regions = append(regions, trimmed)
		}
	}
	if len(regions) == 0 {
		return types.ListNull(types.StringType)
	}
	list, d := types.ListValueFrom(ctx, types.StringType, regions)
	diags.Append(d...)
	return list
}

// newSettingsConfig decodes the settings map from a cloud account registration API response.
//
// Missing fields will default to their null types.
func newSettingsConfig(ctx context.Context, settings interface{}, diags *diag.Diagnostics) *settingsConfig {
	config := &settingsConfig{
		RTVDRegions: types.ListNull(types.StringType),
		// if other registration endpoints will default log ingestion method to eventbridge
		// then this logic can be updated to default to eventbridge here instead of the
		// resource logic checking if the output is null.
		LogIngestionMethod:         types.StringNull(),
		LogIngestionS3BucketName:   types.StringNull(),
		LogIngestionSnsTopicArn:    types.StringNull(),
		LogIngestionS3BucketPrefix: types.StringNull(),
		LogIngestionKmsKeyArn:      types.StringNull(),

		// Initialize DSPM and Vulnerability Scanning settings
		DSPMRoleName:                       types.StringNull(),
		DSPMHostAccountID:                  types.StringNull(),
		VulnerabilityScanningRoleName:      types.StringNull(),
		VulnerabilityScanningHostAccountID: types.StringNull(),
	}

	if settings == nil {
		return config
	}

	// Temporary struct for decoding raw values from settings map using mapstructure tags
	var raw struct {
		RTVDRegions                        string `mapstructure:"rtvd.regions"`
		LogIngestionMethod                 string `mapstructure:"log.ingestion.method"`
		LogIngestionS3BucketName           string `mapstructure:"s3.log.ingestion.bucket.name"`
		LogIngestionSnsTopicArn            string `mapstructure:"s3.log.ingestion.sns.topic.arn"`
		LogIngestionS3BucketPrefix         string `mapstructure:"s3.log.ingestion.bucket.prefix"`
		LogIngestionKmsKeyArn              string `mapstructure:"s3.log.ingestion.kms.key.arn"`
		DSPMRole                           string `mapstructure:"dspm.role"`
		DSPMHostAccountID                  string `mapstructure:"dspm.host.account"`
		VulnerabilityScanningRole          string `mapstructure:"vulnerability_scanning.role"`
		VulnerabilityScanningHostAccountID string `mapstructure:"vulnerability_scanning.host.account"`
	}

	if err := mapstructure.Decode(settings, &raw); err != nil {
		diags.AddError(
			"Failed to decode settings",
			fmt.Sprintf("Error decoding settings: %s", err),
		)
		return config
	}

	config.RTVDRegions = parseRegionString(ctx, raw.RTVDRegions, diags)

	config.LogIngestionMethod = flex.StringValueToFramework(raw.LogIngestionMethod)
	config.LogIngestionS3BucketName = flex.StringValueToFramework(raw.LogIngestionS3BucketName)
	config.LogIngestionSnsTopicArn = flex.StringValueToFramework(raw.LogIngestionSnsTopicArn)
	config.LogIngestionS3BucketPrefix = flex.StringValueToFramework(raw.LogIngestionS3BucketPrefix)
	config.LogIngestionKmsKeyArn = flex.StringValueToFramework(raw.LogIngestionKmsKeyArn)

	// Assign DSPM and Vulnerability Scanning settings
	config.DSPMRoleName = flex.StringValueToFramework(raw.DSPMRole)
	config.DSPMHostAccountID = flex.StringValueToFramework(raw.DSPMHostAccountID)
	config.VulnerabilityScanningRoleName = flex.StringValueToFramework(raw.VulnerabilityScanningRole)
	config.VulnerabilityScanningHostAccountID = flex.StringValueToFramework(raw.VulnerabilityScanningHostAccountID)

	return config
}
