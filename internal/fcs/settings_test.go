package fcs_test

import (
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/fcs"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

func TestNewSettingsConfig(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	tests := []struct {
		name                           string
		settings                       any
		wantRtvd                       []string
		wantLogIngestionMethod         types.String
		wantLogIngestionS3BucketName   types.String
		wantLogIngestionSnsTopicArn    types.String
		wantLogIngestionS3BucketPrefix types.String
		wantLogIngestionKmsKeyArn      types.String
	}{
		{
			name: "defined settings",
			settings: map[string]any{
				"rtvd.regions":                   "us-east-1,us-west-2",
				"log.ingestion.method":           "s3",
				"s3.log.ingestion.bucket.name":   "my-bucket",
				"s3.log.ingestion.sns.topic.arn": "arn:aws:sns:us-east-1:123456789012:my-topic",
				"s3.log.ingestion.bucket.prefix": "logs/",
				"s3.log.ingestion.kms.key.arn":   "arn:aws:kms:us-east-1:123456789012:key/12345678",
			},
			wantRtvd:                       []string{"us-east-1", "us-west-2"},
			wantLogIngestionMethod:         types.StringValue("s3"),
			wantLogIngestionS3BucketName:   types.StringValue("my-bucket"),
			wantLogIngestionSnsTopicArn:    types.StringValue("arn:aws:sns:us-east-1:123456789012:my-topic"),
			wantLogIngestionS3BucketPrefix: types.StringValue("logs/"),
			wantLogIngestionKmsKeyArn:      types.StringValue("arn:aws:kms:us-east-1:123456789012:key/12345678"),
		},
		{
			name: "empty strings",
			settings: map[string]any{
				"rtvd.regions":                   "",
				"log.ingestion.method":           "",
				"s3.log.ingestion.bucket.name":   "",
				"s3.log.ingestion.sns.topic.arn": "",
				"s3.log.ingestion.bucket.prefix": "",
				"s3.log.ingestion.kms.key.arn":   "",
			},

			wantRtvd:                       nil,
			wantLogIngestionMethod:         types.StringNull(),
			wantLogIngestionS3BucketName:   types.StringNull(),
			wantLogIngestionSnsTopicArn:    types.StringNull(),
			wantLogIngestionS3BucketPrefix: types.StringNull(),
			wantLogIngestionKmsKeyArn:      types.StringNull(),
		},
		{
			name:                           "nil settings",
			settings:                       nil,
			wantRtvd:                       nil,
			wantLogIngestionMethod:         types.StringNull(),
			wantLogIngestionS3BucketName:   types.StringNull(),
			wantLogIngestionSnsTopicArn:    types.StringNull(),
			wantLogIngestionS3BucketPrefix: types.StringNull(),
			wantLogIngestionKmsKeyArn:      types.StringNull(),
		},
		{
			name:                           "empty type",
			settings:                       map[string]any{},
			wantRtvd:                       nil,
			wantLogIngestionMethod:         types.StringNull(),
			wantLogIngestionS3BucketName:   types.StringNull(),
			wantLogIngestionSnsTopicArn:    types.StringNull(),
			wantLogIngestionS3BucketPrefix: types.StringNull(),
			wantLogIngestionKmsKeyArn:      types.StringNull(),
		},
		{
			name: "regions with trailing commas and empty values",
			settings: map[string]any{
				"rtvd.regions": "us-east-1,,us-west-2,",
			},
			wantRtvd:                       []string{"us-east-1", "us-west-2"},
			wantLogIngestionMethod:         types.StringNull(),
			wantLogIngestionS3BucketName:   types.StringNull(),
			wantLogIngestionSnsTopicArn:    types.StringNull(),
			wantLogIngestionS3BucketPrefix: types.StringNull(),
			wantLogIngestionKmsKeyArn:      types.StringNull(),
		},
		{
			name: "regions with only commas and whitespace",
			settings: map[string]any{
				"rtvd.regions": ",,,",
			},
			wantRtvd:                       nil,
			wantLogIngestionMethod:         types.StringNull(),
			wantLogIngestionS3BucketName:   types.StringNull(),
			wantLogIngestionSnsTopicArn:    types.StringNull(),
			wantLogIngestionS3BucketPrefix: types.StringNull(),
			wantLogIngestionKmsKeyArn:      types.StringNull(),
		},
		{
			name: "regions with mixed whitespace",
			settings: map[string]any{
				"rtvd.regions": "  us-east-1  ,  , us-west-2  ",
			},
			wantRtvd:                       []string{"us-east-1", "us-west-2"},
			wantLogIngestionMethod:         types.StringNull(),
			wantLogIngestionS3BucketName:   types.StringNull(),
			wantLogIngestionSnsTopicArn:    types.StringNull(),
			wantLogIngestionS3BucketPrefix: types.StringNull(),
			wantLogIngestionKmsKeyArn:      types.StringNull(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var diags diag.Diagnostics
			config := fcs.NewSettingsConfig(ctx, tt.settings, &diags)
			assert.False(t, diags.HasError(), "unexpected error: %v", diags.Errors())

			wantRtvd := acctest.StringListOrNull(tt.wantRtvd...)

			assert.True(t, config.RTVDRegions.Equal(wantRtvd), "RTVD regions mismatch: got %v, want %v", config.RTVDRegions, wantRtvd)

			assert.True(t, config.LogIngestionMethod.Equal(tt.wantLogIngestionMethod), "LogIngestionMethod mismatch: got %v, want %v", config.LogIngestionMethod, tt.wantLogIngestionMethod)
			assert.True(t, config.LogIngestionS3BucketName.Equal(tt.wantLogIngestionS3BucketName), "LogIngestionBucketName mismatch: got %v, want %v", config.LogIngestionS3BucketName, tt.wantLogIngestionS3BucketName)
			assert.True(t, config.LogIngestionSnsTopicArn.Equal(tt.wantLogIngestionSnsTopicArn), "LogIngestionSnsTopicArn mismatch: got %v, want %v", config.LogIngestionSnsTopicArn, tt.wantLogIngestionSnsTopicArn)
			assert.True(t, config.LogIngestionS3BucketPrefix.Equal(tt.wantLogIngestionS3BucketPrefix), "LogIngestionBucketPrefix mismatch: got %v, want %v", config.LogIngestionS3BucketPrefix, tt.wantLogIngestionS3BucketPrefix)
			assert.True(t, config.LogIngestionKmsKeyArn.Equal(tt.wantLogIngestionKmsKeyArn), "LogIngestionKmsKeyArn mismatch: got %v, want %v", config.LogIngestionKmsKeyArn, tt.wantLogIngestionKmsKeyArn)
		})
	}
}
