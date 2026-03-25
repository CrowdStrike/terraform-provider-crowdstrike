package mlexclusion

import (
	"context"
	"testing"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/strfmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildExcludedFrom(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		excludeDetections bool
		excludeUploads    bool
		expected          []string
	}{
		{
			name:              "detections_only",
			excludeDetections: true,
			excludeUploads:    false,
			expected:          []string{mlExcludedFromBlocking},
		},
		{
			name:              "uploads_only",
			excludeDetections: false,
			excludeUploads:    true,
			expected:          []string{mlExcludedFromExtraction},
		},
		{
			name:              "both_modes",
			excludeDetections: true,
			excludeUploads:    true,
			expected:          []string{mlExcludedFromBlocking, mlExcludedFromExtraction},
		},
		{
			name:              "neither_mode",
			excludeDetections: false,
			excludeUploads:    false,
			expected:          []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			actual := buildExcludedFrom(tt.excludeDetections, tt.excludeUploads)
			assert.ElementsMatch(t, tt.expected, actual)
		})
	}
}

func TestPayloadHasNotFoundError(t *testing.T) {
	t.Parallel()

	assert.True(t, payloadHasNotFoundError([]*models.MsaAPIError{
		{Code: utils.Addr(int32(404))},
	}))

	assert.False(t, payloadHasNotFoundError([]*models.MsaAPIError{
		{Code: utils.Addr(int32(400))},
	}))

	assert.False(t, payloadHasNotFoundError([]*models.MsaAPIError{
		nil,
		{Code: nil},
	}))
}

func TestMLExclusionWrap(t *testing.T) {
	t.Parallel()

	createdOn := strfmt.DateTime(time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC))
	lastModified := strfmt.DateTime(time.Date(2026, 2, 1, 11, 0, 0, 0, time.UTC))

	tests := []struct {
		name                  string
		exclusion             *models.ExclusionsExclusionV1
		expectedHostGroups    []string
		expectedAppliedGlobal bool
		expectedDetections    bool
		expectedUploads       bool
	}{
		{
			name: "global_exclusion",
			exclusion: &models.ExclusionsExclusionV1{
				ID:              utils.Addr("global-id"),
				Value:           utils.Addr("/tmp/global/*"),
				RegexpValue:     utils.Addr("regexp-global"),
				ValueHash:       utils.Addr("hash-global"),
				AppliedGlobally: utils.Addr(true),
				CreatedBy:       utils.Addr("creator@example.com"),
				ModifiedBy:      utils.Addr("modifier@example.com"),
				CreatedOn:       &createdOn,
				LastModified:    &lastModified,
				ExcludedFrom:    []string{mlExcludedFromBlocking, mlExcludedFromExtraction},
			},
			expectedHostGroups:    []string{mlExclusionGlobalHostGroupID},
			expectedAppliedGlobal: true,
			expectedDetections:    true,
			expectedUploads:       true,
		},
		{
			name: "targeted_exclusion",
			exclusion: &models.ExclusionsExclusionV1{
				ID:              utils.Addr("targeted-id"),
				Value:           utils.Addr("/tmp/targeted/*"),
				RegexpValue:     utils.Addr("regexp-targeted"),
				ValueHash:       utils.Addr("hash-targeted"),
				AppliedGlobally: utils.Addr(false),
				CreatedBy:       utils.Addr("creator@example.com"),
				ModifiedBy:      utils.Addr("modifier@example.com"),
				CreatedOn:       &createdOn,
				LastModified:    &lastModified,
				ExcludedFrom:    []string{mlExcludedFromBlocking},
				Groups: []*models.HostGroupsHostGroupV1{
					{ID: utils.Addr("host-group-1")},
				},
			},
			expectedHostGroups:    []string{"host-group-1"},
			expectedAppliedGlobal: false,
			expectedDetections:    true,
			expectedUploads:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var model mlExclusionResourceModel
			diags := model.wrap(context.Background(), tt.exclusion)
			require.False(t, diags.HasError())

			var hostGroups []string
			diags = model.HostGroups.ElementsAs(context.Background(), &hostGroups, false)
			require.False(t, diags.HasError())

			assert.ElementsMatch(t, tt.expectedHostGroups, hostGroups)
			assert.Equal(t, tt.expectedAppliedGlobal, model.AppliedGlobally.ValueBool())
			assert.Equal(t, tt.expectedDetections, model.ExcludeDetections.ValueBool())
			assert.Equal(t, tt.expectedUploads, model.ExcludeUploads.ValueBool())
			assert.Equal(t, *tt.exclusion.Value, model.Pattern.ValueString())
		})
	}
}
