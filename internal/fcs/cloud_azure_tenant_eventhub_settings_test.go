package fcs_test

import (
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/fcs"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

// TestFlattenEventhubSettings covers the API shapes the acceptance tests cannot
// produce: a nil slice, a nil element, and settings whose fields are nil pointers.
func TestFlattenEventhubSettings(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		settings []*models.AzureEventHubSettings
		want     []*fcs.EventhubSettings
	}{
		"nil slice": {
			settings: nil,
			want:     []*fcs.EventhubSettings{},
		},
		"empty slice": {
			settings: []*models.AzureEventHubSettings{},
			want:     []*fcs.EventhubSettings{},
		},
		"one setting": {
			settings: []*models.AzureEventHubSettings{
				{
					EventHubID:    utils.Addr("/subscriptions/sub/eventhubs/one"),
					Purpose:       utils.Addr("activity_logs"),
					ConsumerGroup: utils.Addr("cg-one"),
				},
			},
			want: []*fcs.EventhubSettings{
				{
					Id:            types.StringValue("/subscriptions/sub/eventhubs/one"),
					Type:          types.StringValue("activity_logs"),
					ConsumerGroup: types.StringValue("cg-one"),
				},
			},
		},
		// The order the API returns is preserved.
		"two settings of different types": {
			settings: []*models.AzureEventHubSettings{
				{
					EventHubID:    utils.Addr("/subscriptions/sub/eventhubs/activity"),
					Purpose:       utils.Addr("activity_logs"),
					ConsumerGroup: utils.Addr("cg-activity"),
				},
				{
					EventHubID:    utils.Addr("/subscriptions/sub/eventhubs/entra"),
					Purpose:       utils.Addr("entra_logs"),
					ConsumerGroup: utils.Addr("cg-entra"),
				},
			},
			want: []*fcs.EventhubSettings{
				{
					Id:            types.StringValue("/subscriptions/sub/eventhubs/activity"),
					Type:          types.StringValue("activity_logs"),
					ConsumerGroup: types.StringValue("cg-activity"),
				},
				{
					Id:            types.StringValue("/subscriptions/sub/eventhubs/entra"),
					Type:          types.StringValue("entra_logs"),
					ConsumerGroup: types.StringValue("cg-entra"),
				},
			},
		},
		// The API models these as a slice of pointers, so a nil element is
		// representable.
		"nil element is skipped": {
			settings: []*models.AzureEventHubSettings{
				nil,
				{
					EventHubID:    utils.Addr("/subscriptions/sub/eventhubs/one"),
					Purpose:       utils.Addr("activity_logs"),
					ConsumerGroup: utils.Addr("cg-one"),
				},
			},
			want: []*fcs.EventhubSettings{
				{
					Id:            types.StringValue("/subscriptions/sub/eventhubs/one"),
					Type:          types.StringValue("activity_logs"),
					ConsumerGroup: types.StringValue("cg-one"),
				},
			},
		},
		"only nil elements": {
			settings: []*models.AzureEventHubSettings{nil, nil},
			want:     []*fcs.EventhubSettings{},
		},
		// Every field is an optional pointer, so a setting can arrive with none
		// of them populated.
		"nil fields become null": {
			settings: []*models.AzureEventHubSettings{{}},
			want: []*fcs.EventhubSettings{
				{
					Id:            types.StringNull(),
					Type:          types.StringNull(),
					ConsumerGroup: types.StringNull(),
				},
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := fcs.FlattenEventhubSettings(
				models.AzureTenantRegistration{EventHubSettings: tc.settings},
			)

			// A nil slice would become a null collection rather than an empty one.
			assert.NotNil(t, got, "expected a non-nil slice")
			assert.Equal(t, tc.want, got)
		})
	}
}
