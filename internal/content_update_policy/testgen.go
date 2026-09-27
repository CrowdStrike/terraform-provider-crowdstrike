//go:build testgen

package contentupdatepolicy

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/testgen"

const pinnedVersionSkip = "testgen: pinned content versions must exist in the tenant; values from the environment are not supported yet"

func init() {
	testgen.Register("crowdstrike_content_update_policy", testgen.Resource{
		Skip: map[string]string{
			"hostGroups": "testgen: references to other resources are not supported yet",

			"rapidResponsePinnedContentVersion":           pinnedVersionSkip,
			"sensorOperationsPinnedContentVersion":        pinnedVersionSkip,
			"systemCriticalPinnedContentVersion":          pinnedVersionSkip,
			"vulnerabilityManagementPinnedContentVersion": pinnedVersionSkip,
		},
		ImportIgnore: []string{"last_updated"},
	})

	testgen.Register("crowdstrike_default_content_update_policy", testgen.Resource{
		// There is one default policy per tenant, so its tests cannot run in parallel.
		Serial: true,
		// Delete only removes the default policy from state.
		NoDisappears: true,
		Skip: map[string]string{
			"rapidResponsePinnedContentVersion":           pinnedVersionSkip,
			"sensorOperationsPinnedContentVersion":        pinnedVersionSkip,
			"systemCriticalPinnedContentVersion":          pinnedVersionSkip,
			"vulnerabilityManagementPinnedContentVersion": pinnedVersionSkip,
		},
		ImportIgnore: []string{"last_updated"},
	})
}
