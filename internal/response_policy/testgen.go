//go:build testgen

package responsepolicy

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/testgen"

func init() {
	testgen.Register("crowdstrike_response_policy", testgen.Resource{
		Skip: map[string]string{
			"hostGroups": "testgen: references to other resources are not supported yet",
		},
		ImportIgnore: []string{"last_updated"},
	})
}
