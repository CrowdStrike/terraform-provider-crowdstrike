//go:build testgen

package hostgroups

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/testgen"

func init() {
	testgen.Register("crowdstrike_host_group", testgen.Resource{
		// Each type requires a different membership attribute; dynamic with
		// an assignment rule is the smallest valid host group.
		Base: map[string]any{
			"type":            "dynamic",
			"assignment_rule": "hostname:'tf-acc-test-a'",
		},
		Attributes: map[string]testgen.Attribute{
			"assignment_rule": {Values: []any{"hostname:'tf-acc-test-a'", "hostname:'tf-acc-test-b'"}},
			"hostnames": {
				Values:   []any{"TF-ACC-HOST-1", "TF-ACC-HOST-2", "TF-ACC-HOST-3"},
				Requires: map[string]any{"type": "static", "assignment_rule": nil},
			},
		},
		ImportIgnore: []string{"last_updated"},
		Skip: map[string]string{
			"hostIds": "testgen: host IDs must reference real hosts in the tenant",
			"type":    "testgen: each type requires a different membership attribute; covered by the assignmentRule and hostnames tests",
		},
	})
}
