//go:build testgen

package cidgroup

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/testgen"

func init() {
	testgen.Register("crowdstrike_cid_group", testgen.Resource{
		Skip: map[string]string{
			"cids": "testgen: child CIDs come from TF_ACC_CID_GROUP_CHILD_CIDS; values from the environment are not supported yet",
		},
	})
}
