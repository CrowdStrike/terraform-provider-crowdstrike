package cloud_posture

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"

var cloudPostureRuleScopes = []scopes.Scope{
	{
		Name:  "Cloud Security Policies",
		Read:  true,
		Write: true,
	},
}
