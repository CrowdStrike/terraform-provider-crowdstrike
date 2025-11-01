package cloudsecurity

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"

var cloudSecurityRuleScopes = []scopes.Scope{
	{
		Name:  "Cloud Security Policies",
		Read:  true,
		Write: true,
	},
}
