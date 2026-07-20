package cloudsecurity

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"

var cloudSecurityRuleScopes = []scopes.Scope{
	{
		Name:  "Cloud Security Policies",
		Read:  true,
		Write: true,
	},
}

var cloudSecurityKacPolicyScopes = []scopes.Scope{
	{
		Name:  "Falcon Container Policies",
		Read:  true,
		Write: true,
	},
}

var cloudSecurityIacRuleScopes = []scopes.Scope{
	{
		Name:  "Cloud Security Policies",
		Read:  true,
		Write: true,
	},
	{
		Name:  "Infrastructure-as-Code",
		Read:  true,
		Write: true,
	},
}
