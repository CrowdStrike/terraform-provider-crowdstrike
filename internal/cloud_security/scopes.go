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
		Name:  "Falcon Container Image",
		Read:  true,
		Write: true,
	},
	{
		Name:  "Kubernetes Admission Control Policy",
		Read:  true,
		Write: true,
	},
}
