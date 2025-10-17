package cloudcompliance

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"

var cloudComplianceFrameworkScopes = []scopes.Scope{
	{
		Name:  "Cloud Security Policies",
		Read:  true,
		Write: false,
	},
}

var cloudComplianceCustomFrameworkScopes = []scopes.Scope{
	{
		Name:  "Cloud Security Custom Policies",
		Read:  true,
		Write: true,
	},
}
