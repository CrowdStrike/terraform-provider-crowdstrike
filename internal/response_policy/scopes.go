package responsepolicy

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"

var apiScopesReadWrite = []scopes.Scope{
	{
		Name:  "Response Policies",
		Read:  true,
		Write: true,
	},
}

var precedenceAPIScopes = []scopes.Scope{
	{
		Name:  "Response Policies",
		Read:  true,
		Write: true,
	},
	{
		Name: "Sensor Download",
		Read: true,
	},
}
