package fim

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"

var apiScopesRead = []scopes.Scope{
	{
		Name:  "Falcon FileVantage",
		Read:  true,
		Write: false,
	},
}

var apiScopesReadWrite = []scopes.Scope{
	{
		Name:  "Falcon FileVantage",
		Read:  true,
		Write: true,
	},
}
