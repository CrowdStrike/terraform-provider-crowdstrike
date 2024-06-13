package fim

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"

var apiScopes = []scopes.Scope{
	{
		Name:  "Falcon FileVantage",
		Read:  true,
		Write: true,
	},
}
