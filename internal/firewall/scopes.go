package firewall

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"

var apiScopesReadWrite = []scopes.Scope{
	{
		Name:  "Firewall management",
		Read:  true,
		Write: true,
	},
}

var apiScopesRead = []scopes.Scope{
	{
		Name:  "Firewall management",
		Read:  true,
		Write: false,
	},
}
