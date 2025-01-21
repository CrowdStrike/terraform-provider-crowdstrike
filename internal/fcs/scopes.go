package fcs

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"

var cspmScopes = []scopes.Scope{
	{
		Name:  "CSPM registration",
		Read:  true,
		Write: true,
	},
}

var fcsScopes = []scopes.Scope{
	{
		Name:  "Cloud security AWS registration",
		Read:  true,
		Write: true,
	},
}
