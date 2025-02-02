package fcs

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"

var cloudSecurityScopes = []scopes.Scope{
	{
		Name:  "Cloud security AWS registration",
		Read:  true,
		Write: true,
	},
	{
		Name:  "CSPM registration",
		Read:  true,
		Write: true,
	},
}
