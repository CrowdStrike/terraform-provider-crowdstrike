package usergroup

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"

var apiScopes = []scopes.Scope{
	{
		Name:  "Flight Control",
		Read:  true,
		Write: true,
	},
}
