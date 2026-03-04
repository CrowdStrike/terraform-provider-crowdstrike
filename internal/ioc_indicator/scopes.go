package iocindicator

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"

var apiScopes = []scopes.Scope{
	{
		Name:  "IOC Management",
		Read:  true,
		Write: true,
	},
}
