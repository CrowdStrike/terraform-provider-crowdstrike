package ioarulegroup

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"

var apiScopesRead = []scopes.Scope{
	{
		Name:  "Custom IOA Rules",
		Read:  true,
		Write: false,
	},
}

var apiScopesReadWrite = []scopes.Scope{
	{
		Name:  "Custom IOA Rules",
		Read:  true,
		Write: true,
	},
}
