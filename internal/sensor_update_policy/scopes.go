package sensorupdatepolicy

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"

var apiScopesRead = []scopes.Scope{
	{
		Name:  "Sensor update policies",
		Read:  true,
		Write: false,
	},
}

var apiScopesReadWrite = []scopes.Scope{
	{
		Name:  "Sensor update policies",
		Read:  true,
		Write: true,
	},
}
