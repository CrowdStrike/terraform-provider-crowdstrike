package sensorupdatepolicy

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"

var dataSourceApiScopes = []scopes.Scope{
	{
		Name:  "sensor-update-policies",
		Read:  true,
		Write: false,
	},
}
