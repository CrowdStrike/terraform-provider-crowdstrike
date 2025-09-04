package user

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"

var userManagementScopes = []scopes.Scope{
	{
		Name:  "User Management",
		Read:  true,
		Write: true,
	},
}

var getCidScopes = []scopes.Scope{
	{
		Name:  "Sensor Download",
		Read:  true,
		Write: false,
	},
}

var getRolesScopes = []scopes.Scope{
	{
		Name:  "User Management",
		Read:  true,
		Write: false,
	},
}
