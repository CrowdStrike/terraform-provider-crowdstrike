package user

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"

var userManagementScopes = []scopes.Scope{
	{
		Name:  "User Management",
		Read:  true,
		Write: true,
	},
}
