package installtoken

import (
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
)

var apiScopesReadWrite = []scopes.Scope{
	{
		Name:  "Installation Tokens",
		Read:  true,
		Write: true,
	},
	{
		Name:  "Installation Tokens Settings",
		Read:  false,
		Write: true,
	},
}

// settingsAPIScopes covers the installation token settings: the settings are read
// through the Installation Tokens API and written through the Installation Tokens
// Settings API.
var settingsAPIScopes = []scopes.Scope{
	{
		Name: "Installation Tokens",
		Read: true,
	},
	{
		Name:  "Installation Tokens Settings",
		Write: true,
	},
}
