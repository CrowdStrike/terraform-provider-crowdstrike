package fcs

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"

var cloudSecurityScopes = []scopes.Scope{
	{
		Name:  "Cloud security AWS registration",
		Read:  true,
		Write: true,
	},
}

var azureRegistrationScopes = []scopes.Scope{
	{
		Name:  "Cloud security Azure registration",
		Read:  true,
		Write: true,
	},
}

// azureRegistrationReadScopes are the scopes a read-only lookup needs.
var azureRegistrationReadScopes = []scopes.Scope{
	{
		Name:  "Cloud security Azure registration",
		Read:  true,
		Write: false,
	},
}
