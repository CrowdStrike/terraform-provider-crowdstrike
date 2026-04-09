package devicecontrolpolicy

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"

var apiScopesReadWrite = []scopes.Scope{
	{
		Name:  "Device control policies",
		Read:  true,
		Write: true,
	},
}
