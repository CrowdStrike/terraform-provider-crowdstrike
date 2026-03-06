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
