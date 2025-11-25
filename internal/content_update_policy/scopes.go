package contentupdatepolicy

import (
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
)

var apiScopesRead = []scopes.Scope{
	{
		Name:  "Content Update Policy",
		Read:  true,
		Write: false,
	},
}

var apiScopesReadWrite = []scopes.Scope{
	{
		Name:  "Content Update Policy",
		Read:  true,
		Write: true,
	},
}
