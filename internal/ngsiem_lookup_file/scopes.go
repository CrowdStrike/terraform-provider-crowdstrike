package lookupfile

import (
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
)

var apiScopesReadWrite = []scopes.Scope{
	{
		Name:  "NGSIEM",
		Read:  true,
		Write: true,
	},
}

var apiScopesRead = []scopes.Scope{
	{
		Name: "NGSIEM",
		Read: true,
	},
}
