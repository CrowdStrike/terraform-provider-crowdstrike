package ngsiemdataconnection

import (
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
)

// Name is the scope's exact label in the Falcon console's API-client scope picker (verified
// in-console) so users can find the row they must grant.
var apiScopesReadWrite = []scopes.Scope{
	{
		Name:  "NGSIEM Data Connections API",
		Read:  true,
		Write: true,
	},
}

var apiScopesRead = []scopes.Scope{
	{
		Name: "NGSIEM Data Connections API",
		Read: true,
	},
}
