package falconcontainerimage

import (
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
)

var apiScopesReadWrite = []scopes.Scope{
	{
		Name:  "Falcon Container Image",
		Read:  true,
		Write: true,
	},
}
