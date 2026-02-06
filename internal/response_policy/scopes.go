package responsepolicy

import (
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
)

var apiScopes = []scopes.Scope{
	{
		Name:  "Response policies",
		Read:  true,
		Write: true,
	},
}
