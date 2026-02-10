package responsepolicy

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"

var apiScopesReadWrite = []scopes.Scope{
	{
		Name:  "Response Policies",
		Read:  true,
		Write: true,
	},
}
